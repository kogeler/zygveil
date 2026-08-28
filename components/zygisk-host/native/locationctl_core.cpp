// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "locationctl_core.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <map>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace zygveil::location {
namespace {

constexpr std::array<std::string_view, 5> kLiveInputKeys = {
    "schema_version",
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
};

constexpr std::array<std::string_view, 12> kRuntimeStatusKeys = {
    "schema_version",   "state",             "reason",
    "raw_gnss_mode",    "hook_count",        "system_server_pid",
    "system_server_start_ticks", "config_generation", "boot_id", "control_fd",
    "control_owner_pid", "control_owner_start_ticks",
};

bool SetError(std::string* error, std::string message) {
  if (error != nullptr) {
    *error = std::move(message);
  }
  return false;
}

std::string Trim(std::string_view input) {
  const auto first = input.find_first_not_of(" \t\r");
  if (first == std::string_view::npos) {
    return {};
  }
  const auto last = input.find_last_not_of(" \t\r");
  return std::string(input.substr(first, last - first + 1));
}

bool ParseDecimal(std::string_view text, int maximum_fraction_digits, double* output) {
  if (text.empty() || text.size() > 32 || text.front() == '+' || text.front() == '.') {
    return false;
  }
  std::size_t index = text.front() == '-' ? 1 : 0;
  if (index == text.size() || text[index] < '0' || text[index] > '9') {
    return false;
  }
  bool decimal = false;
  int fraction_digits = 0;
  for (; index < text.size(); ++index) {
    const char value = text[index];
    if (value == '.') {
      if (decimal || index + 1 == text.size()) {
        return false;
      }
      decimal = true;
      continue;
    }
    if (value < '0' || value > '9') {
      return false;
    }
    if (decimal && ++fraction_digits > maximum_fraction_digits) {
      return false;
    }
  }
  std::string owned(text);
  char* end = nullptr;
  errno = 0;
  const double value = std::strtod(owned.c_str(), &end);
  if (errno != 0 || end == owned.c_str() || *end != '\0' || !std::isfinite(value)) {
    return false;
  }
  *output = value;
  return true;
}

bool ParseUnsigned(std::string_view text, std::uint64_t maximum, std::uint64_t* output) {
  if (text.empty() || text.front() == '+' || text.front() == '-') {
    return false;
  }
  std::uint64_t value = 0;
  const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
  if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value > maximum) {
    return false;
  }
  *output = value;
  return true;
}

bool ValidBootId(std::string_view value) {
  if (value.size() != 36) {
    return false;
  }
  for (std::size_t index = 0; index < value.size(); ++index) {
    if (index == 8 || index == 13 || index == 18 || index == 23) {
      if (value[index] != '-') {
        return false;
      }
    } else if (!((value[index] >= '0' && value[index] <= '9') ||
                 (value[index] >= 'a' && value[index] <= 'f'))) {
      return false;
    }
  }
  return true;
}

bool RuntimeReasonIsCoordinateFree(std::string_view value) {
  constexpr std::array forbidden = {
      std::string_view{"center_latitude_deg"},
      std::string_view{"center_longitude_deg"},
      std::string_view{"altitude_ellipsoid_m"},
      std::string_view{"altitude_msl_m"},
      std::string_view{"$"},
  };
  return std::none_of(forbidden.begin(), forbidden.end(),
                      [&](std::string_view token) { return value.find(token) != value.npos; });
}

std::string_view SafeHelperReason(std::string_view reason) {
  const bool token = !reason.empty() && reason.size() <= 64 &&
      std::all_of(reason.begin(), reason.end(), [](unsigned char value) {
        return (value >= 'a' && value <= 'z') || value == '_';
      });
  return token && RuntimeReasonIsCoordinateFree(reason) ? reason
                                                        : std::string_view{"internal_error"};
}

std::string Decimal(double value) {
  std::array<char, 64> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value,
                                    std::chars_format::general,
                                    std::numeric_limits<double>::max_digits10);
  return result.ec == std::errc{} ? std::string(buffer.data(), result.ptr) : "invalid";
}

std::string UiDecimal(double value, int maximum_fraction_digits) {
  std::array<char, 64> buffer{};
  const auto result = std::to_chars(buffer.data(), buffer.data() + buffer.size(), value,
                                    std::chars_format::fixed, maximum_fraction_digits);
  if (result.ec != std::errc{}) {
    return "invalid";
  }
  std::string rendered(buffer.data(), result.ptr);
  while (rendered.ends_with('0')) {
    rendered.pop_back();
  }
  if (rendered.ends_with('.')) {
    rendered.pop_back();
  }
  return rendered == "-0" ? "0" : rendered;
}

bool WriteFully(int descriptor, std::string_view text) {
  const char* data = text.data();
  std::size_t remaining = text.size();
  while (remaining > 0) {
    const ssize_t written = write(descriptor, data, remaining);
    if (written < 0 && errno == EINTR) {
      continue;
    }
    if (written <= 0) {
      return false;
    }
    data += written;
    remaining -= static_cast<std::size_t>(written);
  }
  return true;
}

std::optional<std::string> ReadTextFile(int descriptor, std::size_t maximum,
                                        std::string_view kind, std::string* error) {
  std::string result;
  std::array<char, 1024> buffer{};
  while (true) {
    const ssize_t count = read(descriptor, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      SetError(error, std::string(kind) + "_read_failed");
      return std::nullopt;
    }
    if (count == 0) {
      break;
    }
    if (result.size() + static_cast<std::size_t>(count) > maximum) {
      SetError(error, std::string(kind) + "_oversized");
      return std::nullopt;
    }
    result.append(buffer.data(), static_cast<std::size_t>(count));
  }
  return result;
}

}  // namespace

bool ValidRuntimeStatusReason(std::string_view reason) {
  return !reason.empty() && reason.size() <= 256 && reason.find('=') == reason.npos &&
      std::all_of(reason.begin(), reason.end(), [](unsigned char value) {
        return value >= 0x20 && value <= 0x7e;
      }) &&
      RuntimeReasonIsCoordinateFree(reason);
}

std::optional<std::uint64_t> ParseProcessStartTicks(std::string_view stat) {
  const std::size_t command_end = stat.rfind(')');
  if (command_end == stat.npos || command_end + 2 >= stat.size() ||
      stat[command_end + 1] != ' ') {
    return std::nullopt;
  }
  std::size_t offset = command_end + 2;
  for (int field = 3; field <= 22; ++field) {
    while (offset < stat.size() && stat[offset] == ' ') {
      ++offset;
    }
    const std::size_t end = stat.find_first_of(" \n\r", offset);
    const std::size_t token_end = end == stat.npos ? stat.size() : end;
    if (token_end == offset) {
      return std::nullopt;
    }
    if (field == 22) {
      std::uint64_t ticks = 0;
      return ParseUnsigned(stat.substr(offset, token_end - offset), UINT64_MAX, &ticks) && ticks > 0
          ? std::optional<std::uint64_t>{ticks}
          : std::nullopt;
    }
    offset = token_end;
  }
  return std::nullopt;
}

std::optional<LiveInput> ParseLiveInput(std::string_view text, std::string* error) {
  if (text.empty() || text.size() > kMaximumLiveInputBytes || text.find('\0') != std::string_view::npos) {
    SetError(error, "invalid_input_size");
    return std::nullopt;
  }
  std::map<std::string, std::string> values;
  std::size_t offset = 0;
  while (offset <= text.size()) {
    const std::size_t end = text.find('\n', offset);
    const std::size_t length = end == std::string_view::npos ? text.size() - offset : end - offset;
    const std::string line = Trim(text.substr(offset, length));
    if (!line.empty()) {
      const std::size_t separator = line.find('=');
      if (separator == std::string::npos) {
        SetError(error, "invalid_input_shape");
        return std::nullopt;
      }
      const std::string key = Trim(std::string_view(line).substr(0, separator));
      const std::string value = Trim(std::string_view(line).substr(separator + 1));
      if (key.empty() || value.empty() ||
          std::find(kLiveInputKeys.begin(), kLiveInputKeys.end(), key) == kLiveInputKeys.end() ||
          !values.emplace(key, value).second) {
        SetError(error, "invalid_input_keys");
        return std::nullopt;
      }
    }
    if (end == std::string_view::npos) {
      break;
    }
    offset = end + 1;
  }
  if (values.size() != kLiveInputKeys.size() || values["schema_version"] != "1") {
    SetError(error, "invalid_input_schema");
    return std::nullopt;
  }
  LiveInput input;
  if (!ParseDecimal(values["center_latitude_deg"], 8, &input.center_latitude_deg) ||
      !ParseDecimal(values["center_longitude_deg"], 8, &input.center_longitude_deg) ||
      !ParseDecimal(values["altitude_ellipsoid_m"], 3, &input.altitude_ellipsoid_m) ||
      !ParseDecimal(values["altitude_msl_m"], 3, &input.altitude_msl_m)) {
    SetError(error, "invalid_decimal_input");
    return std::nullopt;
  }
  if (input.center_latitude_deg < -90.0 || input.center_latitude_deg > 90.0 ||
      input.center_longitude_deg < -180.0 || input.center_longitude_deg > 180.0 ||
      input.altitude_ellipsoid_m < -12000.0 || input.altitude_ellipsoid_m > 100000.0 ||
      input.altitude_msl_m < -12000.0 || input.altitude_msl_m > 100000.0) {
    SetError(error, "input_out_of_range");
    return std::nullopt;
  }
  return input;
}

std::optional<RuntimeControlStatus> ParseRuntimeControlStatus(std::string_view text,
                                                              std::string* error) {
  if (text.empty() || text.size() > kMaximumRuntimeStatusBytes ||
      text.find('\0') != std::string_view::npos) {
    SetError(error, "runtime_status_size_invalid");
    return std::nullopt;
  }
  std::map<std::string, std::string> values;
  std::size_t offset = 0;
  while (offset <= text.size()) {
    const std::size_t end = text.find('\n', offset);
    const std::size_t length =
        end == std::string_view::npos ? text.size() - offset : end - offset;
    const std::string line = Trim(text.substr(offset, length));
    if (!line.empty()) {
      const std::size_t separator = line.find('=');
      if (separator == std::string::npos) {
        SetError(error, "runtime_status_shape_invalid");
        return std::nullopt;
      }
      const std::string key = Trim(std::string_view(line).substr(0, separator));
      const std::string value = Trim(std::string_view(line).substr(separator + 1));
      if (key.empty() || value.empty() ||
          std::find(kRuntimeStatusKeys.begin(), kRuntimeStatusKeys.end(), key) ==
              kRuntimeStatusKeys.end() ||
          !values.emplace(key, value).second) {
        SetError(error, "runtime_status_keys_invalid");
        return std::nullopt;
      }
    }
    if (end == std::string_view::npos) {
      break;
    }
    offset = end + 1;
  }
  if (values.size() != kRuntimeStatusKeys.size() || values["schema_version"] != "4") {
    SetError(error, "runtime_status_schema_invalid");
    return std::nullopt;
  }
  RuntimeControlStatus status;
  status.state = values["state"];
  status.reason = values["reason"];
  status.raw_gnss_mode = values["raw_gnss_mode"];
  status.boot_id = values["boot_id"];
  std::uint64_t hook_count = 0;
  std::uint64_t system_server_pid = 0;
  std::uint64_t system_server_start_ticks = 0;
  std::uint64_t control_fd = 0;
  std::uint64_t control_owner_pid = 0;
  std::uint64_t control_owner_start_ticks = 0;
  if ((status.state != "ready" && status.state != "arming" && status.state != "inactive") ||
      (status.raw_gnss_mode != "blocked" && status.raw_gnss_mode != "passthrough" &&
       status.raw_gnss_mode != "unknown") ||
      !ValidRuntimeStatusReason(status.reason) || !ValidBootId(status.boot_id) ||
      !ParseUnsigned(values["hook_count"], UINT32_MAX, &hook_count) ||
      !ParseUnsigned(values["system_server_pid"], UINT32_MAX, &system_server_pid) ||
      !ParseUnsigned(values["system_server_start_ticks"], UINT64_MAX,
                     &system_server_start_ticks) ||
      !ParseUnsigned(values["config_generation"], kMaximumConfigGeneration,
                     &status.config_generation) ||
      !ParseUnsigned(values["control_fd"], INT_MAX, &control_fd) ||
      !ParseUnsigned(values["control_owner_pid"], UINT32_MAX, &control_owner_pid) ||
      !ParseUnsigned(values["control_owner_start_ticks"], UINT64_MAX,
                     &control_owner_start_ticks)) {
    SetError(error, "runtime_status_value_invalid");
    return std::nullopt;
  }
  status.hook_count = static_cast<std::uint32_t>(hook_count);
  status.system_server_pid = static_cast<std::uint32_t>(system_server_pid);
  status.system_server_start_ticks = system_server_start_ticks;
  status.control_fd = static_cast<int>(control_fd);
  status.control_owner_pid = static_cast<std::uint32_t>(control_owner_pid);
  status.control_owner_start_ticks = control_owner_start_ticks;
  const bool ready = status.state == "ready";
  if ((ready && (status.system_server_pid == 0 || status.config_generation == 0 ||
                  status.system_server_start_ticks == 0 ||
                  status.hook_count != 5 || status.control_fd < 3 ||
                  status.control_owner_pid == 0 ||
                  status.control_owner_start_ticks == 0 ||
                  status.raw_gnss_mode == "unknown")) ||
      ((status.system_server_pid == 0) != (status.system_server_start_ticks == 0)) ||
      ((status.control_owner_pid == 0) != (status.control_owner_start_ticks == 0)) ||
      (!ready && (status.hook_count != 0 || status.control_fd != 0 ||
                   status.control_owner_pid != 0 ||
                   status.control_owner_start_ticks != 0))) {
    SetError(error, "runtime_status_state_invalid");
    return std::nullopt;
  }
  return status;
}

std::optional<Config> BuildLiveCandidate(const Config& persisted,
                                         std::uint64_t published_generation,
                                         const LiveInput& input, std::string* error) {
  const std::uint64_t base = std::max(persisted.config_generation, published_generation);
  if (base >= kMaximumControlGeneration) {
    SetError(error, "generation_wrap");
    return std::nullopt;
  }
  Config candidate = persisted;
  candidate.enabled = true;
  candidate.center_latitude_deg = input.center_latitude_deg;
  candidate.center_longitude_deg = input.center_longitude_deg;
  candidate.altitude_ellipsoid_m = input.altitude_ellipsoid_m;
  candidate.altitude_msl_m = input.altitude_msl_m;
  candidate.config_generation = base + 1;
  if (!ValidateLiveTransition(persisted, candidate, base, error)) {
    return std::nullopt;
  }
  return candidate;
}

std::string RenderConfig(const Config& config) {
  return "schema_version=" + std::to_string(config.schema_version) +
         "\nenabled=" + (config.enabled ? std::string("true") : std::string("false")) +
         "\nraw_gnss_mode=" + std::string(RawGnssModeName(config.raw_gnss_mode)) +
         "\ncenter_latitude_deg=" + Decimal(config.center_latitude_deg) +
         "\ncenter_longitude_deg=" + Decimal(config.center_longitude_deg) +
         "\naltitude_ellipsoid_m=" + Decimal(config.altitude_ellipsoid_m) +
         "\naltitude_msl_m=" + Decimal(config.altitude_msl_m) +
         "\nhorizontal_jitter_sigma_m=" + Decimal(config.horizontal_jitter_sigma_m) +
         "\nhorizontal_jitter_radius_m=" + Decimal(config.horizontal_jitter_radius_m) +
         "\nhorizontal_correlation_time_s=" + Decimal(config.horizontal_correlation_time_s) +
         "\nvertical_jitter_sigma_m=" + Decimal(config.vertical_jitter_sigma_m) +
         "\naccuracy_correlation_time_s=" + Decimal(config.accuracy_correlation_time_s) +
         "\nspeed_deadband_mps=" + Decimal(config.speed_deadband_mps) +
         "\nspeed_max_mps=" + Decimal(config.speed_max_mps) +
         "\nbearing_min_speed_mps=" + Decimal(config.bearing_min_speed_mps) +
         "\nrandom_seed=" + std::to_string(config.random_seed) +
         "\nconfig_generation=" + std::to_string(config.config_generation) + "\n";
}

std::string RenderHelperStatus(const HelperStatus& status, bool include_coordinates) {
  const std::string_view safe_reason = SafeHelperReason(status.reason);
  std::string result =
      "schema_version=1\nmodule_state=" + status.module_state +
      "\nruntime_state=" + status.runtime_state + "\ncontrol_state=" + status.control_state +
      "\nreason=" + std::string(safe_reason) +
      "\nraw_gnss_mode=" + std::string(RawGnssModeName(status.raw_gnss_mode)) +
      "\nboot_config_generation=" + std::to_string(status.boot_config_generation) +
      "\npersisted_generation=" + std::to_string(status.persisted_generation) +
      "\npublished_generation=" + std::to_string(status.published_generation) +
      "\napplied_generation=" + std::to_string(status.applied_generation) +
      "\nsystem_server_pid=" + std::to_string(status.system_server_pid) +
      "\nsystem_server_start_ticks=" +
      std::to_string(status.system_server_start_ticks) +
      "\nboot_id=" + status.boot_id + "\n";
  if (include_coordinates && status.config.has_value()) {
    result += "center_latitude_deg=" + UiDecimal(status.config->center_latitude_deg, 8) +
              "\ncenter_longitude_deg=" + UiDecimal(status.config->center_longitude_deg, 8) +
              "\naltitude_ellipsoid_m=" + UiDecimal(status.config->altitude_ellipsoid_m, 3) +
              "\naltitude_msl_m=" + UiDecimal(status.config->altitude_msl_m, 3) + "\n";
  }
  return result;
}

HelperStatus DeriveHelperStatus(const Config& config, const ControlPage* page,
                                std::string_view fallback_reason) {
  HelperStatus status;
  status.persisted_generation = config.config_generation;
  status.raw_gnss_mode = config.raw_gnss_mode;
  status.config = config;
  status.reason = std::string(fallback_reason);
  if (page == nullptr) {
    return status;
  }
  status.boot_config_generation = page->header.boot_config_generation;
  status.published_generation = LoadPublishedGeneration(*page);
  status.system_server_pid = page->header.server_pid;
  status.boot_id = std::string(page->header.boot_id.data());
  // An applied ack release-publishes after applied_generation, so read it first.
  const ControlAck acknowledgement = ReadControlAck(*page);
  status.applied_generation = LoadAppliedGeneration(*page);
  const ControlRuntimeState runtime = LoadControlRuntimeState(*page);
  status.runtime_state = std::string(ControlRuntimeStateName(runtime));
  status.module_state = runtime == ControlRuntimeState::kActive
      ? "active"
      : runtime == ControlRuntimeState::kWaiting ? "waiting" : "inactive";
  if (runtime == ControlRuntimeState::kWaiting && !config.enabled &&
      status.persisted_generation == status.boot_config_generation &&
      status.published_generation == status.persisted_generation &&
      status.applied_generation == status.persisted_generation) {
    status.control_state = "awaiting_first_coordinates";
    status.reason = "none";
    status.config.reset();
    return status;
  }
  if (runtime != ControlRuntimeState::kActive && runtime != ControlRuntimeState::kWaiting) {
    status.control_state = "unavailable";
    status.reason = "runtime_inactive";
    return status;
  }
  if (acknowledgement.generation == status.persisted_generation &&
      acknowledgement.state == ControlAckState::kRejected &&
      acknowledgement.reason == ControlReason::kPersistenceFailed &&
      status.persisted_generation > status.published_generation &&
      status.published_generation == status.applied_generation) {
    status.control_state = "recovery_required";
    status.reason = "persistence_uncertain";
    return status;
  }
  if (status.persisted_generation > status.published_generation) {
    status.control_state = "saved_pending_reboot";
    status.reason = "publish_unavailable";
  } else if (status.published_generation == status.applied_generation) {
    status.control_state = "applied";
    status.reason = "none";
  } else if (acknowledgement.generation == status.published_generation) {
    if (acknowledgement.state == ControlAckState::kRejected &&
        acknowledgement.reason == ControlReason::kPersistenceFailed &&
        status.persisted_generation == status.applied_generation) {
      status.control_state = "recovery_required";
      status.reason = "rollback_persistence_uncertain";
      return status;
    }
    if (acknowledgement.state == ControlAckState::kRejected &&
        status.persisted_generation == status.published_generation) {
      status.control_state = "recovery_required";
      status.reason = "persisted_runtime_rejection";
    } else {
      status.control_state = std::string(ControlAckStateName(acknowledgement.state));
      status.reason = std::string(ControlReasonName(acknowledgement.reason));
    }
  } else {
    status.control_state = "saved_pending_upstream";
    status.reason = "none";
  }
  return status;
}

std::optional<Config> ReadConfigAt(int directory, uid_t expected_uid, gid_t expected_gid,
                                   std::string* error) {
  const int descriptor = openat(directory, "config.properties", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    SetError(error, "config_open_failed");
    return std::nullopt;
  }
  struct stat status {};
  const bool valid = fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode) &&
                     status.st_uid == expected_uid && status.st_gid == expected_gid &&
                     status.st_nlink == 1 && (status.st_mode & 07777) == 0600 &&
                     status.st_size > 0 &&
                     static_cast<std::size_t>(status.st_size) <= kMaximumConfigBytes;
  if (!valid) {
    close(descriptor);
    SetError(error, "config_identity_invalid");
    return std::nullopt;
  }
  const auto text = ReadTextFile(descriptor, kMaximumConfigBytes, "config", error);
  close(descriptor);
  if (!text.has_value()) {
    return std::nullopt;
  }
  std::string parse_error;
  const auto config = ParseConfig(*text, &parse_error);
  if (!config.has_value()) {
    SetError(error, "config_invalid");
  }
  return config;
}

std::optional<RuntimeControlStatus> ReadRuntimeControlStatusAt(
    int directory, uid_t expected_uid, gid_t expected_gid, std::string* error) {
  const int descriptor = openat(directory, "runtime-status.properties",
                                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    SetError(error, "runtime_status_open_failed");
    return std::nullopt;
  }
  struct stat status {};
  const bool valid = fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode) &&
      status.st_uid == expected_uid && status.st_gid == expected_gid && status.st_nlink == 1 &&
      (status.st_mode & 07777) == 0644 && status.st_size > 0 &&
      static_cast<std::size_t>(status.st_size) <= kMaximumRuntimeStatusBytes;
  if (!valid) {
    close(descriptor);
    SetError(error, "runtime_status_identity_invalid");
    return std::nullopt;
  }
  const auto text =
      ReadTextFile(descriptor, kMaximumRuntimeStatusBytes, "runtime_status", error);
  close(descriptor);
  return text.has_value() ? ParseRuntimeControlStatus(*text, error) : std::nullopt;
}

ConfigPersistenceResult PersistConfigAt(int directory, const Config& config, uid_t owner,
                                        gid_t group, std::string* error) {
  std::string validation_error;
  if (!ValidateConfig(config, &validation_error)) {
    SetError(error, "config_invalid");
    return ConfigPersistenceResult::kNotCommitted;
  }
  const auto existing = ReadConfigAt(directory, owner, group, error);
  if (!existing.has_value()) {
    return ConfigPersistenceResult::kNotCommitted;
  }
  constexpr char temporary[] = ".config.properties.tmp";
  const int stale = openat(directory, temporary, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (stale >= 0) {
    struct stat stale_status {};
    const bool removable = fstat(stale, &stale_status) == 0 && S_ISREG(stale_status.st_mode) &&
                           stale_status.st_uid == owner && stale_status.st_gid == group &&
                           stale_status.st_nlink == 1 && (stale_status.st_mode & 07777) == 0600;
    close(stale);
    if (!removable || unlinkat(directory, temporary, 0) != 0) {
      SetError(error, "config_temporary_identity_invalid");
      return ConfigPersistenceResult::kNotCommitted;
    }
  } else if (errno != ENOENT) {
    SetError(error, "config_temporary_identity_invalid");
    return ConfigPersistenceResult::kNotCommitted;
  }
  const int output = openat(directory, temporary,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (output < 0) {
    SetError(error, "config_temporary_open_failed");
    return ConfigPersistenceResult::kNotCommitted;
  }
  const std::string body = RenderConfig(config);
  const bool written = fchown(output, owner, group) == 0 && fchmod(output, 0600) == 0 &&
                       WriteFully(output, body) && fsync(output) == 0;
  close(output);
  if (!written) {
    unlinkat(directory, temporary, 0);
    SetError(error, "config_temporary_write_failed");
    return ConfigPersistenceResult::kNotCommitted;
  }
  if (renameat(directory, temporary, directory, "config.properties") != 0) {
    unlinkat(directory, temporary, 0);
    SetError(error, "config_rename_failed");
    return ConfigPersistenceResult::kNotCommitted;
  }
  if (fsync(directory) != 0) {
    SetError(error, "config_directory_sync_failed");
    return ConfigPersistenceResult::kCommitted;
  }
  return ConfigPersistenceResult::kDurable;
}

bool WriteRuntimeControlStatusAt(int directory, std::string_view body,
                                 std::uint32_t expected_server_pid, uid_t owner, gid_t group,
                                 std::string* error) {
  const auto parsed = ParseRuntimeControlStatus(body, error);
  if (!parsed.has_value() || parsed->system_server_pid != expected_server_pid) {
    if (parsed.has_value()) {
      SetError(error, "runtime_status_process_mismatch");
    }
    return false;
  }
  constexpr char temporary[] = ".runtime-status.tmp";
  const int stale = openat(directory, temporary, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (stale >= 0) {
    struct stat stale_status {};
    const bool removable = fstat(stale, &stale_status) == 0 && S_ISREG(stale_status.st_mode) &&
                           stale_status.st_uid == owner && stale_status.st_gid == group &&
                           stale_status.st_nlink == 1 &&
                           (stale_status.st_mode & 07777) == 0644;
    close(stale);
    if (!removable || unlinkat(directory, temporary, 0) != 0) {
      return SetError(error, "runtime_status_temporary_identity_invalid");
    }
  } else if (errno != ENOENT) {
    return SetError(error, "runtime_status_temporary_identity_invalid");
  }
  const int output = openat(directory, temporary,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
  if (output < 0) {
    return SetError(error, "runtime_status_temporary_open_failed");
  }
  const bool written = fchown(output, owner, group) == 0 && fchmod(output, 0644) == 0 &&
                       WriteFully(output, body) && fsync(output) == 0;
  close(output);
  if (!written) {
    unlinkat(directory, temporary, 0);
    return SetError(error, "runtime_status_temporary_write_failed");
  }
  if (renameat(directory, temporary, directory, "runtime-status.properties") != 0) {
    unlinkat(directory, temporary, 0);
    return SetError(error, "runtime_status_rename_failed");
  }
  if (fsync(directory) != 0) {
    return SetError(error, "runtime_status_directory_sync_failed");
  }
  return true;
}

}  // namespace zygveil::location
