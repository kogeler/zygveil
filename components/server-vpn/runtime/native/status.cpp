// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "status.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <map>
#include <utility>

#include "sha256.hpp"

namespace zygveil::server_vpn {
namespace {

constexpr std::array<std::string_view, 15> kStatusKeys = {
    "schema_version",
    "feature",
    "state",
    "reason",
    "system_server_pid",
    "system_server_start_ticks",
    "boot_id",
    "artifact_generation",
    "config_generation",
    "catalog_version",
    "catalog_hook_count",
    "hook_count",
    "target_set_sha256",
    "engine_owner",
    "owner_generation",
};

bool SetError(std::string* error, std::string_view value) {
  if (error != nullptr) {
    error->assign(value);
  }
  return false;
}

bool IsSha256(std::string_view value) {
  return value.size() == 64 &&
      std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') ||
            (character >= 'a' && character <= 'f');
      });
}

bool IsBootId(std::string_view value) {
  if (value.size() != 36) {
    return false;
  }
  for (std::size_t index = 0; index < value.size(); ++index) {
    const bool separator = index == 8 || index == 13 || index == 18 || index == 23;
    if ((separator && value[index] != '-') ||
        (!separator && !((value[index] >= '0' && value[index] <= '9') ||
                         (value[index] >= 'a' && value[index] <= 'f')))) {
      return false;
    }
  }
  return true;
}

bool ParseUnsigned(std::string_view value, std::uint64_t maximum, std::uint64_t* output) {
  if (value.empty() || value.front() == '+' || value.front() == '-' || value.size() > 20) {
    return false;
  }
  std::uint64_t parsed = 0;
  const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
  if (result.ec != std::errc{} || result.ptr != value.data() + value.size() || parsed > maximum) {
    return false;
  }
  *output = parsed;
  return true;
}

std::optional<std::map<std::string, std::string>> ParseProperties(
    std::string_view input, std::string* error) {
  if (input.empty() || input.size() > kMaximumStatusBytes || input.back() != '\n') {
    SetError(error, "status_size_or_termination_invalid");
    return std::nullopt;
  }
  std::map<std::string, std::string> values;
  std::size_t offset = 0;
  while (offset < input.size()) {
    const std::size_t end = input.find('\n', offset);
    const std::string_view line = input.substr(offset, end - offset);
    offset = end + 1;
    const std::size_t separator = line.find('=');
    if (separator == std::string_view::npos || separator == 0 ||
        line.find('=', separator + 1) != std::string_view::npos) {
      SetError(error, "status_line_invalid");
      return std::nullopt;
    }
    const std::string_view key = line.substr(0, separator);
    const std::string_view value = line.substr(separator + 1);
    const bool ascii = std::all_of(line.begin(), line.end(), [](unsigned char character) {
      return character >= 0x21 && character <= 0x7e;
    });
    if (!ascii || value.empty() ||
        !values.emplace(std::string(key), std::string(value)).second) {
      SetError(error, "status_value_invalid");
      return std::nullopt;
    }
  }
  if (values.size() != kStatusKeys.size() ||
      !std::all_of(kStatusKeys.begin(), kStatusKeys.end(), [&](std::string_view key) {
        return values.contains(std::string(key));
      })) {
    SetError(error, "status_keys_invalid");
    return std::nullopt;
  }
  return values;
}

}  // namespace

bool ValidStatusReason(std::string_view reason) {
  return !reason.empty() && reason.size() <= 128 &&
      std::all_of(reason.begin(), reason.end(), [](unsigned char character) {
        return (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') || character == '_' ||
            character == ':' || character == '.' || character == '-';
      });
}

bool ValidateRuntimeStatus(const RuntimeStatus& status, std::string* error) {
  if (status.state != "arming" && status.state != "active" && status.state != "inactive") {
    return SetError(error, "status_state_invalid");
  }
  if (!ValidStatusReason(status.reason)) {
    return SetError(error, "status_reason_invalid");
  }
  if (status.system_server_pid == 0 || status.system_server_start_ticks == 0 ||
      !IsBootId(status.boot_id)) {
    return SetError(error, "status_process_identity_invalid");
  }
  if (status.artifact_generation != kArtifactGeneration ||
      status.owner_generation != kOwnerGeneration || status.catalog_version != 1 ||
      status.catalog_hook_count != kCatalogHookCount ||
      !IsSha256(status.target_set_sha256)) {
    return SetError(error, "status_generation_invalid");
  }
  if (status.config_generation > kMaximumConfigGeneration) {
    return SetError(error, "status_config_generation_invalid");
  }
  if ((status.state == "active" &&
       (status.config_generation == 0 || status.hook_count != kCatalogHookCount ||
        status.target_set_sha256 == std::string(64, '0'))) ||
      (status.state != "active" && status.hook_count != 0)) {
    return SetError(error, "status_activation_invalid");
  }
  if (error != nullptr) {
    error->clear();
  }
  return true;
}

std::optional<RuntimeStatus> ParseRuntimeStatus(std::string_view input, std::string* error) {
  const auto values = ParseProperties(input, error);
  if (!values.has_value() || values->at("schema_version") != "1" ||
      values->at("feature") != "server_vpn" ||
      values->at("engine_owner") != "shared") {
    if (values.has_value()) {
      SetError(error, "status_identity_invalid");
    }
    return std::nullopt;
  }
  std::uint64_t server_pid = 0;
  std::uint64_t start_ticks = 0;
  std::uint64_t artifact_generation = 0;
  std::uint64_t config_generation = 0;
  std::uint64_t catalog_version = 0;
  std::uint64_t catalog_hook_count = 0;
  std::uint64_t hook_count = 0;
  std::uint64_t owner_generation = 0;
  const std::uint64_t u32_max = std::numeric_limits<std::uint32_t>::max();
  if (!ParseUnsigned(values->at("system_server_pid"), u32_max, &server_pid) ||
      !ParseUnsigned(values->at("system_server_start_ticks"),
                     std::numeric_limits<std::uint64_t>::max(), &start_ticks) ||
      !ParseUnsigned(values->at("artifact_generation"), u32_max, &artifact_generation) ||
      !ParseUnsigned(values->at("config_generation"), kMaximumConfigGeneration,
                     &config_generation) ||
      !ParseUnsigned(values->at("catalog_version"), u32_max, &catalog_version) ||
      !ParseUnsigned(values->at("catalog_hook_count"), u32_max, &catalog_hook_count) ||
      !ParseUnsigned(values->at("hook_count"), u32_max, &hook_count) ||
      !ParseUnsigned(values->at("owner_generation"), u32_max, &owner_generation)) {
    SetError(error, "status_number_invalid");
    return std::nullopt;
  }
  RuntimeStatus status{
      .state = values->at("state"),
      .reason = values->at("reason"),
      .system_server_pid = static_cast<std::uint32_t>(server_pid),
      .system_server_start_ticks = start_ticks,
      .boot_id = values->at("boot_id"),
      .artifact_generation = static_cast<std::uint32_t>(artifact_generation),
      .config_generation = config_generation,
      .catalog_version = static_cast<std::uint32_t>(catalog_version),
      .catalog_hook_count = static_cast<std::uint32_t>(catalog_hook_count),
      .hook_count = static_cast<std::uint32_t>(hook_count),
      .target_set_sha256 = values->at("target_set_sha256"),
      .owner_generation = static_cast<std::uint32_t>(owner_generation),
  };
  return ValidateRuntimeStatus(status, error) ? std::optional<RuntimeStatus>{std::move(status)}
                                               : std::nullopt;
}

std::string EncodeRuntimeStatus(const RuntimeStatus& status) {
  return "schema_version=1\nfeature=server_vpn\nstate=" + status.state +
      "\nreason=" + status.reason +
      "\nsystem_server_pid=" + std::to_string(status.system_server_pid) +
      "\nsystem_server_start_ticks=" + std::to_string(status.system_server_start_ticks) +
      "\nboot_id=" + status.boot_id +
      "\nartifact_generation=" + std::to_string(status.artifact_generation) +
      "\nconfig_generation=" + std::to_string(status.config_generation) +
      "\ncatalog_version=" + std::to_string(status.catalog_version) +
      "\ncatalog_hook_count=" + std::to_string(status.catalog_hook_count) +
      "\nhook_count=" + std::to_string(status.hook_count) +
      "\ntarget_set_sha256=" + status.target_set_sha256 +
      "\nengine_owner=shared\nowner_generation=" +
      std::to_string(status.owner_generation) + "\n";
}

std::string TargetSetSha256(const Config& config) {
  return Sha256Hex("schema_version=2\ntarget_mode=" + config.target_mode +
                   "\nexclusions=wireguard,controller,canary,magisk\n");
}

}  // namespace zygveil::server_vpn
