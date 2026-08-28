// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "control_protocol.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <climits>
#include <cmath>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <utility>

namespace zygveil::location {
namespace {

constexpr std::size_t kAtomicWordBytes = sizeof(std::uint64_t);
constexpr int kReadAttempts = 8;

bool WaitReadable(int descriptor, int timeout_ms) {
  if (timeout_ms < 0) {
    return false;
  }
  struct timespec started {};
  if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
    return false;
  }
  const std::int64_t deadline_ms =
      static_cast<std::int64_t>(started.tv_sec) * 1000 + started.tv_nsec / 1000000 + timeout_ms;
  while (true) {
    struct timespec now {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
      return false;
    }
    const std::int64_t now_ms =
        static_cast<std::int64_t>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
    const std::int64_t remaining = std::max<std::int64_t>(0, deadline_ms - now_ms);
    struct pollfd candidate {
      .fd = descriptor, .events = POLLIN, .revents = 0
    };
    const int result = poll(&candidate, 1, static_cast<int>(remaining));
    if (result > 0) {
      return (candidate.revents & POLLIN) != 0;
    }
    if (result == 0 || errno != EINTR) {
      return false;
    }
  }
}

bool SetError(std::string* error, std::string message) {
  if (error != nullptr) {
    *error = std::move(message);
  }
  return false;
}

template <typename T>
T LoadAcquire(const T* value) {
  return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

template <typename T>
T LoadRelaxed(const T* value) {
  return __atomic_load_n(value, __ATOMIC_RELAXED);
}

template <typename T>
void StoreRelease(T* destination, T value) {
  __atomic_store_n(destination, value, __ATOMIC_RELEASE);
}

template <typename T>
void StoreRelaxed(T* destination, T value) {
  __atomic_store_n(destination, value, __ATOMIC_RELAXED);
}

void StoreSlot(ControlSlotStorage* destination, const ControlSlot& source) {
  const auto* input = reinterpret_cast<const std::byte*>(&source);
  for (std::size_t index = 0; index < destination->words.size(); ++index) {
    std::uint64_t word = 0;
    std::memcpy(&word, input + index * kAtomicWordBytes, sizeof(word));
    StoreRelaxed(&destination->words[index], word);
  }
}

ControlSlot LoadSlot(const ControlSlotStorage& source) {
  ControlSlot result{};
  auto* output = reinterpret_cast<std::byte*>(&result);
  for (std::size_t index = 0; index < source.words.size(); ++index) {
    const std::uint64_t word = LoadRelaxed(&source.words[index]);
    std::memcpy(output + index * kAtomicWordBytes, &word, sizeof(word));
  }
  return result;
}

std::uint64_t AckToken(std::uint64_t generation, ControlAckState state) {
  return generation << 2U | static_cast<std::uint64_t>(state);
}

using GenerationLoader = std::uint64_t (*)(const ControlPage& page);

ControlReadResult ReadControlConfig(const ControlPage& page,
                                    std::uint64_t current_generation, Config* candidate,
                                    ControlReason* reason, GenerationLoader load_generation) {
  if (reason != nullptr) {
    *reason = ControlReason::kNone;
  }
  for (int attempt = 0; attempt < kReadAttempts; ++attempt) {
    const std::uint64_t generation = load_generation(page);
    if (generation == current_generation) {
      return ControlReadResult::kNoUpdate;
    }
    if (generation < current_generation) {
      if (reason != nullptr) {
        *reason = ControlReason::kStaleGeneration;
      }
      return ControlReadResult::kStale;
    }
    if (generation == 0 || generation > kMaximumControlGeneration) {
      if (reason != nullptr) {
        *reason = ControlReason::kGenerationWrap;
      }
      return ControlReadResult::kInvalid;
    }
    const ControlSlot slot = LoadSlot(page.slots[generation & 1U]);
    if (generation != load_generation(page)) {
      continue;
    }
    if (slot.generation != generation || slot.payload_size != sizeof(WireConfig)) {
      if (reason != nullptr) {
        *reason = ControlReason::kInvalidSlot;
      }
      return ControlReadResult::kInvalid;
    }
    if (slot.checksum != Crc32c(&slot.payload, sizeof(slot.payload))) {
      if (reason != nullptr) {
        *reason = ControlReason::kChecksumMismatch;
      }
      return ControlReadResult::kInvalid;
    }
    std::string decode_error;
    const auto decoded = DecodeConfig(slot.payload, &decode_error);
    if (!decoded.has_value() || decoded->config_generation != generation) {
      if (reason != nullptr) {
        *reason = ControlReason::kInvalidConfig;
      }
      return ControlReadResult::kInvalid;
    }
    if (BootFieldsDigest(slot.payload) != page.header.boot_fields_digest) {
      if (reason != nullptr) {
        *reason = ControlReason::kBootFieldMismatch;
      }
      return ControlReadResult::kInvalid;
    }
    if (candidate != nullptr) {
      *candidate = *decoded;
    }
    return ControlReadResult::kReady;
  }
  return ControlReadResult::kRetry;
}

ControlAck DecodeAck(std::uint64_t token, ControlReason reason) {
  const auto state = static_cast<ControlAckState>(token & 0x3U);
  if (state > ControlAckState::kRejected) {
    return {};
  }
  return {token >> 2U, state, reason};
}

template <typename T>
void DigestValue(std::uint64_t* digest, const T& value) {
  const auto* bytes = reinterpret_cast<const unsigned char*>(&value);
  for (std::size_t index = 0; index < sizeof(T); ++index) {
    *digest ^= bytes[index];
    *digest *= 1099511628211ULL;
  }
}

}  // namespace

bool AcquireControlLock(int descriptor, ControlLockMode mode) {
  struct flock lock {};
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  const int command = mode == ControlLockMode::kWait ? F_SETLKW : F_SETLK;
  while (fcntl(descriptor, command, &lock) != 0) {
    if (errno != EINTR) {
      return false;
    }
  }
  return true;
}

bool ValidateControlMemfdDescriptor(int descriptor, uid_t expected_uid, gid_t expected_gid,
                                    std::string* error, int expected_access_mode) {
  struct stat status {};
  const int flags = descriptor >= 0 ? fcntl(descriptor, F_GETFL) : -1;
  const int seals = descriptor >= 0 ? fcntl(descriptor, F_GET_SEALS) : -1;
  if (flags < 0 || seals != kControlMemfdSeals ||
      (flags & O_ACCMODE) != expected_access_mode ||
      fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_uid != expected_uid || status.st_gid != expected_gid || status.st_nlink != 0 ||
      (status.st_mode & 07777) != kControlMemfdMode ||
      status.st_size != static_cast<off_t>(sizeof(ControlPage))) {
    return SetError(error, "control_memfd_identity_invalid");
  }
  return true;
}

bool SendChannelToken(int socket, char token) {
  ssize_t sent;
  do {
    sent = send(socket, &token, sizeof(token), MSG_NOSIGNAL);
  } while (sent < 0 && errno == EINTR);
  return sent == static_cast<ssize_t>(sizeof(token));
}

bool ReceiveChannelBytes(int socket, void* buffer, std::size_t bytes, int timeout_ms,
                         std::string* error) {
  if (socket < 0 || (buffer == nullptr && bytes != 0) || timeout_ms < 0) {
    return SetError(error, "channel_read_invalid");
  }
  struct timespec started {};
  if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
    return SetError(error, "channel_clock_failed");
  }
  const std::int64_t deadline_ms =
      static_cast<std::int64_t>(started.tv_sec) * 1000 + started.tv_nsec / 1000000 + timeout_ms;
  auto* output = static_cast<std::byte*>(buffer);
  while (bytes > 0) {
    struct timespec now {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
      return SetError(error, "channel_clock_failed");
    }
    const std::int64_t now_ms =
        static_cast<std::int64_t>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
    const std::int64_t remaining_ms = std::max<std::int64_t>(0, deadline_ms - now_ms);
    if (!WaitReadable(socket, static_cast<int>(std::min<std::int64_t>(remaining_ms, INT_MAX)))) {
      return SetError(error, "channel_read_timeout");
    }
    ssize_t received;
    do {
      received = recv(socket, output, bytes, 0);
    } while (received < 0 && errno == EINTR);
    if (received <= 0) {
      return SetError(error, "channel_read_incomplete");
    }
    output += received;
    bytes -= static_cast<std::size_t>(received);
  }
  return true;
}

bool SendChannelDescriptor(int socket, int descriptor, char token) {
  struct iovec vector {
    .iov_base = &token, .iov_len = sizeof(token)
  };
  std::array<char, CMSG_SPACE(sizeof(descriptor))> control{};
  struct msghdr message {};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = control.data();
  message.msg_controllen = control.size();
  struct cmsghdr* header = CMSG_FIRSTHDR(&message);
  if (header == nullptr) {
    return false;
  }
  header->cmsg_level = SOL_SOCKET;
  header->cmsg_type = SCM_RIGHTS;
  header->cmsg_len = CMSG_LEN(sizeof(descriptor));
  std::memcpy(CMSG_DATA(header), &descriptor, sizeof(descriptor));
  ssize_t sent;
  do {
    sent = sendmsg(socket, &message, MSG_NOSIGNAL);
  } while (sent < 0 && errno == EINTR);
  return sent == static_cast<ssize_t>(sizeof(token));
}

std::optional<ChannelMessage> ReceiveChannelMessage(int socket, int timeout_ms,
                                                    std::string* error) {
  if (!WaitReadable(socket, timeout_ms)) {
    SetError(error, "channel_not_readable");
    return std::nullopt;
  }
  char token = '\0';
  struct iovec vector {
    .iov_base = &token, .iov_len = sizeof(token)
  };
  std::array<char, 4096> control{};
  struct msghdr message {};
  message.msg_iov = &vector;
  message.msg_iovlen = 1;
  message.msg_control = control.data();
  message.msg_controllen = control.size();
  ssize_t received;
  do {
    received = recvmsg(socket, &message, MSG_CMSG_CLOEXEC);
  } while (received < 0 && errno == EINTR);
  int descriptor = -1;
  bool ancillary_valid = true;
  bool credentials_seen = false;
  bool security_seen = false;
  for (struct cmsghdr* header = CMSG_FIRSTHDR(&message); header != nullptr;
       header = CMSG_NXTHDR(&message, header)) {
    if (header->cmsg_level != SOL_SOCKET) {
      ancillary_valid = false;
      continue;
    }
    if (header->cmsg_type == SCM_RIGHTS) {
      const std::size_t payload_bytes = header->cmsg_len >= CMSG_LEN(0)
          ? header->cmsg_len - CMSG_LEN(0)
          : 0;
      if (payload_bytes == 0 || payload_bytes % sizeof(int) != 0) {
        ancillary_valid = false;
        continue;
      }
      const std::size_t count = payload_bytes / sizeof(int);
      for (std::size_t index = 0; index < count; ++index) {
        int candidate = -1;
        std::memcpy(&candidate, reinterpret_cast<const char*>(CMSG_DATA(header)) +
                                      index * sizeof(int),
                    sizeof(candidate));
        if (candidate < 0 || descriptor >= 0 || count != 1) {
          ancillary_valid = false;
          if (candidate >= 0) {
            close(candidate);
          }
        } else {
          descriptor = candidate;
        }
      }
      continue;
    }
    if (header->cmsg_type == SCM_CREDENTIALS &&
        header->cmsg_len == CMSG_LEN(sizeof(struct ucred)) && !credentials_seen) {
      struct ucred credentials {};
      std::memcpy(&credentials, CMSG_DATA(header), sizeof(credentials));
      credentials_seen = true;
      ancillary_valid = ancillary_valid && credentials.pid > 0 && credentials.uid == 0 &&
          credentials.gid == 0;
      continue;
    }
#ifdef SCM_SECURITY
    if (header->cmsg_type == SCM_SECURITY && header->cmsg_len >= CMSG_LEN(1) &&
        !security_seen) {
      const std::size_t payload_bytes = header->cmsg_len - CMSG_LEN(0);
      const auto* label = reinterpret_cast<const unsigned char*>(CMSG_DATA(header));
      security_seen = true;
      const bool label_valid = payload_bytes <= 256 && label[payload_bytes - 1] == '\0' &&
          std::find(label, label + payload_bytes - 1, '\0') == label + payload_bytes - 1 &&
          std::all_of(label, label + payload_bytes - 1, [](unsigned char value) {
            return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                (value >= '0' && value <= '9') || value == ':' || value == '_' ||
                value == '-' || value == '.';
          });
      ancillary_valid = ancillary_valid && label_valid;
      continue;
    }
#endif
    ancillary_valid = false;
  }
  const bool valid = received == static_cast<ssize_t>(sizeof(token)) && ancillary_valid &&
      (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) == 0;
  if (!valid) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    SetError(error, received != static_cast<ssize_t>(sizeof(token))
                        ? "channel_payload_invalid"
                    : (message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0
                        ? "channel_ancillary_truncated"
                        : "channel_ancillary_invalid");
    return std::nullopt;
  }
  return ChannelMessage{token, descriptor};
}

bool ReceiveChannelToken(int socket, char expected_token, int timeout_ms,
                         std::string* error) {
  auto message = ReceiveChannelMessage(socket, timeout_ms, error);
  if (!message.has_value()) {
    return false;
  }
  if (message->descriptor >= 0) {
    close(message->descriptor);
    return SetError(error, "channel_descriptor_unexpected");
  }
  return message->token == expected_token || SetError(error, "channel_token_mismatch");
}

int ReceiveChannelDescriptor(int socket, char expected_token, int timeout_ms,
                             std::string* error) {
  auto message = ReceiveChannelMessage(socket, timeout_ms, error);
  if (!message.has_value()) {
    return -1;
  }
  if (message->token != expected_token || message->descriptor < 0) {
    if (message->descriptor >= 0) {
      close(message->descriptor);
    }
    SetError(error, message->token != expected_token ? "channel_token_mismatch"
                                                     : "channel_descriptor_missing");
    return -1;
  }
  return message->descriptor;
}

WireConfig EncodeConfig(const Config& config) {
  return {
      .schema_version = static_cast<std::uint32_t>(config.schema_version),
      .enabled = config.enabled ? 1U : 0U,
      .raw_gnss_mode = static_cast<std::uint32_t>(config.raw_gnss_mode),
      .reserved = 0,
      .config_generation = config.config_generation,
      .random_seed = config.random_seed,
      .center_latitude_deg = config.center_latitude_deg,
      .center_longitude_deg = config.center_longitude_deg,
      .altitude_ellipsoid_m = config.altitude_ellipsoid_m,
      .altitude_msl_m = config.altitude_msl_m,
      .horizontal_jitter_sigma_m = config.horizontal_jitter_sigma_m,
      .horizontal_jitter_radius_m = config.horizontal_jitter_radius_m,
      .horizontal_correlation_time_s = config.horizontal_correlation_time_s,
      .vertical_jitter_sigma_m = config.vertical_jitter_sigma_m,
      .accuracy_correlation_time_s = config.accuracy_correlation_time_s,
      .speed_deadband_mps = config.speed_deadband_mps,
      .speed_max_mps = config.speed_max_mps,
      .bearing_min_speed_mps = config.bearing_min_speed_mps,
  };
}

std::optional<Config> DecodeConfig(const WireConfig& wire, std::string* error) {
  if (wire.reserved != 0 || wire.schema_version > static_cast<std::uint32_t>(INT_MAX) ||
      wire.enabled > 1U ||
      wire.raw_gnss_mode > static_cast<std::uint32_t>(RawGnssMode::kUnsupported)) {
    SetError(error, "wire_shape_invalid");
    return std::nullopt;
  }
  Config config{
      .schema_version = static_cast<int>(wire.schema_version),
      .enabled = wire.enabled == 1U,
      .raw_gnss_mode = static_cast<RawGnssMode>(wire.raw_gnss_mode),
      .center_latitude_deg = wire.center_latitude_deg,
      .center_longitude_deg = wire.center_longitude_deg,
      .altitude_ellipsoid_m = wire.altitude_ellipsoid_m,
      .altitude_msl_m = wire.altitude_msl_m,
      .horizontal_jitter_sigma_m = wire.horizontal_jitter_sigma_m,
      .horizontal_jitter_radius_m = wire.horizontal_jitter_radius_m,
      .horizontal_correlation_time_s = wire.horizontal_correlation_time_s,
      .vertical_jitter_sigma_m = wire.vertical_jitter_sigma_m,
      .accuracy_correlation_time_s = wire.accuracy_correlation_time_s,
      .speed_deadband_mps = wire.speed_deadband_mps,
      .speed_max_mps = wire.speed_max_mps,
      .bearing_min_speed_mps = wire.bearing_min_speed_mps,
      .random_seed = wire.random_seed,
      .config_generation = wire.config_generation,
  };
  if (config.config_generation > kMaximumControlGeneration || !ValidateConfig(config, error)) {
    return std::nullopt;
  }
  return config;
}

std::uint32_t Crc32c(const void* data, std::size_t size) {
  const auto* bytes = static_cast<const unsigned char*>(data);
  std::uint32_t crc = UINT32_MAX;
  for (std::size_t index = 0; index < size; ++index) {
    crc ^= bytes[index];
    for (int bit = 0; bit < 8; ++bit) {
      const std::uint32_t mask = 0U - (crc & 1U);
      crc = (crc >> 1U) ^ (0x82f63b78U & mask);
    }
  }
  return ~crc;
}

std::uint64_t BootFieldsDigest(const WireConfig& config) {
  std::uint64_t digest = 1469598103934665603ULL;
  DigestValue(&digest, config.schema_version);
  DigestValue(&digest, config.raw_gnss_mode);
  DigestValue(&digest, config.random_seed);
  DigestValue(&digest, config.horizontal_jitter_sigma_m);
  DigestValue(&digest, config.horizontal_jitter_radius_m);
  DigestValue(&digest, config.horizontal_correlation_time_s);
  DigestValue(&digest, config.vertical_jitter_sigma_m);
  DigestValue(&digest, config.accuracy_correlation_time_s);
  DigestValue(&digest, config.speed_deadband_mps);
  DigestValue(&digest, config.speed_max_mps);
  DigestValue(&digest, config.bearing_min_speed_mps);
  return digest;
}

bool InitializeControlPage(ControlPage* page, const Config& boot_config, std::uint32_t server_pid,
                           std::string_view boot_id, std::string* error) {
  if (page == nullptr || server_pid == 0 || boot_id.empty() || boot_id.size() >= kControlBootIdBytes) {
    return SetError(error, "page_identity_invalid");
  }
  std::string config_error;
  if (!ValidateConfig(boot_config, &config_error) ||
      boot_config.config_generation > kMaximumControlGeneration) {
    return SetError(error, "boot_config_invalid:" + config_error);
  }
  std::memset(page, 0, sizeof(*page));
  page->header.magic = kControlPageMagic;
  page->header.schema_version = kControlPageSchema;
  page->header.page_size = kControlPageBytes;
  page->header.server_pid = server_pid;
  page->header.runtime_state = static_cast<std::uint32_t>(ControlRuntimeState::kArming);
  page->header.boot_config_generation = boot_config.config_generation;
  const WireConfig wire = EncodeConfig(boot_config);
  page->header.boot_fields_digest = BootFieldsDigest(wire);
  std::memcpy(page->header.boot_id.data(), boot_id.data(), boot_id.size());

  ControlSlot initial{};
  initial.generation = boot_config.config_generation;
  initial.payload_size = sizeof(WireConfig);
  initial.payload = wire;
  initial.checksum = Crc32c(&initial.payload, sizeof(initial.payload));
  StoreSlot(&page->slots[boot_config.config_generation & 1U], initial);
  page->header.published_generation = boot_config.config_generation;
  page->header.applied_generation = boot_config.config_generation;
  page->header.acknowledgement_reason = static_cast<std::uint32_t>(ControlReason::kNone);
  page->header.acknowledgement_token =
      AckToken(boot_config.config_generation, ControlAckState::kApplied);
  return true;
}

bool ValidateControlPage(const ControlPage& page, std::string* error) {
  if (page.header.magic != kControlPageMagic ||
      page.header.schema_version != kControlPageSchema || page.header.page_size != kControlPageBytes ||
      page.header.server_pid == 0 || page.header.boot_config_generation == 0 ||
      page.header.boot_config_generation > kMaximumControlGeneration) {
    return SetError(error, "page_header_invalid");
  }
  const auto state = static_cast<ControlRuntimeState>(LoadAcquire(&page.header.runtime_state));
  if (state > ControlRuntimeState::kInactive) {
    return SetError(error, "page_runtime_state_invalid");
  }
  const auto terminator = std::find(page.header.boot_id.begin(), page.header.boot_id.end(), '\0');
  if (terminator == page.header.boot_id.begin() || terminator == page.header.boot_id.end()) {
    return SetError(error, "page_boot_id_invalid");
  }
  const std::uint64_t published = LoadAcquire(&page.header.published_generation);
  if (published == 0 || published > kMaximumControlGeneration) {
    return SetError(error, "page_generation_invalid");
  }
  return true;
}

bool ValidateControlIdentity(const ControlPage& page, std::uint32_t server_pid,
                             std::string_view boot_id, std::uint64_t boot_generation,
                             std::uint64_t boot_fields_digest, std::string* error) {
  if (!ValidateControlPage(page, error)) {
    return false;
  }
  const std::string_view stored_boot_id(page.header.boot_id.data());
  if (page.header.server_pid != server_pid || stored_boot_id != boot_id ||
      page.header.boot_config_generation != boot_generation ||
      page.header.boot_fields_digest != boot_fields_digest) {
    return SetError(error, "page_identity_mismatch");
  }
  return true;
}

ControlRuntimeState LoadControlRuntimeState(const ControlPage& page) {
  const auto value = LoadAcquire(&page.header.runtime_state);
  if (value > static_cast<std::uint32_t>(ControlRuntimeState::kInactive)) {
    return ControlRuntimeState::kUninitialized;
  }
  return static_cast<ControlRuntimeState>(value);
}

void StoreControlRuntimeState(ControlPage* page, ControlRuntimeState state) {
  if (page != nullptr) {
    StoreRelease(&page->header.runtime_state, static_cast<std::uint32_t>(state));
  }
}

std::uint64_t LoadPublishedGeneration(const ControlPage& page) {
  return LoadAcquire(&page.header.published_generation);
}

std::uint64_t LoadAppliedGeneration(const ControlPage& page) {
  return LoadAcquire(&page.header.applied_generation);
}

bool PublishControlConfig(ControlPage* page, const Config& armed, const Config& candidate,
                          std::string* error) {
  if (page == nullptr || !ValidateControlPage(*page, error)) {
    return false;
  }
  const ControlRuntimeState runtime = LoadControlRuntimeState(*page);
  if (runtime != ControlRuntimeState::kWaiting && runtime != ControlRuntimeState::kActive) {
    return SetError(error, "runtime_inactive");
  }
  const std::uint64_t published = LoadPublishedGeneration(*page);
  if (candidate.config_generation > kMaximumControlGeneration) {
    return SetError(error, "generation_wrap");
  }
  if (!ValidateLiveTransition(armed, candidate, published, error)) {
    return false;
  }
  const WireConfig wire = EncodeConfig(candidate);
  if (BootFieldsDigest(wire) != page->header.boot_fields_digest) {
    return SetError(error, "boot_field_mismatch");
  }
  ControlSlot slot{};
  slot.generation = candidate.config_generation;
  slot.payload_size = sizeof(WireConfig);
  slot.payload = wire;
  slot.checksum = Crc32c(&slot.payload, sizeof(slot.payload));
  StoreSlot(&page->slots[candidate.config_generation & 1U], slot);
  StoreRelaxed(&page->header.acknowledgement_reason,
               static_cast<std::uint32_t>(ControlReason::kNone));
  StoreRelease(&page->header.acknowledgement_token,
               AckToken(candidate.config_generation, ControlAckState::kPending));
  StoreRelease(&page->header.published_generation, candidate.config_generation);
  return true;
}

ControlReadResult ReadPublishedControlConfig(const ControlPage& page,
                                             std::uint64_t applied_generation, Config* candidate,
                                             ControlReason* reason) {
  return ReadControlConfig(page, applied_generation, candidate, reason,
                           LoadPublishedGeneration);
}

ControlReadResult ReadAppliedControlConfig(const ControlPage& page,
                                           std::uint64_t current_generation, Config* candidate,
                                           ControlReason* reason) {
  const std::uint64_t applied = LoadAppliedGeneration(page);
  if (applied > LoadPublishedGeneration(page)) {
    if (reason != nullptr) {
      *reason = ControlReason::kInvalidSlot;
    }
    return ControlReadResult::kInvalid;
  }
  return ReadControlConfig(page, current_generation, candidate, reason,
                           LoadAppliedGeneration);
}

void PublishControlAck(ControlPage* page, std::uint64_t generation, ControlAckState state,
                       ControlReason reason) {
  if (page == nullptr || generation == 0 || generation > kMaximumControlGeneration ||
      (state != ControlAckState::kApplied && state != ControlAckState::kRejected)) {
    return;
  }
  StoreRelaxed(&page->header.acknowledgement_reason, static_cast<std::uint32_t>(reason));
  if (state == ControlAckState::kApplied) {
    StoreRelease(&page->header.applied_generation, generation);
  }
  StoreRelease(&page->header.acknowledgement_token, AckToken(generation, state));
}

ControlAck ReadControlAck(const ControlPage& page) {
  for (int attempt = 0; attempt < kReadAttempts; ++attempt) {
    const std::uint64_t token = LoadAcquire(&page.header.acknowledgement_token);
    const auto reason_value = LoadRelaxed(&page.header.acknowledgement_reason);
    if (token != LoadAcquire(&page.header.acknowledgement_token)) {
      continue;
    }
    const auto reason = reason_value <= static_cast<std::uint32_t>(ControlReason::kInternalError)
                            ? static_cast<ControlReason>(reason_value)
                            : ControlReason::kInternalError;
    return DecodeAck(token, reason);
  }
  return {};
}

std::string_view ControlRuntimeStateName(ControlRuntimeState state) {
  switch (state) {
    case ControlRuntimeState::kUninitialized:
      return "uninitialized";
    case ControlRuntimeState::kArming:
      return "arming";
    case ControlRuntimeState::kWaiting:
      return "waiting";
    case ControlRuntimeState::kActive:
      return "active";
    case ControlRuntimeState::kInactive:
      return "inactive";
  }
  return "invalid";
}

std::string_view ControlAckStateName(ControlAckState state) {
  switch (state) {
    case ControlAckState::kNone:
      return "none";
    case ControlAckState::kPending:
      return "saved_pending_upstream";
    case ControlAckState::kApplied:
      return "applied";
    case ControlAckState::kRejected:
      return "rejected";
  }
  return "invalid";
}

std::string_view ControlReasonName(ControlReason reason) {
  switch (reason) {
    case ControlReason::kNone:
      return "none";
    case ControlReason::kInvalidPage:
      return "invalid_page";
    case ControlReason::kIdentityMismatch:
      return "identity_mismatch";
    case ControlReason::kRuntimeInactive:
      return "runtime_inactive";
    case ControlReason::kInvalidConfig:
      return "invalid_config";
    case ControlReason::kBootFieldMismatch:
      return "boot_field_mismatch";
    case ControlReason::kStaleGeneration:
      return "stale_generation";
    case ControlReason::kGenerationWrap:
      return "generation_wrap";
    case ControlReason::kInvalidSlot:
      return "invalid_slot";
    case ControlReason::kChecksumMismatch:
      return "checksum_mismatch";
    case ControlReason::kPersistenceFailed:
      return "persistence_failed";
    case ControlReason::kInternalError:
      return "internal_error";
  }
  return "invalid";
}

}  // namespace zygveil::location
