// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <atomic>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>

#include "model.hpp"

namespace zygveil::location {

inline constexpr std::uint64_t kControlPageMagic = 0x4c525443434f4c47ULL;
inline constexpr std::uint32_t kControlPageSchema = 1;
inline constexpr std::size_t kControlPageBytes = 4096;
inline constexpr std::size_t kControlBootIdBytes = 40;
inline constexpr std::uint64_t kMaximumControlGeneration = kMaximumConfigGeneration;
inline constexpr std::string_view kControlMemfdName = "zygveil-location-control";
inline constexpr std::string_view kControlMemfdProcTarget =
    "/memfd:zygveil-location-control (deleted)";
inline constexpr mode_t kControlMemfdMode = 0777;
inline constexpr int kControlMemfdSeals = F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;

enum class ControlLockMode {
  kTry,
  kWait,
};

enum class ControlRuntimeState : std::uint32_t {
  kUninitialized = 0,
  kArming = 1,
  kWaiting = 2,
  kActive = 3,
  kInactive = 4,
};

enum class ControlAckState : std::uint32_t {
  kNone = 0,
  kPending = 1,
  kApplied = 2,
  kRejected = 3,
};

enum class ControlReason : std::uint32_t {
  kNone = 0,
  kInvalidPage = 1,
  kIdentityMismatch = 2,
  kRuntimeInactive = 3,
  kInvalidConfig = 4,
  kBootFieldMismatch = 5,
  kStaleGeneration = 6,
  kGenerationWrap = 7,
  kInvalidSlot = 8,
  kChecksumMismatch = 9,
  kPersistenceFailed = 10,
  kInternalError = 11,
};

enum class ControlReadResult {
  kNoUpdate,
  kReady,
  kStale,
  kInvalid,
  kRetry,
};

struct ChannelMessage {
  char token = '\0';
  int descriptor = -1;
};

struct WireConfig {
  std::uint32_t schema_version;
  std::uint32_t enabled;
  std::uint32_t raw_gnss_mode;
  std::uint32_t reserved;
  std::uint64_t config_generation;
  std::uint64_t random_seed;
  double center_latitude_deg;
  double center_longitude_deg;
  double altitude_ellipsoid_m;
  double altitude_msl_m;
  double horizontal_jitter_sigma_m;
  double horizontal_jitter_radius_m;
  double horizontal_correlation_time_s;
  double vertical_jitter_sigma_m;
  double accuracy_correlation_time_s;
  double speed_deadband_mps;
  double speed_max_mps;
  double bearing_min_speed_mps;
};

struct alignas(64) ControlSlot {
  std::uint64_t generation;
  std::uint32_t payload_size;
  std::uint32_t checksum;
  WireConfig payload;
  std::array<std::byte, 48> reserved;
};

struct alignas(64) ControlSlotStorage {
  std::array<std::uint64_t, sizeof(ControlSlot) / sizeof(std::uint64_t)> words;
};

struct alignas(64) ControlPageHeader {
  std::uint64_t magic;
  std::uint32_t schema_version;
  std::uint32_t page_size;
  std::uint32_t server_pid;
  std::uint32_t runtime_state;
  std::uint64_t boot_config_generation;
  std::uint64_t boot_fields_digest;
  std::array<char, kControlBootIdBytes> boot_id;
  std::uint64_t published_generation;
  std::uint64_t applied_generation;
  std::uint64_t acknowledgement_token;
  std::uint32_t acknowledgement_reason;
  std::array<std::byte, 20> reserved;
};

struct alignas(64) ControlPage {
  ControlPageHeader header;
  std::array<ControlSlotStorage, 2> slots;
  std::array<std::byte, 3584> reserved;
};

struct ControlAck {
  std::uint64_t generation = 0;
  ControlAckState state = ControlAckState::kNone;
  ControlReason reason = ControlReason::kNone;
};

static_assert(sizeof(WireConfig) == 128);
static_assert(sizeof(ControlSlot) == 192);
static_assert(sizeof(ControlSlotStorage) == sizeof(ControlSlot));
static_assert(alignof(ControlSlotStorage) == 64);
static_assert(sizeof(ControlPageHeader) == 128);
static_assert(sizeof(ControlPage) == kControlPageBytes);
static_assert(alignof(ControlPage) == 64);
static_assert(offsetof(ControlPageHeader, published_generation) % alignof(std::uint64_t) == 0);
static_assert(offsetof(ControlPageHeader, acknowledgement_token) % alignof(std::uint64_t) == 0);
static_assert(sizeof(ControlSlot) % sizeof(std::uint64_t) == 0);
static_assert(std::atomic<std::uint64_t>::is_always_lock_free);

WireConfig EncodeConfig(const Config& config);
std::optional<Config> DecodeConfig(const WireConfig& wire, std::string* error);

std::uint32_t Crc32c(const void* data, std::size_t size);
std::uint64_t BootFieldsDigest(const WireConfig& config);
bool AcquireControlLock(int descriptor, ControlLockMode mode);
bool ValidateControlMemfdDescriptor(int descriptor, uid_t expected_uid, gid_t expected_gid,
                                    std::string* error, int expected_access_mode = O_RDWR);
bool SendChannelToken(int socket, char token);
bool ReceiveChannelBytes(int socket, void* buffer, std::size_t bytes, int timeout_ms,
                         std::string* error = nullptr);
std::optional<ChannelMessage> ReceiveChannelMessage(int socket, int timeout_ms,
                                                    std::string* error = nullptr);
bool ReceiveChannelToken(int socket, char expected_token, int timeout_ms,
                         std::string* error = nullptr);
bool SendChannelDescriptor(int socket, int descriptor, char token);
int ReceiveChannelDescriptor(int socket, char expected_token, int timeout_ms,
                             std::string* error = nullptr);

bool InitializeControlPage(ControlPage* page, const Config& boot_config, std::uint32_t server_pid,
                           std::string_view boot_id, std::string* error);
bool ValidateControlPage(const ControlPage& page, std::string* error);
bool ValidateControlIdentity(const ControlPage& page, std::uint32_t server_pid,
                             std::string_view boot_id, std::uint64_t boot_generation,
                             std::uint64_t boot_fields_digest, std::string* error);

ControlRuntimeState LoadControlRuntimeState(const ControlPage& page);
void StoreControlRuntimeState(ControlPage* page, ControlRuntimeState state);
std::uint64_t LoadPublishedGeneration(const ControlPage& page);
std::uint64_t LoadAppliedGeneration(const ControlPage& page);

bool PublishControlConfig(ControlPage* page, const Config& armed, const Config& candidate,
                          std::string* error);
ControlReadResult ReadPublishedControlConfig(const ControlPage& page,
                                             std::uint64_t applied_generation, Config* candidate,
                                             ControlReason* reason);
ControlReadResult ReadAppliedControlConfig(const ControlPage& page,
                                           std::uint64_t current_generation, Config* candidate,
                                           ControlReason* reason);

void PublishControlAck(ControlPage* page, std::uint64_t generation, ControlAckState state,
                       ControlReason reason);
ControlAck ReadControlAck(const ControlPage& page);

std::string_view ControlRuntimeStateName(ControlRuntimeState state);
std::string_view ControlAckStateName(ControlAckState state);
std::string_view ControlReasonName(ControlReason reason);

}  // namespace zygveil::location
