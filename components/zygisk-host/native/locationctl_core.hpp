// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>

#include "control_protocol.hpp"

namespace zygveil::location {

inline constexpr std::size_t kMaximumLiveInputBytes = 1024;
inline constexpr std::size_t kMaximumConfigBytes = 32 * 1024;
inline constexpr std::size_t kMaximumRuntimeStatusBytes = 4096;

struct LiveInput {
  double center_latitude_deg = 0.0;
  double center_longitude_deg = 0.0;
  double altitude_ellipsoid_m = 0.0;
  double altitude_msl_m = 0.0;
};

struct HelperStatus {
  std::string module_state = "inactive";
  std::string runtime_state = "unavailable";
  std::string control_state = "unavailable";
  std::string reason = "none";
  std::uint64_t boot_config_generation = 0;
  std::uint64_t persisted_generation = 0;
  std::uint64_t published_generation = 0;
  std::uint64_t applied_generation = 0;
  std::uint32_t system_server_pid = 0;
  std::uint64_t system_server_start_ticks = 0;
  std::string boot_id = "unavailable";
  RawGnssMode raw_gnss_mode = RawGnssMode::kBlocked;
  std::optional<Config> config;
};

struct RuntimeControlStatus {
  std::string state;
  std::string reason;
  std::string raw_gnss_mode;
  std::uint32_t hook_count = 0;
  std::uint32_t system_server_pid = 0;
  std::uint64_t system_server_start_ticks = 0;
  std::uint64_t config_generation = 0;
  std::string boot_id;
  int control_fd = 0;
  std::uint32_t control_owner_pid = 0;
  std::uint64_t control_owner_start_ticks = 0;
};

enum class ConfigPersistenceResult {
  kNotCommitted,
  kCommitted,
  kDurable,
};

std::optional<LiveInput> ParseLiveInput(std::string_view text, std::string* error);
std::optional<Config> BuildLiveCandidate(const Config& persisted,
                                         std::uint64_t published_generation,
                                         const LiveInput& input, std::string* error);
std::string RenderConfig(const Config& config);
std::string RenderHelperStatus(const HelperStatus& status, bool include_coordinates);
HelperStatus DeriveHelperStatus(const Config& config, const ControlPage* page,
                                std::string_view fallback_reason = "runtime_inactive");
std::optional<RuntimeControlStatus> ParseRuntimeControlStatus(std::string_view text,
                                                              std::string* error);
std::optional<std::uint64_t> ParseProcessStartTicks(std::string_view stat);
bool ValidRuntimeStatusReason(std::string_view reason);

std::optional<Config> ReadConfigAt(int directory, uid_t expected_uid, gid_t expected_gid,
                                   std::string* error);
std::optional<RuntimeControlStatus> ReadRuntimeControlStatusAt(
    int directory, uid_t expected_uid, gid_t expected_gid, std::string* error);
ConfigPersistenceResult PersistConfigAt(int directory, const Config& config, uid_t owner,
                                        gid_t group, std::string* error);
bool WriteRuntimeControlStatusAt(int directory, std::string_view body,
                                 std::uint32_t expected_server_pid, uid_t owner, gid_t group,
                                 std::string* error);

}  // namespace zygveil::location
