// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "config.hpp"

namespace zygveil::server_vpn {

inline constexpr std::uint32_t kArtifactGeneration = 1;
inline constexpr std::uint32_t kOwnerGeneration = 1;
inline constexpr std::uint32_t kCatalogHookCount = 14;
inline constexpr std::size_t kMaximumStatusBytes = 4096;

struct RuntimeStatus {
  std::string state;
  std::string reason;
  std::uint32_t system_server_pid = 0;
  std::uint64_t system_server_start_ticks = 0;
  std::string boot_id;
  std::uint32_t artifact_generation = kArtifactGeneration;
  std::uint64_t config_generation = 0;
  std::uint32_t catalog_version = 1;
  std::uint32_t catalog_hook_count = kCatalogHookCount;
  std::uint32_t hook_count = 0;
  std::string target_set_sha256 = std::string(64, '0');
  std::uint32_t owner_generation = kOwnerGeneration;
};

bool ValidStatusReason(std::string_view reason);
bool ValidateRuntimeStatus(const RuntimeStatus& status, std::string* error);
std::optional<RuntimeStatus> ParseRuntimeStatus(std::string_view input, std::string* error);
std::string EncodeRuntimeStatus(const RuntimeStatus& status);
std::string TargetSetSha256(const Config& config);

}  // namespace zygveil::server_vpn
