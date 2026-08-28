// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace zygveil::server_vpn {

inline constexpr std::string_view kBackendId = "zygveil_server_vpn";
inline constexpr std::string_view kTargetMode = "eligible_user0_apps";
inline constexpr std::uint64_t kMaximumConfigGeneration = (1ULL << 62) - 1;
inline constexpr std::size_t kMaximumConfigBytes = 8192;

struct Config {
  std::uint32_t schema_version = 0;
  std::uint32_t catalog_version = 0;
  std::uint64_t config_generation = 0;
  std::string backend_id;
  std::string target_mode;
};

std::optional<Config> ParseConfig(std::string_view input, std::string* error);
std::string EncodeConfig(const Config& config);
bool ValidateConfig(const Config& config, std::string* error);

}  // namespace zygveil::server_vpn
