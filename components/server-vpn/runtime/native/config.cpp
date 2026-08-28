// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "config.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace zygveil::server_vpn {
namespace {

constexpr std::array<std::string_view, 5> kFixedKeys = {
    "schema_version",
    "backend_id",
    "catalog_version",
    "config_generation",
    "target_mode",
};

bool SetError(std::string* error, std::string_view value) {
  if (error != nullptr) {
    error->assign(value);
  }
  return false;
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

bool ParseProperties(std::string_view input, std::map<std::string, std::string>* values,
                     std::string* error) {
  if (input.empty() || input.size() > kMaximumConfigBytes || input.back() != '\n') {
    return SetError(error, "config_size_or_termination_invalid");
  }
  for (unsigned char character : input) {
    if (character != '\n' && (character < 0x20 || character > 0x7e)) {
      return SetError(error, "config_ascii_invalid");
    }
  }
  std::size_t offset = 0;
  bool properties_started = false;
  while (offset < input.size()) {
    const std::size_t end = input.find('\n', offset);
    const std::string_view line = input.substr(offset, end - offset);
    offset = end + 1;
    if (line.empty()) {
      return SetError(error, "config_empty_line");
    }
    if (line.front() == '#') {
      if (properties_started) {
        return SetError(error, "config_line_invalid");
      }
      continue;
    }
    properties_started = true;
    const std::size_t separator = line.find('=');
    if (separator == std::string_view::npos || separator == 0 ||
        separator + 1 == line.size() || line.find('=', separator + 1) != std::string_view::npos) {
      return SetError(error, "config_line_invalid");
    }
    if (!values->emplace(std::string(line.substr(0, separator)),
                         std::string(line.substr(separator + 1))).second) {
      return SetError(error, "config_duplicate_key");
    }
  }
  return true;
}

}  // namespace

bool ValidateConfig(const Config& config, std::string* error) {
  if (config.schema_version != 2) {
    return SetError(error, "config_schema_invalid");
  }
  if (config.backend_id != kBackendId) {
    return SetError(error, "config_backend_invalid");
  }
  if (config.catalog_version != 1) {
    return SetError(error, "config_catalog_invalid");
  }
  if (config.config_generation == 0 || config.config_generation > kMaximumConfigGeneration) {
    return SetError(error, "config_generation_invalid");
  }
  if (config.target_mode != kTargetMode) {
    return SetError(error, "config_target_mode_invalid");
  }
  if (error != nullptr) {
    error->clear();
  }
  return true;
}

std::optional<Config> ParseConfig(std::string_view input, std::string* error) {
  std::map<std::string, std::string> values;
  if (!ParseProperties(input, &values, error)) {
    return std::nullopt;
  }
  std::set<std::string> expected;
  for (std::string_view key : kFixedKeys) {
    expected.emplace(key);
  }
  if (values.size() != expected.size() ||
      !std::all_of(values.begin(), values.end(), [&](const auto& entry) {
        return expected.contains(entry.first);
      })) {
    SetError(error, "config_keys_invalid");
    return std::nullopt;
  }

  std::uint64_t schema = 0;
  std::uint64_t catalog = 0;
  std::uint64_t generation = 0;
  if (!ParseUnsigned(values["schema_version"], std::numeric_limits<std::uint32_t>::max(),
                     &schema) ||
      !ParseUnsigned(values["catalog_version"], std::numeric_limits<std::uint32_t>::max(),
                     &catalog) ||
      !ParseUnsigned(values["config_generation"], kMaximumConfigGeneration, &generation)) {
    SetError(error, "config_number_invalid");
    return std::nullopt;
  }
  Config config{
      .schema_version = static_cast<std::uint32_t>(schema),
      .catalog_version = static_cast<std::uint32_t>(catalog),
      .config_generation = generation,
      .backend_id = values["backend_id"],
      .target_mode = values["target_mode"],
  };
  return ValidateConfig(config, error) ? std::optional<Config>{std::move(config)} : std::nullopt;
}

std::string EncodeConfig(const Config& config) {
  return "schema_version=" + std::to_string(config.schema_version) +
      "\nbackend_id=" + config.backend_id +
      "\ncatalog_version=" + std::to_string(config.catalog_version) +
      "\nconfig_generation=" + std::to_string(config.config_generation) +
      "\ntarget_mode=" + config.target_mode + "\n";
}

}  // namespace zygveil::server_vpn
