// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "status.hpp"

#include <cstdlib>
#include <iostream>
#include <string>

#include "sha256.hpp"

namespace {

int tests = 0;

void Check(bool condition, const char* description) {
  ++tests;
  if (!condition) {
    std::cerr << "FAIL " << description << '\n';
    std::exit(1);
  }
}

std::string Replace(std::string input, std::string_view from, std::string_view to) {
  const std::size_t offset = input.find(from);
  Check(offset != std::string::npos, "status replacement fixture");
  input.replace(offset, from.size(), to);
  return input;
}

void Reject(const std::string& input, const char* description) {
  std::string error;
  Check(!zygveil::server_vpn::ParseRuntimeStatus(input, &error).has_value(), description);
  Check(!error.empty(), "status rejection reason");
}

}  // namespace

int main() {
  using zygveil::server_vpn::Config;
  using zygveil::server_vpn::EncodeRuntimeStatus;
  using zygveil::server_vpn::ParseRuntimeStatus;
  using zygveil::server_vpn::RuntimeStatus;
  using zygveil::server_vpn::TargetSetSha256;

  Check(zygveil::server_vpn::Sha256Hex("") ==
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256 empty vector");
  Check(zygveil::server_vpn::Sha256Hex("abc") ==
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256 abc vector");
  Config config;
  config.target_mode = std::string(zygveil::server_vpn::kTargetMode);
  const std::string target_digest = TargetSetSha256(config);
  Check(target_digest.size() == 64 && target_digest != std::string(64, '0'),
        "target digest present");

  RuntimeStatus active{
      .state = "active",
      .reason = "active",
      .system_server_pid = 123,
      .system_server_start_ticks = 456,
      .boot_id = "12345678-1234-1234-1234-123456789abc",
      .config_generation = 7,
      .hook_count = zygveil::server_vpn::kCatalogHookCount,
      .target_set_sha256 = target_digest,
  };
  std::string error;
  const std::string encoded = EncodeRuntimeStatus(active);
  const auto parsed = ParseRuntimeStatus(encoded, &error);
  Check(parsed.has_value() && error.empty(), "active status round trip");
  Check(parsed->target_set_sha256 == target_digest, "target digest round trip");
  Check(parsed->hook_count == 14 && parsed->config_generation == 7,
        "active generations round trip");

  RuntimeStatus inactive = active;
  inactive.state = "inactive";
  inactive.reason = "foundation_catalog_not_armed";
  inactive.hook_count = 0;
  Check(ParseRuntimeStatus(EncodeRuntimeStatus(inactive), &error).has_value(),
        "inactive status valid");
  RuntimeStatus arming = inactive;
  arming.state = "arming";
  arming.reason = "pre_server_initializing";
  Check(ParseRuntimeStatus(EncodeRuntimeStatus(arming), &error).has_value(),
        "arming status valid");

  Reject(Replace(encoded, "state=active", "state=other"), "unknown state rejected");
  Reject(Replace(encoded, "reason=active", "reason=has space"), "unsafe reason rejected");
  Reject(Replace(encoded, "hook_count=14", "hook_count=13"), "partial active rejected");
  Reject(Replace(encoded, "hook_count=14", "hook_count=0"), "zero active rejected");
  Reject(Replace(encoded, "config_generation=7", "config_generation=0"),
         "zero active generation rejected");
  Reject(Replace(encoded, target_digest, std::string(64, '0')),
         "empty active target digest rejected");
  Reject(Replace(encoded, "engine_owner=shared", "engine_owner=separate"),
         "second owner rejected");
  Reject(Replace(encoded, "feature=server_vpn", "feature=location"),
         "feature mismatch rejected");
  Reject(Replace(encoded, "catalog_hook_count=14", "catalog_hook_count=15"),
         "catalog count rejected");
  Reject(Replace(encoded, "artifact_generation=1", "artifact_generation=2"),
         "artifact generation rejected");
  Reject(Replace(encoded, "owner_generation=1", "owner_generation=2"),
         "owner generation rejected");
  Reject(Replace(encoded, "12345678-1234-1234-1234-123456789abc", "unavailable"),
         "invalid boot identity rejected");
  Reject(encoded + "unknown=value\n", "unknown status key rejected");
  Reject(encoded.substr(0, encoded.size() - 1), "unterminated status rejected");

  std::cout << "schema_version=1\nstatus=PASS\ntests=" << tests
            << "\ncategories=status,privacy,identity,sha256,negative\n";
  return 0;
}
