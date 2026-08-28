// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "config.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

namespace {

int tests = 0;

void Check(bool condition, const char* description) {
  ++tests;
  if (!condition) {
    std::cerr << "FAIL " << description << '\n';
    std::exit(1);
  }
}

std::string Read(const char* path) {
  std::ifstream stream(path);
  Check(stream.good(), "example readable");
  return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

std::string Replace(std::string input, std::string_view from, std::string_view to) {
  const std::size_t offset = input.find(from);
  Check(offset != std::string::npos, "replacement fixture present");
  input.replace(offset, from.size(), to);
  return input;
}

void Reject(const std::string& input, const char* description) {
  std::string error;
  Check(!zygveil::server_vpn::ParseConfig(input, &error).has_value(), description);
  Check(!error.empty(), "rejection has bounded reason");
}

}  // namespace

int main(int argc, char** argv) {
  using zygveil::server_vpn::EncodeConfig;
  using zygveil::server_vpn::ParseConfig;

  Check(argc == 2, "fixture argument");
  const std::string example = Read(argv[1]);
  const std::size_t config_start = example.find("schema_version=");
  Check(config_start != std::string::npos, "example config body present");
  const std::string valid = example.substr(config_start);
  std::string error;
  const auto parsed = ParseConfig(example, &error);
  Check(parsed.has_value(), "example parses");
  Check(error.empty(), "valid parse clears error");
  Check(parsed->schema_version == 2, "schema exact");
  Check(parsed->catalog_version == 1, "catalog exact");
  Check(parsed->config_generation == 2, "generation exact");
  Check(parsed->backend_id == zygveil::server_vpn::kBackendId, "backend exact");
  Check(parsed->target_mode == zygveil::server_vpn::kTargetMode, "target mode exact");
  Check(EncodeConfig(*parsed) == valid, "comments excluded from canonical encoding");
  Check(valid.find("\nenabled=") == std::string::npos, "feature enabled key absent");
  Check(valid.find("\nmode=") == std::string::npos, "runtime mode key absent");

  Reject(valid + "unknown=1\n", "unknown key rejected");
  Reject(valid + "# trailing metadata\n", "non-leading metadata rejected");
  Reject(Replace(example, "backend_id=", "# embedded metadata\nbackend_id="),
         "embedded metadata rejected");
  Reject(valid + "schema_version=2\n", "duplicate key rejected");
  Reject(Replace(valid, "schema_version=2", "schema_version=1"), "schema rejected");
  Reject(Replace(valid, "backend_id=zygveil_server_vpn", "backend_id=other"), "backend rejected");
  Reject(Replace(valid, "catalog_version=1", "catalog_version=2"), "catalog rejected");
  Reject(Replace(valid, "config_generation=2", "config_generation=0"), "zero generation rejected");
  Reject(Replace(valid, "config_generation=2", "config_generation=+2"), "signed generation rejected");
  Reject(Replace(valid, "config_generation=2", "config_generation=4611686018427387904"),
         "generation overflow rejected");
  Reject(Replace(valid, "target_mode=eligible_user0_apps", "target_mode=explicit"),
         "non-production target mode rejected");
  Reject(Replace(valid, "target_mode=eligible_user0_apps", "target_mode=ELIGIBLE_USER0_APPS"),
         "noncanonical target mode rejected");
  Reject(Replace(valid, "target_mode=eligible_user0_apps", "target_mode=eligible_user0_apps "),
         "target mode whitespace rejected");
  Reject(valid.substr(0, valid.size() - 1), "missing final newline rejected");
  Reject(Replace(valid, "backend_id=", "backend_id= "), "space rejected");
  Reject(Replace(valid, "backend_id=", "backend_id=\t"), "tab rejected");
  Reject(Replace(valid, "backend_id=", "backend_id=\r"), "carriage return rejected");
  Reject(Replace(valid, "backend_id=", "backend_id=="), "extra separator rejected");
  Reject(Replace(valid, "catalog_version=1\n", ""), "missing key rejected");
  Reject(Replace(valid, "target_mode=eligible_user0_apps\n", ""),
         "missing target mode rejected");

  std::cout << "schema_version=1\nstatus=PASS\ntests=" << tests
            << "\ncategories=parse,validation,policy,negative\n";
  return 0;
}
