// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "locationctl_core.hpp"

#include <array>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

int tests = 0;

void Check(bool condition, const char* name) {
  ++tests;
  if (!condition) {
    std::cerr << "FAIL " << name << '\n';
    std::exit(1);
  }
}

bool WriteFully(int descriptor, const std::string& text) {
  const char* data = text.data();
  std::size_t remaining = text.size();
  while (remaining > 0) {
    const ssize_t count = write(descriptor, data, remaining);
    if (count <= 0) {
      return false;
    }
    data += count;
    remaining -= static_cast<std::size_t>(count);
  }
  return true;
}

zygveil::location::Config ConfigFixture() {
  zygveil::location::Config config;
  config.enabled = true;
  config.center_latitude_deg = 10.25;
  config.center_longitude_deg = -20.5;
  config.altitude_ellipsoid_m = 125.25;
  config.altitude_msl_m = 90.125;
  config.random_seed = 1234;
  config.config_generation = 7;
  return config;
}

}  // namespace

int main() {
  using namespace zygveil::location;
  std::string error;
  constexpr std::string_view valid =
      "schema_version=1\n"
      "center_latitude_deg=-33.12345678\n"
      "center_longitude_deg=179.99999999\n"
      "altitude_ellipsoid_m=123.456\n"
      "altitude_msl_m=-12.125\n";
  const auto input = ParseLiveInput(valid, &error);
  Check(input.has_value(), "valid input parses");
  Check(input->center_latitude_deg == -33.12345678, "latitude parses exactly");
  Check(input->altitude_msl_m == -12.125, "altitude parses exactly");
  Check(!ParseLiveInput(std::string(valid) + "unknown=1\n", &error).has_value(),
        "unknown key rejected");
  Check(!ParseLiveInput("schema_version=1\n", &error).has_value(), "missing keys rejected");
  Check(!ParseLiveInput(
             "schema_version=1\ncenter_latitude_deg=1.000000001\n"
             "center_longitude_deg=2\naltitude_ellipsoid_m=3\naltitude_msl_m=4\n",
             &error)
             .has_value(),
        "coordinate precision enforced");
  Check(!ParseLiveInput(
             "schema_version=1\ncenter_latitude_deg=1\ncenter_longitude_deg=2\n"
             "altitude_ellipsoid_m=3.0001\naltitude_msl_m=4\n",
             &error)
             .has_value(),
        "altitude precision enforced");
  Check(!ParseLiveInput(
             "schema_version=1\ncenter_latitude_deg=1,5\ncenter_longitude_deg=2\n"
             "altitude_ellipsoid_m=3\naltitude_msl_m=4\n",
             &error)
             .has_value(),
        "locale comma rejected by helper protocol");
  Check(!ParseLiveInput(
             "schema_version=1\ncenter_latitude_deg=nan\ncenter_longitude_deg=2\n"
             "altitude_ellipsoid_m=3\naltitude_msl_m=4\n",
             &error)
             .has_value(),
        "non-finite input rejected");
  Check(!ParseLiveInput(
             "schema_version=1\ncenter_latitude_deg=91\ncenter_longitude_deg=2\n"
             "altitude_ellipsoid_m=3\naltitude_msl_m=4\n",
             &error)
             .has_value(),
        "latitude range enforced");
  Check(!ParseLiveInput(
             "schema_version=1\ncenter_latitude_deg=1\ncenter_longitude_deg=181\n"
             "altitude_ellipsoid_m=3\naltitude_msl_m=4\n",
             &error)
             .has_value(),
        "longitude range enforced");
  Check(!ParseLiveInput(std::string(kMaximumLiveInputBytes + 1, '1'), &error).has_value(),
        "oversized input rejected");

  constexpr std::string_view runtime_status =
      "schema_version=4\n"
      "state=ready\n"
      "reason=active:blocked\n"
      "raw_gnss_mode=blocked\n"
      "hook_count=5\n"
      "system_server_pid=1234\n"
      "system_server_start_ticks=424242\n"
      "config_generation=7\n"
      "boot_id=11111111-2222-3333-4444-555555555555\n"
      "control_fd=42\n"
      "control_owner_pid=5678\n"
      "control_owner_start_ticks=434343\n";
  const auto parsed_runtime = ParseRuntimeControlStatus(runtime_status, &error);
  Check(parsed_runtime.has_value() && parsed_runtime->system_server_pid == 1234 &&
            parsed_runtime->system_server_start_ticks == 424242 &&
            parsed_runtime->control_fd == 42 &&
            parsed_runtime->control_owner_pid == 5678 &&
            parsed_runtime->control_owner_start_ticks == 434343 &&
            parsed_runtime->config_generation == 7,
        "ready runtime status parses");
  Check(!ParseRuntimeControlStatus(
             std::string(runtime_status).replace(15, 1, "2"), &error)
             .has_value(),
        "old runtime status schema rejected");
  Check(!ParseRuntimeControlStatus(
             std::string(runtime_status).replace(runtime_status.find("control_fd=42"),
                                                 std::strlen("control_fd=42"), "control_fd=0"),
             &error)
             .has_value(),
        "ready runtime status requires control descriptor");
  Check(!ParseRuntimeControlStatus(
             std::string(runtime_status).replace(
                 runtime_status.find("system_server_start_ticks=424242"),
                 std::strlen("system_server_start_ticks=424242"),
                 "system_server_start_ticks=0"),
             &error)
             .has_value(),
        "ready runtime status requires process start identity");
  Check(!ParseRuntimeControlStatus(
             std::string(runtime_status).replace(
                 runtime_status.find("control_owner_start_ticks=434343"),
                 std::strlen("control_owner_start_ticks=434343"),
                 "control_owner_start_ticks=0"),
             &error)
             .has_value(),
        "ready runtime status requires control owner identity");
  Check(!ParseRuntimeControlStatus(std::string(runtime_status) + "unknown=1\n", &error)
             .has_value(),
        "runtime status unknown key rejected");
  Check(!ParseRuntimeControlStatus(std::string(runtime_status) + "control_fd=42\n", &error)
             .has_value(),
        "runtime status duplicate key rejected");
  Check(!ParseRuntimeControlStatus(
             std::string(runtime_status).replace(
                 runtime_status.find("config_generation=7"),
                 std::strlen("config_generation=7"),
                 "config_generation=4611686018427387904"),
             &error)
             .has_value(),
        "runtime status generation range enforced");
  const auto process_start = ParseProcessStartTicks(
      "123 (system server) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 23\n");
  Check(process_start.has_value() && *process_start == 424242,
        "proc stat process start time parses after a spaced command");
  Check(!ParseProcessStartTicks("123 (system_server) S 1 2 3\n").has_value(),
        "truncated proc stat process start time rejected");
  Check(!ParseRuntimeControlStatus(
             std::string(runtime_status).replace(
                 runtime_status.find("reason=active:blocked"),
                 std::strlen("reason=active:blocked"), "reason=center_latitude_deg=1"),
             &error)
             .has_value(),
        "runtime status coordinate-bearing reason rejected");
  Check(!ParseRuntimeControlStatus(
             std::string(runtime_status).replace(
                 runtime_status.find("reason=active:blocked"),
                 std::strlen("reason=active:blocked"), "reason=$GLGGA"),
             &error)
             .has_value(),
        "runtime status NMEA-bearing reason rejected");
  const std::string inactive_runtime =
      "schema_version=4\nstate=inactive\nreason=disabled_by_config\n"
      "raw_gnss_mode=blocked\nhook_count=0\nsystem_server_pid=1234\n"
      "system_server_start_ticks=424242\n"
      "config_generation=0\nboot_id=11111111-2222-3333-4444-555555555555\n"
      "control_fd=0\ncontrol_owner_pid=0\ncontrol_owner_start_ticks=0\n";
  Check(ParseRuntimeControlStatus(inactive_runtime, &error).has_value(),
        "inactive runtime status permits absent control descriptor");

  Config persisted = ConfigFixture();
  const auto candidate = BuildLiveCandidate(persisted, 9, *input, &error);
  Check(candidate.has_value() && candidate->config_generation == 10,
        "generation advances from published maximum");
  Check(candidate->enabled, "first live candidate activates location");
  Check(candidate->raw_gnss_mode == persisted.raw_gnss_mode &&
            candidate->random_seed == persisted.random_seed,
        "boot fields preserved");
  Config maximum = persisted;
  maximum.config_generation = kMaximumControlGeneration;
  Check(!BuildLiveCandidate(maximum, kMaximumControlGeneration, *input, &error).has_value(),
        "generation wrap rejected");

  Config waiting = persisted;
  waiting.enabled = false;
  ControlPage waiting_page{};
  constexpr std::string_view boot_id = "11111111-2222-3333-4444-555555555555";
  Check(InitializeControlPage(&waiting_page, waiting, 1234, boot_id, &error),
        "waiting helper page initialized");
  StoreControlRuntimeState(&waiting_page, ControlRuntimeState::kWaiting);
  HelperStatus awaiting_first = DeriveHelperStatus(waiting, &waiting_page);
  Check(awaiting_first.control_state == "awaiting_first_coordinates" &&
            !awaiting_first.config.has_value(),
        "clean waiting helper status hides placeholder coordinates");
  const auto first_candidate =
      BuildLiveCandidate(waiting, waiting.config_generation, *input, &error);
  Check(first_candidate.has_value() &&
            PublishControlConfig(&waiting_page, waiting, *first_candidate, &error),
        "first activation candidate published");
  PublishControlAck(&waiting_page, first_candidate->config_generation,
                    ControlAckState::kRejected, ControlReason::kInvalidConfig);
  HelperStatus first_rejected = DeriveHelperStatus(waiting, &waiting_page);
  Check(first_rejected.control_state == "rejected" &&
            first_rejected.reason == "invalid_config",
        "rolled-back first activation remains a coherent rejection");

  ControlPage control_page{};
  Check(InitializeControlPage(&control_page, persisted, 1234, boot_id, &error),
        "helper status page initialized");
  StoreControlRuntimeState(&control_page, ControlRuntimeState::kActive);
  HelperStatus initial_status = DeriveHelperStatus(persisted, &control_page);
  Check(initial_status.control_state == "applied" &&
            initial_status.persisted_generation == persisted.config_generation,
        "initial helper status applied");
  ControlPage uncertain_persistence_page{};
  Check(InitializeControlPage(&uncertain_persistence_page, persisted, 1234, boot_id, &error),
        "uncertain persistence page initialized");
  StoreControlRuntimeState(&uncertain_persistence_page, ControlRuntimeState::kActive);
  PublishControlAck(&uncertain_persistence_page, candidate->config_generation,
                    ControlAckState::kRejected, ControlReason::kPersistenceFailed);
  HelperStatus uncertain_persistence =
      DeriveHelperStatus(*candidate, &uncertain_persistence_page);
  Check(uncertain_persistence.control_state == "recovery_required" &&
            uncertain_persistence.reason == "persistence_uncertain" &&
            uncertain_persistence.persisted_generation >
                uncertain_persistence.published_generation &&
            uncertain_persistence.published_generation ==
                uncertain_persistence.applied_generation,
        "uncertain initial persistence requires recovery");
  HelperStatus reboot_pending = DeriveHelperStatus(*candidate, &control_page);
  Check(reboot_pending.control_state == "saved_pending_reboot" &&
            reboot_pending.reason == "publish_unavailable",
        "persisted unpublished generation waits for reboot");
  Check(PublishControlConfig(&control_page, persisted, *candidate, &error),
        "helper status candidate published");
  HelperStatus upstream_pending = DeriveHelperStatus(*candidate, &control_page);
  Check(upstream_pending.control_state == "saved_pending_upstream",
        "published generation waits for upstream");
  PublishControlAck(&control_page, candidate->config_generation, ControlAckState::kRejected,
                    ControlReason::kChecksumMismatch);
  HelperStatus rejected_status = DeriveHelperStatus(persisted, &control_page);
  Check(rejected_status.control_state == "rejected" &&
            rejected_status.persisted_generation == rejected_status.applied_generation,
        "rolled back runtime rejection remains coherent");
  HelperStatus recovery_status = DeriveHelperStatus(*candidate, &control_page);
  Check(recovery_status.control_state == "recovery_required" &&
            recovery_status.reason == "persisted_runtime_rejection",
        "unrolled runtime rejection requires recovery");
  PublishControlAck(&control_page, candidate->config_generation, ControlAckState::kRejected,
                    ControlReason::kPersistenceFailed);
  HelperStatus uncertain_rollback = DeriveHelperStatus(persisted, &control_page);
  Check(uncertain_rollback.control_state == "recovery_required" &&
            uncertain_rollback.reason == "rollback_persistence_uncertain" &&
            uncertain_rollback.persisted_generation == uncertain_rollback.applied_generation,
        "uncertain durable rollback requires recovery");

  const std::string rendered = RenderConfig(*candidate);
  const auto round_trip = ParseConfig(rendered, &error);
  Check(round_trip.has_value(), "rendered config parses");
  Check(round_trip->config_generation == candidate->config_generation &&
            round_trip->center_longitude_deg == candidate->center_longitude_deg,
        "rendered config round trip exact");

  HelperStatus status;
  status.module_state = "active";
  status.runtime_state = "active";
  status.control_state = "applied";
  status.persisted_generation = candidate->config_generation;
  status.published_generation = candidate->config_generation;
  status.applied_generation = candidate->config_generation;
  status.system_server_pid = 1234;
  status.system_server_start_ticks = 424242;
  status.boot_id = std::string(boot_id);
  status.config = *candidate;
  const std::string redacted = RenderHelperStatus(status, false);
  Check(redacted.find("center_latitude_deg") == std::string::npos &&
            redacted.find("center_longitude_deg") == std::string::npos &&
            redacted.find("179.99999999") == std::string::npos &&
            redacted.find("system_server_start_ticks=424242") != std::string::npos,
        "redacted status excludes coordinates and binds process start time");
  status.reason = "center_latitude_deg";
  const std::string sanitized = RenderHelperStatus(status, false);
  Check(sanitized.find("center_latitude_deg") == std::string::npos &&
            sanitized.find("reason=internal_error") != std::string::npos,
        "helper status sanitizes coordinate-bearing reasons");
  status.reason = "none";
  const std::string full = RenderHelperStatus(status, true);
  Check(full.find("center_latitude_deg=-33.12345678\n") != std::string::npos &&
            full.find("center_longitude_deg=179.99999999\n") != std::string::npos &&
            full.find("altitude_ellipsoid_m=123.456\n") != std::string::npos &&
            full.find("altitude_msl_m=-12.125\n") != std::string::npos,
        "UI status uses controller-compatible decimal precision");
  status.config->center_latitude_deg = 0.00000001;
  status.config->center_longitude_deg = -0.00000001;
  status.config->altitude_ellipsoid_m = 0.001;
  status.config->altitude_msl_m = -0.001;
  const std::string small = RenderHelperStatus(status, true);
  Check(small.find("center_latitude_deg=0.00000001\n") != std::string::npos &&
            small.find("center_longitude_deg=-0.00000001\n") != std::string::npos &&
            small.find("altitude_ellipsoid_m=0.001\n") != std::string::npos &&
            small.find("altitude_msl_m=-0.001\n") != std::string::npos,
        "UI status avoids exponent notation at precision boundaries");

  std::array<char, 64> directory_template{};
  std::strcpy(directory_template.data(), "/tmp/locationctl-test-XXXXXX");
  char* directory_path = mkdtemp(directory_template.data());
  Check(directory_path != nullptr, "temporary directory created");
  const int directory = open(directory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  Check(directory >= 0, "temporary directory opened");
  const int lock = openat(directory, ".locationctl.lock",
                          O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  Check(lock >= 0 && AcquireControlLock(lock, ControlLockMode::kTry),
        "control lock acquired");
  const pid_t contender = fork();
  Check(contender >= 0, "control lock contender forked");
  if (contender == 0) {
    close(lock);
    const int candidate = openat(directory, ".locationctl.lock", O_RDWR | O_CLOEXEC);
    const bool acquired = candidate >= 0 && AcquireControlLock(candidate, ControlLockMode::kTry);
    if (candidate >= 0) {
      close(candidate);
    }
    _exit(acquired ? 1 : 0);
  }
  int contender_status = 0;
  Check(waitpid(contender, &contender_status, 0) == contender &&
            WIFEXITED(contender_status) && WEXITSTATUS(contender_status) == 0,
        "control lock excludes another process");
  close(lock);
  const int reacquired = openat(directory, ".locationctl.lock", O_RDWR | O_CLOEXEC);
  Check(reacquired >= 0 && AcquireControlLock(reacquired, ControlLockMode::kWait),
        "control lock releases on close");
  close(reacquired);
  const int initial = openat(directory, "config.properties",
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  Check(initial >= 0 && WriteFully(initial, RenderConfig(persisted)) && fsync(initial) == 0,
        "initial secure config written");
  close(initial);
  const auto loaded = ReadConfigAt(directory, geteuid(), getegid(), &error);
  Check(loaded.has_value() && loaded->config_generation == persisted.config_generation,
        "secure config reads");
  Check(renameat(directory, "config.properties", directory, "config.valid") == 0,
        "valid config staged for malformed-content test");
  const int malformed = openat(directory, "config.properties",
                               O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  Check(malformed >= 0 && WriteFully(malformed, "schema_version=1\n") &&
            fsync(malformed) == 0,
        "malformed secure config written");
  close(malformed);
  Check(!ReadConfigAt(directory, geteuid(), getegid(), &error).has_value() &&
            error == "config_invalid",
        "malformed config error is coordinate-free");
  unlinkat(directory, "config.properties", 0);
  Check(renameat(directory, "config.valid", directory, "config.properties") == 0,
        "valid config restored after malformed-content test");
  Check(PersistConfigAt(directory, *candidate, geteuid(), getegid(), &error) ==
            ConfigPersistenceResult::kDurable,
        "atomic config replacement succeeds");
  const auto replaced = ReadConfigAt(directory, geteuid(), getegid(), &error);
  Check(replaced.has_value() && replaced->config_generation == candidate->config_generation,
        "atomic config replacement visible");
  Check(WriteRuntimeControlStatusAt(directory, runtime_status, 1234, geteuid(), getegid(), &error),
        "secure runtime status written atomically");
  Check(!WriteRuntimeControlStatusAt(directory, std::string(runtime_status) +
                                                    "center_latitude_deg=1\n",
                                     1234, geteuid(), getegid(), &error),
        "coordinate-bearing runtime status rejected");
  Check(!WriteRuntimeControlStatusAt(directory, runtime_status, 4321, geteuid(), getegid(), &error),
        "runtime status process mismatch rejected");
  const auto loaded_runtime =
      ReadRuntimeControlStatusAt(directory, geteuid(), getegid(), &error);
  Check(loaded_runtime.has_value() && loaded_runtime->control_fd == 42,
        "secure runtime status reads");
  Check(renameat(directory, "runtime-status.properties", directory, "runtime-status.saved") == 0,
        "runtime status staged for symlink test");
  Check(symlinkat("runtime-status.saved", directory, "runtime-status.properties") == 0,
        "runtime status symlink fixture created");
  Check(!ReadRuntimeControlStatusAt(directory, geteuid(), getegid(), &error).has_value(),
        "runtime status symlink rejected");
  unlinkat(directory, "runtime-status.properties", 0);
  renameat(directory, "runtime-status.saved", directory, "runtime-status.properties");

  const std::string stale_runtime_name = ".runtime-status.tmp";
  Check(symlinkat("runtime-status.properties", directory, stale_runtime_name.c_str()) == 0,
        "runtime status stale symlink fixture created");
  Check(!WriteRuntimeControlStatusAt(directory, runtime_status, 1234, geteuid(), getegid(), &error),
        "runtime status stale symlink rejected");
  unlinkat(directory, stale_runtime_name.c_str(), 0);
  const int stale_runtime = openat(directory, stale_runtime_name.c_str(),
                                   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
  Check(stale_runtime >= 0 && fchmod(stale_runtime, 0644) == 0,
        "interrupted runtime temporary created");
  close(stale_runtime);
  Check(WriteRuntimeControlStatusAt(directory, runtime_status, 1234, geteuid(), getegid(), &error),
        "owned interrupted runtime temporary recovered");

  const std::string stale_name = ".config.properties.tmp";
  const int stale = openat(directory, stale_name.c_str(),
                           O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  Check(stale >= 0, "interrupted temporary created");
  close(stale);
  Config later = *candidate;
  later.config_generation++;
  Check(PersistConfigAt(directory, later, geteuid(), getegid(), &error) ==
            ConfigPersistenceResult::kDurable,
        "owned interrupted temporary recovered");

  Check(renameat(directory, "config.properties", directory, "config.saved") == 0,
        "config staged for symlink test");
  Check(symlinkat("config.saved", directory, "config.properties") == 0,
        "config symlink fixture created");
  Check(!ReadConfigAt(directory, geteuid(), getegid(), &error).has_value(),
        "config symlink rejected");
  Check(PersistConfigAt(directory, later, geteuid(), getegid(), &error) ==
            ConfigPersistenceResult::kNotCommitted,
        "invalid persistent identity remains uncommitted");
  unlinkat(directory, "config.properties", 0);
  unlinkat(directory, "runtime-status.properties", 0);
  renameat(directory, "config.saved", directory, "config.properties");
  unlinkat(directory, "config.properties", 0);
  unlinkat(directory, ".locationctl.lock", 0);
  close(directory);
  Check(rmdir(directory_path) == 0, "temporary directory removed");

  std::cout << "schema_version=1\nstatus=PASS\ntests=" << tests
            << "\ncategories=input,precision,range,generation,render,status_privacy,"
               "runtime_status,status_recovery,locking,persistence,interruption,symlink\n";
  return 0;
}
