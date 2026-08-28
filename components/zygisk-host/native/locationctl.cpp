// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "locationctl_core.hpp"

#include <array>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace zygveil::location {
namespace {

constexpr char kModuleDirectory[] = "/data/adb/modules/zygveil";
constexpr char kHelperPath[] = "/data/adb/modules/zygveil/locationctl";
constexpr char kLockName[] = ".locationctl.lock";
constexpr int kAckWaitAttempts = 80;
constexpr long kAckWaitNanoseconds = 25 * 1000 * 1000;

ssize_t ReadNoInterrupt(int descriptor, void* buffer, std::size_t size) {
  ssize_t count;
  do {
    count = read(descriptor, buffer, size);
  } while (count < 0 && errno == EINTR);
  return count;
}

ssize_t ReadLinkNoInterrupt(const char* path, char* buffer, std::size_t size) {
  ssize_t count;
  do {
    count = readlink(path, buffer, size);
  } while (count < 0 && errno == EINTR);
  return count;
}

bool SleepFully(long nanoseconds) {
  struct timespec remaining {
    .tv_sec = 0, .tv_nsec = nanoseconds
  };
  while (nanosleep(&remaining, &remaining) != 0) {
    if (errno != EINTR) {
      return false;
    }
  }
  return true;
}

bool WriteFully(int descriptor, std::string_view text) {
  const char* input = text.data();
  std::size_t remaining = text.size();
  while (remaining > 0) {
    const ssize_t count = write(descriptor, input, remaining);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return false;
    }
    input += count;
    remaining -= static_cast<std::size_t>(count);
  }
  return true;
}

int PrintFailure(std::string reason, int exit_code) {
  HelperStatus status;
  status.control_state = "rejected";
  status.reason = std::move(reason);
  WriteFully(STDOUT_FILENO, RenderHelperStatus(status, false));
  return exit_code;
}

bool ValidateExecutable() {
  std::array<char, 256> path{};
  const ssize_t count =
      ReadLinkNoInterrupt("/proc/self/exe", path.data(), path.size() - 1);
  if (count != static_cast<ssize_t>(std::strlen(kHelperPath)) ||
      std::memcmp(path.data(), kHelperPath, static_cast<std::size_t>(count)) != 0) {
    return false;
  }
  const int executable = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
  const int installed = open(kHelperPath, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat executable_status {};
  struct stat installed_status {};
  const bool valid =
      executable >= 0 && installed >= 0 && fstat(executable, &executable_status) == 0 &&
      fstat(installed, &installed_status) == 0 && S_ISREG(executable_status.st_mode) &&
      executable_status.st_uid == 0 && executable_status.st_gid == 0 &&
      executable_status.st_nlink == 1 && (executable_status.st_mode & 07777) == 0755 &&
      executable_status.st_dev == installed_status.st_dev &&
      executable_status.st_ino == installed_status.st_ino;
  if (executable >= 0) {
    close(executable);
  }
  if (installed >= 0) {
    close(installed);
  }
  return valid;
}

int OpenModuleDirectory() {
  const int directory = open(kModuleDirectory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  struct stat status {};
  if (directory < 0 || fstat(directory, &status) != 0 || !S_ISDIR(status.st_mode) ||
      status.st_uid != 0 || status.st_gid != 0 || status.st_nlink == 0 ||
      (status.st_mode & 07777) != 0755) {
    if (directory >= 0) {
      close(directory);
    }
    return -1;
  }
  return directory;
}

int LockControl(int directory) {
  int descriptor = openat(directory, kLockName,
                          O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (descriptor < 0) {
    return -1;
  }
  struct stat status {};
  const bool valid = fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode) &&
                     status.st_uid == 0 && status.st_gid == 0 && status.st_nlink == 1 &&
                     (status.st_mode & 07777) == 0600;
  if (!valid || !AcquireControlLock(descriptor, ControlLockMode::kWait)) {
    close(descriptor);
    return -1;
  }
  return descriptor;
}

std::string ReadBootId() {
  const int descriptor = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return {};
  }
  std::array<char, kControlBootIdBytes> buffer{};
  const ssize_t count = ReadNoInterrupt(descriptor, buffer.data(), buffer.size() - 1);
  close(descriptor);
  if (count < 36) {
    return {};
  }
  return std::string(buffer.data(), 36);
}

bool IsProcessIdentity(std::uint32_t pid, std::uint64_t expected_start_ticks) {
  if (pid == 0 || kill(static_cast<pid_t>(pid), 0) != 0) {
    return false;
  }
  const std::string stat_path = "/proc/" + std::to_string(pid) + "/stat";
  const int stat_descriptor = open(stat_path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (stat_descriptor < 0) {
    return false;
  }
  std::array<char, 1024> stat_body{};
  const ssize_t stat_count =
      ReadNoInterrupt(stat_descriptor, stat_body.data(), stat_body.size() - 1);
  close(stat_descriptor);
  const auto start_ticks = stat_count > 0 && stat_count < static_cast<ssize_t>(stat_body.size() - 1)
      ? ParseProcessStartTicks(
            std::string_view(stat_body.data(), static_cast<std::size_t>(stat_count)))
      : std::nullopt;
  if (!start_ticks.has_value() || *start_ticks != expected_start_ticks) {
    return false;
  }
  return true;
}

bool IsSystemServer(std::uint32_t pid, std::uint64_t expected_start_ticks) {
  if (!IsProcessIdentity(pid, expected_start_ticks)) {
    return false;
  }
  const std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    return false;
  }
  std::array<char, 64> command{};
  const ssize_t count = ReadNoInterrupt(descriptor, command.data(), command.size());
  close(descriptor);
  constexpr std::string_view expected = "system_server";
  return count > static_cast<ssize_t>(expected.size()) &&
         std::memcmp(command.data(), expected.data(), expected.size()) == 0 &&
         command[expected.size()] == '\0';
}

bool ValidateControlMemfdTarget(int descriptor) {
  const std::string path = "/proc/self/fd/" + std::to_string(descriptor);
  std::array<char, 128> target{};
  const ssize_t count =
      ReadLinkNoInterrupt(path.c_str(), target.data(), target.size() - 1);
  return count == static_cast<ssize_t>(kControlMemfdProcTarget.size()) &&
      std::string_view(target.data(), static_cast<std::size_t>(count)) ==
      kControlMemfdProcTarget;
}

ControlPage* OpenControlPage(int directory, RuntimeControlStatus* runtime_status,
                             std::string* error) {
  const auto status = ReadRuntimeControlStatusAt(directory, 0, 0, error);
  const std::string current_boot_id = ReadBootId();
  if (!status.has_value() || status->state != "ready" || current_boot_id.empty() ||
      status->boot_id != current_boot_id ||
      !IsSystemServer(status->system_server_pid, status->system_server_start_ticks) ||
      !IsProcessIdentity(status->control_owner_pid,
                         status->control_owner_start_ticks)) {
    *error = "runtime_inactive";
    return nullptr;
  }
  const std::string path = "/proc/" + std::to_string(status->control_owner_pid) + "/fd/" +
      std::to_string(status->control_fd);
  const int descriptor = open(path.c_str(), O_RDWR | O_CLOEXEC);
  if (descriptor < 0 || !ValidateControlMemfdDescriptor(descriptor, 0, 0, error) ||
      !ValidateControlMemfdTarget(descriptor)) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    if (error->empty()) {
      *error = "control_memfd_identity_invalid";
    }
    return nullptr;
  }
  void* mapping =
      mmap(nullptr, sizeof(ControlPage), PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0);
  close(descriptor);
  if (mapping == MAP_FAILED) {
    *error = "control_memfd_map_failed";
    return nullptr;
  }
  *runtime_status = *status;
  return static_cast<ControlPage*>(mapping);
}

std::optional<std::string> ReadStdin(std::string* error) {
  std::string result;
  std::array<char, 256> buffer{};
  while (true) {
    const ssize_t count = read(STDIN_FILENO, buffer.data(), buffer.size());
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0) {
      *error = "stdin_read_failed";
      return std::nullopt;
    }
    if (count == 0) {
      break;
    }
    if (result.size() + static_cast<std::size_t>(count) > kMaximumLiveInputBytes) {
      *error = "stdin_oversized";
      return std::nullopt;
    }
    result.append(buffer.data(), static_cast<std::size_t>(count));
  }
  return result;
}

bool ValidatePageForConfig(const ControlPage& page, const Config& config,
                           const RuntimeControlStatus& runtime_status, std::string* error) {
  const std::string boot_id = ReadBootId();
  return !boot_id.empty() && boot_id == runtime_status.boot_id &&
         IsSystemServer(runtime_status.system_server_pid,
                        runtime_status.system_server_start_ticks) &&
         IsProcessIdentity(runtime_status.control_owner_pid,
                           runtime_status.control_owner_start_ticks) &&
         ValidateControlIdentity(page, runtime_status.system_server_pid, boot_id,
                                 runtime_status.config_generation,
                                 BootFieldsDigest(EncodeConfig(config)), error);
}

HelperStatus DeriveAttestedStatus(const Config& config, const ControlPage* page,
                                  const RuntimeControlStatus& runtime_status,
                                  std::string_view fallback_reason = {}) {
  HelperStatus status = fallback_reason.empty()
      ? DeriveHelperStatus(config, page)
      : DeriveHelperStatus(config, page, fallback_reason);
  status.system_server_start_ticks = runtime_status.system_server_start_ticks;
  return status;
}

int ShowStatus(int directory, bool full) {
  std::string error;
  const auto config = ReadConfigAt(directory, 0, 0, &error);
  if (!config.has_value()) {
    return PrintFailure(error.empty() ? "config_unavailable" : error, 3);
  }
  RuntimeControlStatus runtime_status;
  ControlPage* page = OpenControlPage(directory, &runtime_status, &error);
  if (page == nullptr) {
    HelperStatus status = DeriveHelperStatus(*config, nullptr, error);
    WriteFully(STDOUT_FILENO, RenderHelperStatus(status, full));
    return 0;
  }
  if (!ValidatePageForConfig(*page, *config, runtime_status, &error)) {
    HelperStatus status =
        DeriveHelperStatus(*config, nullptr, "control_page_identity_invalid");
    munmap(page, sizeof(ControlPage));
    WriteFully(STDOUT_FILENO, RenderHelperStatus(status, full));
    return 0;
  }
  const HelperStatus status = DeriveAttestedStatus(*config, page, runtime_status);
  munmap(page, sizeof(ControlPage));
  WriteFully(STDOUT_FILENO, RenderHelperStatus(status, full));
  return 0;
}

int Apply(int directory) {
  std::string error;
  const auto persisted = ReadConfigAt(directory, 0, 0, &error);
  if (!persisted.has_value()) {
    return PrintFailure(error.empty() ? "config_unavailable" : error, 3);
  }
  RuntimeControlStatus runtime_status;
  ControlPage* page = OpenControlPage(directory, &runtime_status, &error);
  const ControlRuntimeState state =
      page == nullptr ? ControlRuntimeState::kInactive : LoadControlRuntimeState(*page);
  if (page == nullptr || !ValidatePageForConfig(*page, *persisted, runtime_status, &error) ||
      (state != ControlRuntimeState::kWaiting && state != ControlRuntimeState::kActive)) {
    if (page != nullptr) {
      munmap(page, sizeof(ControlPage));
    }
    return PrintFailure("runtime_inactive", 3);
  }
  const auto input_text = ReadStdin(&error);
  const auto input = input_text.has_value() ? ParseLiveInput(*input_text, &error) : std::nullopt;
  if (!input.has_value()) {
    munmap(page, sizeof(ControlPage));
    return PrintFailure(error.empty() ? "invalid_input" : error, 2);
  }
  const auto candidate =
      BuildLiveCandidate(*persisted, LoadPublishedGeneration(*page), *input, &error);
  if (!candidate.has_value()) {
    munmap(page, sizeof(ControlPage));
    return PrintFailure(error.empty() ? "invalid_input" : error, 2);
  }
  const ConfigPersistenceResult persistence =
      PersistConfigAt(directory, *candidate, 0, 0, &error);
  if (persistence != ConfigPersistenceResult::kDurable) {
    if (persistence == ConfigPersistenceResult::kCommitted) {
      PublishControlAck(page, candidate->config_generation, ControlAckState::kRejected,
                        ControlReason::kPersistenceFailed);
      const HelperStatus failed = DeriveAttestedStatus(*candidate, page, runtime_status);
      munmap(page, sizeof(ControlPage));
      WriteFully(STDOUT_FILENO, RenderHelperStatus(failed, false));
      return 4;
    }
    munmap(page, sizeof(ControlPage));
    return PrintFailure("persistence_failed", 4);
  }
  if (!PublishControlConfig(page, *persisted, *candidate, &error)) {
    const HelperStatus status = DeriveAttestedStatus(
        *candidate, page, runtime_status, "publish_unavailable");
    munmap(page, sizeof(ControlPage));
    WriteFully(STDOUT_FILENO, RenderHelperStatus(status, false));
    return 0;
  }
  msync(page, sizeof(ControlPage), MS_ASYNC);

  ControlAck acknowledgement;
  for (int attempt = 0; attempt < kAckWaitAttempts; ++attempt) {
    acknowledgement = ReadControlAck(*page);
    if (acknowledgement.generation == candidate->config_generation &&
        (acknowledgement.state == ControlAckState::kApplied ||
         acknowledgement.state == ControlAckState::kRejected)) {
      break;
    }
    if (!SleepFully(kAckWaitNanoseconds)) {
      break;
    }
  }
  if (acknowledgement.generation == candidate->config_generation &&
      acknowledgement.state == ControlAckState::kRejected) {
    const ConfigPersistenceResult rollback =
        PersistConfigAt(directory, *persisted, 0, 0, &error);
    if (rollback != ConfigPersistenceResult::kDurable) {
      if (rollback == ConfigPersistenceResult::kCommitted) {
        PublishControlAck(page, candidate->config_generation, ControlAckState::kRejected,
                          ControlReason::kPersistenceFailed);
        const HelperStatus failed =
            DeriveAttestedStatus(*persisted, page, runtime_status);
        munmap(page, sizeof(ControlPage));
        WriteFully(STDOUT_FILENO, RenderHelperStatus(failed, false));
        return 4;
      }
      HelperStatus failed = DeriveAttestedStatus(*candidate, page, runtime_status);
      failed.reason = "rollback_failed";
      munmap(page, sizeof(ControlPage));
      WriteFully(STDOUT_FILENO, RenderHelperStatus(failed, false));
      return 4;
    }
  }
  const HelperStatus status = DeriveAttestedStatus(
      acknowledgement.state == ControlAckState::kRejected ? *persisted : *candidate, page,
      runtime_status);
  munmap(page, sizeof(ControlPage));
  WriteFully(STDOUT_FILENO, RenderHelperStatus(status, false));
  return acknowledgement.state == ControlAckState::kRejected ? 2 : 0;
}

}  // namespace
}  // namespace zygveil::location

int main(int argc, char** argv) {
  using namespace zygveil::location;
  if (geteuid() != 0 || argc != 2 || !ValidateExecutable()) {
    return PrintFailure("unauthorized_invocation", 5);
  }
  clearenv();
  const std::string_view command(argv[1]);
  if (command == "protocol-self-test") {
    const char vector[] = "123456789";
    const bool valid = sizeof(ControlPage) == kControlPageBytes &&
                       Crc32c(vector, sizeof(vector) - 1) == 0xe3069283U;
    WriteFully(STDOUT_FILENO,
               valid ? "schema_version=1\nstatus=PASS\ncoordinates=absent\n"
                     : "schema_version=1\nstatus=FAIL\ncoordinates=absent\n");
    return valid ? 0 : 6;
  }
  if (command != "apply" && command != "status" && command != "status-ui") {
    return PrintFailure("unknown_command", 5);
  }
  const int directory = OpenModuleDirectory();
  if (directory < 0) {
    return PrintFailure("module_unavailable", 3);
  }
  const int lock = LockControl(directory);
  if (lock < 0) {
    close(directory);
    return PrintFailure("control_lock_failed", 4);
  }
  const int result = command == "apply" ? Apply(directory) : ShowStatus(directory, command == "status-ui");
  close(lock);
  close(directory);
  return result;
}
