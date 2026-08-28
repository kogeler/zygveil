// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "process_liveness.hpp"

#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <string_view>

#include "locationctl_core.hpp"

namespace zygveil::location {
namespace {

constexpr std::string_view kPidfdTarget = "anon_inode:[pidfd]";

bool SetError(std::string* error, std::string_view value) {
  if (error != nullptr) {
    *error = value;
  }
  return false;
}

bool ValidatePidfdDescriptor(int descriptor) {
  const int descriptor_flags = descriptor >= 0 ? fcntl(descriptor, F_GETFD) : -1;
  if (descriptor_flags < 0 || (descriptor_flags & FD_CLOEXEC) == 0) {
    return false;
  }
  const std::string path = "/proc/self/fd/" + std::to_string(descriptor);
  std::array<char, 64> target{};
  ssize_t count;
  do {
    count = readlink(path.c_str(), target.data(), target.size() - 1);
  } while (count < 0 && errno == EINTR);
  return count == static_cast<ssize_t>(kPidfdTarget.size()) &&
      std::string_view(target.data(), static_cast<std::size_t>(count)) == kPidfdTarget;
}

}  // namespace

bool ReadProcessStartTicksForLiveness(pid_t pid, std::uint64_t* output) {
  if (pid <= 0 || output == nullptr) {
    return false;
  }
  const std::string path = "/proc/" + std::to_string(pid) + "/stat";
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    return false;
  }
  std::array<char, 1024> body{};
  ssize_t count;
  do {
    count = read(descriptor, body.data(), body.size() - 1);
  } while (count < 0 && errno == EINTR);
  close(descriptor);
  if (count <= 0 || count == static_cast<ssize_t>(body.size() - 1)) {
    return false;
  }
  const auto parsed = ParseProcessStartTicks(
      std::string_view(body.data(), static_cast<std::size_t>(count)));
  if (!parsed.has_value()) {
    return false;
  }
  *output = *parsed;
  return true;
}

ProcessLivenessResult WaitProcessLiveness(int descriptor, int timeout_ms) {
  if (descriptor < 0 || timeout_ms < 0) {
    return ProcessLivenessResult::kError;
  }
  pollfd request{.fd = descriptor, .events = POLLIN, .revents = 0};
  int result;
  do {
    result = poll(&request, 1, timeout_ms);
  } while (result < 0 && errno == EINTR);
  if (result == 0) {
    return ProcessLivenessResult::kAlive;
  }
  if (result < 0 || (request.revents & POLLNVAL) != 0) {
    return ProcessLivenessResult::kError;
  }
  if ((request.revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
    return ProcessLivenessResult::kExited;
  }
  return ProcessLivenessResult::kError;
}

int OpenProcessLivenessHandle(pid_t pid, std::uint64_t expected_start_ticks,
                              std::string* error) {
  std::uint64_t before = 0;
  if (expected_start_ticks == 0 ||
      !ReadProcessStartTicksForLiveness(pid, &before) || before != expected_start_ticks) {
    SetError(error, "pidfd_process_identity_invalid");
    return -1;
  }
#if defined(__NR_pidfd_open)
  int descriptor;
  do {
    descriptor = static_cast<int>(syscall(__NR_pidfd_open, pid, 0));
  } while (descriptor < 0 && errno == EINTR);
  std::uint64_t after = 0;
  if (descriptor < 0 || !ValidatePidfdDescriptor(descriptor) ||
      !ReadProcessStartTicksForLiveness(pid, &after) || after != expected_start_ticks ||
      WaitProcessLiveness(descriptor, 0) != ProcessLivenessResult::kAlive) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    SetError(error, "pidfd_process_handle_invalid");
    return -1;
  }
  return descriptor;
#else
  SetError(error, "pidfd_unavailable");
  return -1;
#endif
}

}  // namespace zygveil::location
