// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "process_liveness.hpp"

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

int assertions = 0;

void Expect(bool condition, const char* message) {
  ++assertions;
  if (!condition) {
    std::cerr << message << '\n';
    std::exit(1);
  }
}

}  // namespace

int main() {
  using zygveil::location::OpenProcessLivenessHandle;
  using zygveil::location::ProcessLivenessResult;
  using zygveil::location::ReadProcessStartTicksForLiveness;
  using zygveil::location::WaitProcessLiveness;

  std::uint64_t own_start_ticks = 0;
  Expect(ReadProcessStartTicksForLiveness(getpid(), &own_start_ticks),
         "current process start identity unavailable");
  std::string error;
  const int own_handle = OpenProcessLivenessHandle(getpid(), own_start_ticks, &error);
  Expect(own_handle >= 0, "current process pidfd unavailable");
  Expect(WaitProcessLiveness(own_handle, 0) == ProcessLivenessResult::kAlive,
         "current process pidfd is not live");
  close(own_handle);
  Expect(OpenProcessLivenessHandle(getpid(), own_start_ticks + 1, &error) < 0,
         "pidfd accepted a mismatched start identity");
  Expect(WaitProcessLiveness(-1, 0) == ProcessLivenessResult::kError,
         "invalid pidfd was not rejected");

  const pid_t child = fork();
  Expect(child >= 0, "fork failed");
  if (child == 0) {
    for (;;) {
      pause();
    }
  }
  std::uint64_t child_start_ticks = 0;
  for (int attempt = 0; attempt < 100 && child_start_ticks == 0; ++attempt) {
    ReadProcessStartTicksForLiveness(child, &child_start_ticks);
    usleep(1000);
  }
  Expect(child_start_ticks != 0, "child process start identity unavailable");
  const int child_handle = OpenProcessLivenessHandle(child, child_start_ticks, &error);
  Expect(child_handle >= 0, "child process pidfd unavailable");
  Expect(WaitProcessLiveness(child_handle, 0) == ProcessLivenessResult::kAlive,
         "child process pidfd is not live");
  Expect(kill(child, SIGKILL) == 0, "child termination failed");
  int child_status = 0;
  Expect(waitpid(child, &child_status, 0) == child, "child wait failed");
  Expect(WaitProcessLiveness(child_handle, 1000) == ProcessLivenessResult::kExited,
         "child exit was not signaled by pidfd");
  close(child_handle);

  std::cout << "schema_version=1\nstatus=PASS\ntests=" << assertions
            << "\ncategories=pidfd_identity,pidfd_liveness,pidfd_exit\n";
  return 0;
}
