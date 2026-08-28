// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <cstdint>
#include <string>
#include <sys/types.h>

namespace zygveil::location {

enum class ProcessLivenessResult {
  kAlive,
  kExited,
  kError,
};

bool ReadProcessStartTicksForLiveness(pid_t pid, std::uint64_t* output);
int OpenProcessLivenessHandle(pid_t pid, std::uint64_t expected_start_ticks, std::string* error);
ProcessLivenessResult WaitProcessLiveness(int descriptor, int timeout_ms);

}  // namespace zygveil::location
