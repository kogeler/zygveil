// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

namespace zygveil::location {

enum class ApplicationCallbackDisposition {
  kOriginal,
  kSynthetic,
  kSuppressed,
};

constexpr ApplicationCallbackDisposition ResolveApplicationCallbackDisposition(
    bool hook_active, bool fail_closed, bool delivery_active,
    bool transformation_complete) noexcept {
  if (!hook_active) {
    return ApplicationCallbackDisposition::kOriginal;
  }
  if (delivery_active && transformation_complete) {
    return ApplicationCallbackDisposition::kSynthetic;
  }
  return fail_closed ? ApplicationCallbackDisposition::kSuppressed
                     : ApplicationCallbackDisposition::kOriginal;
}

}  // namespace zygveil::location
