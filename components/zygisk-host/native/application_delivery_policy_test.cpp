// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "application_delivery_policy.hpp"

#include <cstdlib>
#include <iostream>

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
  using zygveil::location::ApplicationCallbackDisposition;
  using zygveil::location::ResolveApplicationCallbackDisposition;

  for (const bool fail_closed : {false, true}) {
    for (const bool delivery_active : {false, true}) {
      for (const bool transformation_complete : {false, true}) {
        Expect(
            ResolveApplicationCallbackDisposition(
                false, fail_closed, delivery_active, transformation_complete) ==
                ApplicationCallbackDisposition::kOriginal,
            "inactive hook did not preserve the original callback");
      }
    }
  }
  for (const bool fail_closed : {false, true}) {
    Expect(ResolveApplicationCallbackDisposition(true, fail_closed, true, true) ==
               ApplicationCallbackDisposition::kSynthetic,
           "complete active transformation did not return the synthetic result");
  }
  for (const bool delivery_active : {false, true}) {
    for (const bool transformation_complete : {false, true}) {
      if (delivery_active && transformation_complete) {
        continue;
      }
      Expect(ResolveApplicationCallbackDisposition(
                 true, false, delivery_active, transformation_complete) ==
                 ApplicationCallbackDisposition::kOriginal,
             "POC failure did not preserve the original callback");
      Expect(ResolveApplicationCallbackDisposition(
                 true, true, delivery_active, transformation_complete) ==
                 ApplicationCallbackDisposition::kSuppressed,
             "production failure did not suppress the original callback");
    }
  }

  std::cout << "schema_version=1\nstatus=PASS\ntests=" << assertions
            << "\ncategories=pre_activation,synthetic_success,poc_fail_open,production_fail_closed\n";
  return 0;
}
