// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <string>
#include <string_view>

namespace zygveil::server_vpn {

std::string Sha256Hex(std::string_view input);

}  // namespace zygveil::server_vpn
