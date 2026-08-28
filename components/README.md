<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Supported Components

`components/` contains every supported product source tree:

- `zygisk-host/` owns the single Magisk/Zygisk process lifecycle and hook-engine instance.
- `location/controller/` owns the standalone location-control APK.
- `server-vpn/runtime/` owns server-side VPN policy, bridge, configuration, and native runtime code.
- `probe/` owns one extensible primary/canary public-API oracle for every product feature.

Root Gradle, Make, container, device, quality, and release automation may consume supported product
component code only from this tree; orchestration remains under `tools/automation/` and `mk/`, with
build configuration at the repository root. Feature-specific probe groups share the same APK pair,
lifecycle framework, and source-generation identity; a feature must not introduce a second probe
application project.
