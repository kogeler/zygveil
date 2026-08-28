<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# ZygVeil

ZygVeil is one Magisk/Zygisk module with a single LSPlant/ShadowHook owner and two
feature-isolated transactions: stationary location simulation and system-server VPN-observation
virtualization. Location and server-VPN have separate configuration, status, hook catalogs, failure
states, and acceptance evidence; neither feature calls or configures the other. The VPN feature has
no controller UI and attempts its complete transaction automatically whenever the Magisk module is
enabled and its immutable packaged policy is valid.

The location feature transforms application-visible Location/GNSS-status/NMEA output; production
`blocked` mode suppresses Raw GNSS
measurement/navigation delivery instead of synthesizing orbital data. The separately installed
ZygVeil Location APK requests no Android permissions and invokes only the module's fixed root helper
after owner authorization. It can publish a new stationary center without rebooting.

One primary/canary probe pair under `components/probe/` supplies all location, server-VPN, and
future public-API oracles. The retired application-process VPN implementation is retained only under
`deprecated/lsposed-vpn/`; it is unsupported, untested, and absent from all root build, device,
quality, release, and acceptance flows. ZygVeil does not claim RF/HAL
emulation, root/Zygisk concealment, data-plane changes, or protection against native, traffic,
server-side, integrity, or hardware-attestation observations.

This repository does not identify, certify, or guarantee compatibility with any phone, Android
build, root framework, or firmware. Hook resolution is best-effort against the runtime selected by
the person installing it. Installing or running this code can fail, boot-loop, lose data, or damage
device integrity; the person doing so accepts all responsibility for the device and its contents.

## Quick Start

All routine operations use Make. Android, Java, Gradle, formatters, linters, and static analyzers run
inside the rootless Podman builder.

```text
make doctor
make bootstrap
make topology-check privacy-check docs-check
make test-location-unit test-location-controller-unit
make test-server-vpn-model test-server-vpn-config
make build-probe
make location-build
make location-controller-build
```

These are ordinary development commands. Formal final work uses the strict sequence
`make final-preflight`, `make server-vpn-final-build`, explicit device evidence, and the evidence-only
`make server-vpn-final-attest`; see the maintenance runbooks before entering that flow.

Device installation and stateful tests are intentionally separate from building:

```text
make probe-install-existing probe-install-canary-existing
make location-status
make server-vpn-poc-status
```

Before any state-labelled device target, read
[`docs/maintenance/DEVICE_OPERATIONS.md`](docs/maintenance/DEVICE_OPERATIONS.md). Automation never
toggles VPN state. The shared module and location controller use their explicit lifecycle targets;
the server-VPN feature has no separate UI or enable switch. Development evidence uses explicit
combined-host enable/disable/reboot/status/probe/recovery targets; these are not production setup.
`location-build` produces that combined ZIP; it is not a
second location-only module.

## Documentation

- [`AGENTS.md`](AGENTS.md) is the entry point for automated contributors.
- [`docs/contracts/README.md`](docs/contracts/README.md) indexes the normative behavior.
- [`docs/maintenance/DEVELOPMENT.md`](docs/maintenance/DEVELOPMENT.md) is the development runbook.
- [`docs/maintenance/DEVICE_OPERATIONS.md`](docs/maintenance/DEVICE_OPERATIONS.md) is the device
  runbook.

The current artifact acceptance state and any promoted runtime-session evidence are in
[`docs/contracts/VALIDATION.md`](docs/contracts/VALIDATION.md).
`make check` composes the independent documentation gate with the technical
`make attestation-check`; `make final-preflight` invokes only the latter before freeze. Textual
documentation remains outside runtime-attestation identity: after a documentation-only change, run
only `make docs-check`; no preflight, build, or device evidence is repeated.

## License

Copyright (c) 2026 kogeler. Distributed under the [MIT License](LICENSE).
