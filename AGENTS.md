<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Agent Guide

This file is the single documentation entry point for agents working in this repository. Read the
smallest applicable contract before changing code. Do not infer current behavior from generated
reports, old terminal output, or conversation history.

## Contract Map

| Work area | Read first | Owner of truth |
|---|---|---|
| Module topology, lifecycle, policy boundaries | [`ARCHITECTURE.md`](docs/contracts/ARCHITECTURE.md) | Component responsibilities and invariants |
| Android API hooks or policy semantics | [`PUBLIC_API.md`](docs/contracts/PUBLIC_API.md) | Exact public surface and transformations |
| Probe app, detector IDs, JSONL | [`PROBE.md`](docs/contracts/PROBE.md) | Independent oracle and result schema |
| Make, Podman, build, quality, artifacts | [`AUTOMATION.md`](docs/contracts/AUTOMATION.md) | Supported operational interface |
| Runtime acceptance evidence | [`VALIDATION.md`](docs/contracts/VALIDATION.md) | Accepted artifact/session results and compatibility non-claim |
| Scope, exclusions, logging, residual risk | [`SECURITY.md`](docs/contracts/SECURITY.md) | Bounded claim and safety constraints |
| Development procedure | [`DEVELOPMENT.md`](docs/maintenance/DEVELOPMENT.md) | Routine change workflow |
| Phone installation and state transitions | [`DEVICE_OPERATIONS.md`](docs/maintenance/DEVICE_OPERATIONS.md) | Stateful device runbook |

[`docs/contracts/README.md`](docs/contracts/README.md) defines contract syntax and ownership.

## Non-Negotiable Rules

1. Use Make for every routine operation. Do not invoke `gradlew`, Android SDK tools, Podman build/run,
   ADB mutations, formatters, linters, or test scripts directly when a Make target exists.
2. Keep Make composition in `mk/*.mk`. Put complex orchestration in typed Python under
   `tools/automation/` and expose it through Make.
3. The host must remain free of project Android/JDK/Gradle installations and build execution.
   Ordinary build and quality containers are offline and receive the checkout through validated tar
   streams, never bind mounts.
4. Never toggle external state implicitly. Network tests must validate their declared VPN/module
   state and stop on mismatch. ZygVeil feature targets may mutate only the exact state named by the
   invoked Make target.
5. `components/probe/` is the only probe application project. Its
   `dev.zygveil.probe.primary`/`dev.zygveil.probe.canary` pair must host location, server-VPN, and
   future public-API oracle groups. Do not create feature-specific probe APK projects or couple
   supported automation to an application-process hooking framework.
6. Do not add hidden/System API access, reflection fallbacks, raw Binder/JNI detection, root flows,
   system-server hooks, callback wrappers, or data-plane changes without redefining the contracts
   and threat boundary first.
7. Preserve user changes. Use `apply_patch` for manual edits and use `rg`/`rg --files` for search.
8. A conscious contract deviation, discovered documentation error, or implementation mismatch must
   be corrected in the affected contract in the same change. Stop dependent work until code,
   contract, tests, and Make interface agree. Do not create progress ledgers or historical journals.
9. Keep documentation current-state only. Design rationale belongs in contracts; procedures belong
   in maintenance docs; exact results belong only in `VALIDATION.md`. Link instead of duplicating.
10. Standalone textual documentation is outside code-attestation identity. After a text-only
    documentation change run only `make docs-check`; never rebuild, rerun preflight, reinstall, or
    repeat device evidence solely because documentation changed.

## Repository Layout

```text
components/zygisk-host/          one Magisk/Zygisk host for all supported features
components/location/controller/ standalone location controller APK
components/server-vpn/runtime/  server policy, bridge, native configuration/status
components/probe/               one extensible primary/canary public-API oracle
deprecated/lsposed-vpn/         unsupported and untested source-only archive
mk/                  composable Make target libraries
tools/automation/    Make-wrapped host orchestration and validation
containers/builder/  pinned builder image and entrypoint
docs/contracts/      normative current behavior
docs/maintenance/    operational procedures
dist/                frozen release ZIP, APKs, and source digest
.artifacts/           ignored caches, builds, and reports
.state/               ignored stable signing and resumable local state
```

## Working Protocol

1. Inspect `git status`, the affected contract assertions, implementation, and tests.
2. State which assertion IDs the change affects. If no assertion exists for a durable behavior,
   add one to the owning contract before or with implementation.
3. Make the smallest change consistent with existing ownership boundaries.
4. Use the ordered verification phases in `AUT-018`. During investigation and focused POC
   iteration, run only the smallest affected Make build/test and never promote its artifacts or
   reports. Location uses `location-poc-*`; server-VPN uses `server-vpn-poc-*`. POC flows skip broad
   quality, hashes, reproducibility, full runtime inspection, stability matrices, and evidence
   attestation. Once focused behavior and review pass, finish every contract/runbook/code edit and
   run the independent `make docs-check`. Then run `make final-preflight` for technical inputs only
   and stop on any failure. Only its current attestable-input-bound PASS
   receipt allows final build/freeze and device evidence. Final attest targets aggregate existing
   evidence only and must never run host gates or rebuild. Follow the contract's
   narrow-fix/preflight, source-change, device-retry, and evidence-promotion failure routes exactly.
5. Device work follows `DEVICE_OPERATIONS.md`. Activity-driven targets first perform the bounded
   automatic wake/non-credential-keyguard readiness operation. Only when they report
   `manual_unlock_required` should the agent stop, ask once for the owner to unlock the display, wait
   for confirmation, and rerun that unchanged target instead of guessing or repeating earlier phases.
6. Update `VALIDATION.md` only after immutable, current-artifact evidence passes. Then run only
   `make docs-check`; never repeat preflight or device evidence merely to record accepted results.
   The same rule applies to every text-only documentation correction. Never promote a partial,
   mismatched-hash, or superseded run.

Generated reports under `.artifacts/` are evidence outputs, not documentation. The contracts and
implementation must be understandable without them.

Everything under `deprecated/` is outside the supported graph. Automation may validate the
boundary path and root `deprecated/README.md`; the repository-wide privacy scanner may additionally
perform a content-blind forbidden-pattern scan. Do not otherwise inspect the archived
implementation, format, build, test, install, execute, or use it as evidence.
