<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Automation Contract

### `AUT-001` - Make-only routine interface
**Contract:** Every routine repository, build, quality, artifact, device, framework, probe, and test
operation MUST have a Make target. Complex behavior MUST be implemented in Python under
`tools/automation/` and wrapped by a library in `mk/*.mk`; executable logic MUST NOT be placed in an
ad-hoc scripts directory or named after temporary workflow stages.
Coordinates and altitudes MUST enter device operations only through a validated mode-0600 ignored
file or bounded stdin, never a Make variable expanded into a process argument.

**Evidence:** Root `Makefile`, `mk/*.mk`, `tools/automation/`, and the target inventory below.

### `AUT-002` - Host cleanliness
**Contract:** Project Android, Java, Gradle, formatter, linter, and static-analysis execution MUST
occur inside the builder. Host orchestration MAY use Bash, Make, Python, Git, rootless Podman, ADB,
tar/hash tools, and ordinary filesystem/text utilities, but MUST NOT use a host project JDK, Gradle,
Android SDK, NDK, CMake, formatter, linter, or analyzer. `make doctor` inventories but MUST NOT
install or upgrade host packages.

**Evidence:** `make doctor`, absence of host build recipes, and container job dispatch.

### `AUT-003` - Confined ordinary container
**Contract:** Ordinary builder jobs MUST use rootless Podman with no network, automatic 2048-ID user
namespace, no new privileges, all capabilities dropped, read-only root, private IPC/PID/UTS/cgroup
namespaces, no hosts file, no systemd, 1024 PID limit, 8 GiB memory with no additional swap, nofile
4096, disabled logging, 1800-second timeout, and ephemeral `/tmp` and `/work`. HOME, Gradle, Android,
locale, timezone, Java, SDK, and PATH MUST use the explicit allowlist in `mk/container.mk`.

**Evidence:** `BUILDER_CONFINE`, `make confinement-test`, and `make test-network-block`.

### `AUT-004` - Network boundary
**Contract:** Network access MAY be enabled only for `make image` image acquisition/build and
`make deps` dependency resolution. Every ordinary build, formatter, linter, analyzer, unit test,
APK inspection, signing operation, and confinement proof MUST use `--network=none` and
`--pull=never`. This includes the controller APK and native helper/control protocol.

**Evidence:** `BUILDER_ONLINE`, `DEPENDENCY_ONLINE`, `BUILDER_CONFINE`, and network-block evidence.

### `AUT-005` - Tar-only workspace transport
**Contract:** The checkout, dependency cache, and signing input MUST enter containers through a
validated tar stream; no checkout, cache, Podman socket, or host toolchain bind mount is allowed.
Outputs MUST be allowlisted, path-validated, extracted atomically, and exported only on successful
jobs. Formatter output MUST match the original source manifest before atomic host writes.
`deprecated/` MUST be excluded from the supported source stream and its manifest.

**Evidence:** `tools/automation/container.py`, `container_job.py`, `SOURCE_*` macros, confinement and
formatter tests.

### `AUT-006` - Reproducible inputs
**Contract:** The builder image and Gradle dependency cache MUST be content addressed. Downloaded
standalone tools and Gradle artifacts MUST use exact versions and integrity metadata. Cache
bootstrap MUST resolve every resolvable configuration online, delete build/up-to-date state, and
repeat the complete resolution offline before export. Because AGP creates its executable AAPT2
configuration only when an Android task graph is selected, the root dependency resolver MUST also
declare and resolve the exact `com.android.tools.build:aapt2:9.2.1-15009934:linux` classifier
without executing a compile task. Source compilation is deliberately excluded from cache bootstrap
so a POC compile error cannot discard newly downloaded immutable dependencies; the consolidated
final quality/build gates MUST prove the cache with clean offline compilation.
The dependency key MUST bind dependency declarations and the explicit dependency-cache format
version, not the complete container job implementation, so artifact-inspection edits cannot force
an unrelated dependency redownload. A resolution-protocol or integrity-policy change MUST bump that
format version.

| Tool | Exact version |
|---|---|
| Gradle | `9.4.1` |
| Android Gradle Plugin | `9.2.1` |
| Android build tools | `37.0.0` |
| Java language level | `21` |
| Android NDK | `29.0.14206865` |
| CMake | `3.31.6` |
| Zygisk API | `5` (`8ce26128f81baaed0b969aaf7f52f886b61af4ab`) |
| Zygisk C++ runtime | static libc++ from pinned NDK `29.0.14206865` |
| LSPlant | `61e10e51eb99dca00dd873f48c28a674dd2b4c4c` |
| DexBuilder | `ac7fb2230954ee311808bad469b0db501f31bfb8` |
| parallel-hashmap | `0cd57d29a959256ed66b2afdd1009928fc625d09` |
| ShadowHook | `2.0.1` (`854c775c2c3676e57a0f383597ebf420b5204161`) |

**Evidence:** `make image-key`, container inspector, dependency manifest,
`gradle/verification-metadata.xml`, and `make deps`.

### `AUT-007` - Quality gate
**Contract:** Formatting MUST use Spotless with google-java-format and ktlint, Ruff format/fixes, and
shfmt. Lint MUST use Android Lint, Ruff, ShellCheck, and Hadolint. Static analysis MUST use
warning-fatal javac and mypy. Current exact tool versions are Spotless `8.9.0`, google-java-format
`1.29.0`, ktlint `1.8.0`, Ruff `0.16.4`, mypy `2.3.1`, ShellCheck `0.11.0`, shfmt `3.13.1`, and
Hadolint `2.14.0`.
Unit/model result fields and assertion counts MUST be deterministic for unchanged source and fixed
fixtures. Concurrent tests MUST reduce scheduler-dependent observations to a fixed set of terminal
assertions, and the location control harness MUST repeat the binary and reject different output.
The complete `deprecated/` tree MUST be excluded from every formatter, linter, compiler, analyzer,
and unit-test input.

The repository-wide `format-check` MAY include textual documentation. The technical
`attestation-format-check` MUST run the same code/Kotlin/Java/Python/shell formatting checks while
excluding every textual-documentation input.

**Evidence:** Builder image assertions, Gradle configuration, `make format-check`,
`make attestation-format-check`, `make lint`, `make static-analysis`, and `make quality`.

### `AUT-008` - Artifact and signing identity
**Contract:** The universal primary/canary probe APKs and one common source hash MUST be independently
inspected and reused across feature-specific oracle groups. The location controller APK MUST be a
separate atomic export signed by the same ignored stable identity and MUST never be embedded in the
ZygVeil Magisk ZIP. The one combined ZygVeil ZIP, controller APK, and universal probe pair/source
MUST form the complete supported artifact family. The ZIP MUST contain both feature-isolated
runtime payloads required by `ARC-030`, but MUST NOT contain any controller/probe APK, private target
configuration, device/build inventory, host-private path, or file from `deprecated/`. Every ZIP/APK
export job, including non-attestable POC exports, MUST inspect archive member names and payloads for
the prohibited identity/path material in `SEC-005` before publishing the artifact. The
ignored stable debug keystore MUST be created inside the confined builder with mode 0600 and
preserved by ordinary cleanup. Its certificate SHA-256 is
`2A:20:98:19:1B:DF:2F:DF:1C:4D:3E:4A:2D:26:86:C8:B3:F5:9F:82:25:47:03:31:A4:44:82:ED:07:3E:0C:0D`.

**Evidence:** `make signing-init`, `signing-info`, supported exporters, artifact privacy inspection,
and final artifact inspection.

### `AUT-009` - Explicit device mutation
**Contract:** Build and state-labelled acceptance targets MUST NOT install/reinstall artifacts or
toggle VPN or module state. Restarting adbd as root or returning it to the shell identity MUST use
the explicit `adb-root` or `adb-unroot` target and MUST verify the resulting UID. Location-feature
commands MUST accept only location-specific state and MUST NOT inspect unrelated package or network
state. A direct `probe-run` is diagnostic and MUST NOT be accepted as feature evidence by itself.
Every ADB-backed target MUST select the sole connected and authorized transport automatically when
exactly one transport exists. If more than one transport is present it MUST stop before device work
and require an explicit transient `ADB_SERIAL`; zero or unauthorized transports MUST also stop.
Automation MUST invoke `adb devices` without extended model/product/transport details and MUST NOT
log, report, persist, hash, or copy the selected serial. A durable reboot intent MUST contain no
transport selector; a resumed command must repeat the same automatic-or-explicit selection rule.

Every target whose next stateful operation is an Activity launch MUST first pass the shared device-UI
readiness gate. That gate MUST parse both power wakefulness and WindowManager keyguard state, then
MAY use only bounded `KEYCODE_WAKEUP` and `wm dismiss-keyguard` operations to make an already
authorized ADB device interactive and dismiss a keyguard that requires no owner credential. It MUST
re-read and prove an awake display with no showing keyguard before creating probe run state,
force-stopping an application, or launching an Activity. It MUST NOT enter, store, infer, or bypass a
PIN, pattern, password, biometric, or other owner secret. If the system state is unavailable or a
credential-protected keyguard remains, it MUST stop with an explicit manual-unlock requirement before
the application/device phase begins. `device-ui-ready` MUST expose the same bounded operation for an
explicit checkpoint; Activity-driven targets MUST invoke it internally rather than rely on a stale
earlier result.

Server-VPN commands MUST accept only server-VPN state, common ZygVeil host identity, and the bounded
location checkpoint required to prove feature-local coexistence. Probe, active/status, and evidence
commands MUST additionally require that one VPN agent remains active. Repeatable post-cleanup install,
explicit combined-host enable/disable, and disable/reboot recovery MUST remain usable without a
running VPN provider because none of those operations claims behavioral evidence. Server-VPN
commands MUST NOT inspect
`deprecated/` state, reconfigure the location feature, or toggle VPN state.
Install, configuration, enable, disable, reboot, update, uninstall, and recovery
MUST remain separate explicit targets; build, probe, isolation, and acceptance targets MUST be
nonmutating with respect to installed artifacts, module/VPN/configuration state, and persistent
product state, and MUST stop when the declared backend or VPN-ON state does not match. Probe and
isolation targets MAY perform only their explicitly contracted transient display wake,
non-credential keyguard dismissal, application force-stop, Activity/service launch, and private
run-file lifecycle.

**Evidence:** Typed device/probe/feature orchestration and state mismatch errors.

### `AUT-010` - Cleanup boundary
**Contract:** `make clean` MUST remove generated build/test state while preserving stable signing.
`make clean-containers` MUST remove only project-labelled containers/images. Stable signing MAY be
deleted only by `make clean-signing CONFIRM=delete-stable-signing-identity`.

**Evidence:** `mk/maintenance.mk`, `tools/automation/maintenance.py`, and project label filters.

### `AUT-011` - Complete target inventory
**Contract:** The following table MUST contain every implemented routine Make target exactly once.
Adding, renaming, or deleting a target requires updating this table and its owning runbook in the
same change.

| Target | Purpose |
|---|---|
| `help` | Print the supported interface and variables |
| `doctor` | Verify host prerequisites and rootless Podman |
| `docs-check` | Validate contracts, links, catalogs, and Make inventory; its result is repository quality, never runtime-attestation identity |
| `privacy-check` | Reject device identity, compatibility inventories, persisted ADB selectors, and host-private paths across tracked and candidate repository files |
| `topology-check` | Validate supported component roots and deprecated-source exclusion |
| `attestation-keys` | Validate the current builder/dependency content keys used by final preflight |
| `attestation-check` | Run the documentation-independent technical set without writing a receipt |
| `final-preflight` | Run every attestable host/code gate and atomically record a documentation-independent final-flow receipt |
| `final-preflight-verify` | Verify the existing preflight receipt against current attestable code/data/build inputs without rerunning gates |
| `device-ui-ready` | Wake the display, dismiss only a non-credential keyguard, and prove Activity-launch readiness |
| `adb-root` | Restart rooted-debugging adbd as root and verify UID 0 |
| `adb-unroot` | Return adbd to the shell identity and verify UID 2000 |
| `vpn-status` | Capture sanitized provider and active VPN-agent state |
| `syntax` | Parse Python, Make graph, and orchestration self-tests |
| `image-key` | Print content-addressed builder/dependency keys |
| `image` | Build/inspect the pinned builder image; online when absent |
| `deps` | Resolve and verify the offline Gradle cache; online when absent |
| `bootstrap` | Prepare prerequisites, image, dependencies, and signing |
| `image-save` | Export the current builder as an OCI archive |
| `image-load` | Load the expected OCI builder archive |
| `test-network-block` | Prove ordinary container networking is disabled |
| `confinement-test` | Prove namespaces, privileges, mounts, transport, and host immutability |
| `signing-init` | Create the ignored stable keystore in-container |
| `signing-info` | Inspect the stable certificate identity |
| `shellcheck` | Run the standalone shell check inside the builder |
| `test-server-vpn-model` | Compile and run hook-free server authorization/projection/catalog models offline |
| `test-server-vpn-config` | Compile and run strict immutable server configuration and runtime-status tests offline |
| `server-vpn-poc-build` | Build and inspect one non-attestable combined-host runtime set and production-enabled ZIP without hashes/reproducibility |
| `server-vpn-poc-install` | Install or update the already-built combined-host POC enabled with its packaged server-VPN policy and preserved location coordinates |
| `server-vpn-poc-reboot` | Reboot explicitly and validate the focused combined-host VPN/location status |
| `server-vpn-poc-status` | Validate current combined-host status, ownership, file boundary, and descriptor isolation without mutation |
| `server-vpn-poc-isolation` | Launch controlled probe roles, reject app-side VPN runtime state, and restore both processes stopped |
| `server-vpn-poc-stock-probe` | Capture one state-paired primary stock phase from the universal POC probe |
| `server-vpn-poc-probe` | Capture one state-paired overlapping active primary/canary phase from the universal POC probe |
| `server-vpn-poc-differential` | Evaluate stock/active/rollback POC phase manifests locally without device mutation |
| `server-vpn-poc-recover` | Explicitly disable the disposable combined host and reboot once without altering packaged policy or location configuration |
| `server-vpn-final-build` | Verify final preflight, then clean-build, inspect, and freeze one combined artifact generation |
| `server-vpn-final-verify` | Read-only verify the current preflight-bound frozen generation without a build or device operation |
| `server-vpn-final-install` | Install or update the already-frozen combined host production-enabled without rebuilding or requiring VPN readiness |
| `server-vpn-final-enable` | Explicitly remove the combined-host Magisk disable marker for development evidence while preserving both feature inputs |
| `server-vpn-final-disable` | Explicitly create the combined-host Magisk disable marker for development evidence while preserving both feature inputs |
| `server-vpn-final-reboot` | Reboot explicitly and validate the requested frozen stock or active state with VPN ON |
| `server-vpn-final-status` | Validate current frozen artifact/runtime/VPN identity without mutation |
| `server-vpn-final-isolation` | Launch both frozen probe roles and reject all application-side server-VPN state |
| `server-vpn-final-stock-suite` | Run all five server-VPN groups in main/secondary primary stock roles for baseline or rollback |
| `server-vpn-final-active-suite` | Run all five groups in main/secondary target/canary roles plus callback stress and data-plane smoke |
| `server-vpn-final-recover` | Explicitly disable the frozen combined host and reboot once for rollback without altering packaged policy or location configuration |
| `server-vpn-final-acceptance` | Validate the immutable baseline/active/rollback suite manifests and all group differentials locally |
| `server-vpn-final-attest` | Verify provenance and aggregate existing server-VPN plus location evidence without host gates |
| `location-build` | Build and inspect the combined Magisk/Zygisk module offline |
| `location-poc-build` | Build only the non-attestable global-application native/helper POC below `.artifacts/poc/` |
| `location-candidate-build` | Build only a non-attestable production-semantics native/helper candidate below `.artifacts/poc/` |
| `location-poc-stage` | Fast atomic replacement of the enabled module native/helper without artifact hash or runtime attestation |
| `location-poc-reboot` | Explicitly reboot and wait only for completed boot before the focused canary |
| `location-poc-smoke` | Inspect only fixed-canary active-hook marker and control mapping without hashes or full attestation |
| `location-poc-run` | Run the fast native/helper build, stage, reboot, and focused canary sequence |
| `location-candidate-run` | Run the fast production-semantics build, stage, reboot, and focused canary sequence |
| `location-final-build` | Verify final preflight, then build and fully inspect the combined location artifact set |
| `location-final-attest` | Verify provenance and aggregate existing final location evidence without host gates |
| `test-location-unit` | Run deterministic stationary/GNSS model tests offline |
| `location-controller-build` | Build and inspect the standalone controller APK offline |
| `test-location-controller-unit` | Run controller parser/protocol/state/privacy tests offline |
| `location-controller-install` | Install and verify the exact standalone controller APK |
| `location-controller-install-existing` | Install and verify the already-built frozen controller APK without rebuilding |
| `location-controller-ensure-existing` | Idempotently ensure the already-built frozen controller APK is installed and exact |
| `location-controller-reinstall` | Replace and verify the exact standalone controller APK |
| `location-controller-reinstall-existing` | Replace with the already-built frozen controller APK without rebuilding |
| `location-controller-open` | Open only the controller launcher activity |
| `location-controller-status` | Verify a fresh redacted helper status through granted root |
| `location-controller-root-request` | Trigger the fixed redacted Magisk root-consent flow |
| `location-live-set` | Stream one private live update to the fixed helper through stdin |
| `location-live-status` | Validate redacted helper/control-page state without mutation |
| `location-poc-live-set` | Fast POC helper update without artifact/config hash comparison |
| `location-poc-live-status` | Read POC helper status without artifact hash comparison |
| `location-poc-live-reuse` | Temporarily apply a private POC point, prove it in one existing canary PID, and restore the original point |
| `location-install` | Install the exact combined ZygVeil module production-enabled, initially waiting when owner coordinates do not yet exist |
| `location-install-existing` | Install the already-built frozen combined-module ZIP without rebuilding |
| `location-update` | Replace a healthy waiting/active combined module while preserving its location configuration and production enablement |
| `location-update-existing` | Stage the already-built frozen combined-module ZIP as a production-enabled update without rebuilding |
| `location-uninstall` | Stage Magisk removal only for the exact fully disabled live combined module |
| `location-set` | Atomically replace private fixed-location configuration while disabled |
| `location-input-check` | Validate all private location fixtures and their relationships before preflight or device work |
| `location-final-input-check` | Validate every formal private location fixture and its cross-file relationships before device mutation |
| `location-final-input-verify` | Re-read all formal private fixtures and verify their frozen-generation receipt without replacing it |
| `location-status` | Validate and report module and runtime state without mutation |
| `location-enable` | Validate location boot configuration and remove the shared module disable marker |
| `location-disable` | Create only the shared Magisk disable marker while preserving location activation and coordinates |
| `location-reboot` | Explicitly reboot and verify completed boot, stable system_server, and state |
| `location-logs` | Capture bounded sanitized current/previous-boot location diagnostics |
| `location-recover` | Disable, reboot, prove system_server stability, and collect diagnostics |
| `test-location-baseline` | Capture the no-module public location/GNSS reference |
| `test-location-disabled` | Validate stock behavior after a disabled-module boot |
| `test-location-passthrough` | Validate active synthetic outputs with diagnostic Raw passthrough |
| `test-location-blocked` | Validate active synthetic outputs and zero Raw GNSS delivery |
| `test-location-live` | Validate one applied live generation in primary/canary main/secondary roles |
| `test-location-live-edge` | Validate a newer edge generation on the unchanged live runtime |
| `test-location-isolation` | Prove exact global application ELF/bridge/read-only-page retention with no app thread, writable page, control descriptor, or selection logic |
| `test-location-stability` | Restore-bounded provider and screen cycles plus probe restart under an active blocked runtime |
| `test-location-failures` | Reject malformed, non-finite, out-of-range, over-precision, oversized, and non-root helper calls without changing the applied generation |
| `test-location-stress` | Apply five bounded generations and run overlapping primary/canary sessions on the unchanged active runtime |
| `test-location-persistence` | After an explicit active reboot, prove the latest persisted generation is the boot and applied generation |
| `test-location-restored` | Validate fresh stock outputs after module disable and reboot |
| `test-location-acceptance` | Validate all current-artifact location phase records and recovery |
| `test-location-final-baseline` | Capture a freeze-verified reusable no-module location reference |
| `test-location-final-disabled` | Capture a freeze-verified disabled location phase |
| `test-location-final-passthrough` | Capture a freeze-verified diagnostic Raw-passthrough phase |
| `test-location-final-blocked` | Capture a freeze-verified blocked Raw-GNSS phase |
| `test-location-final-live` | Capture the first freeze-bound no-reboot live generation |
| `test-location-final-live-edge` | Capture the newer freeze-bound boundary fixture generation |
| `test-location-final-isolation` | Capture freeze-bound application-process isolation evidence |
| `test-location-final-stability` | Capture freeze-bound restore-bounded stability evidence |
| `test-location-final-failures` | Capture freeze-bound invalid-input containment evidence |
| `test-location-final-stress` | Capture freeze-bound repeated/concurrent update evidence |
| `test-location-final-persistence` | Capture freeze-bound post-reboot persistence evidence |
| `test-location-final-restored` | Capture freeze-bound post-disable stock restoration |
| `clean-containers` | Remove only project-labelled Podman resources |
| `format` | Apply container formatters through validated tar export |
| `format-check` | Check formatting offline |
| `attestation-format-check` | Check only code/build/runtime formatting without reading textual documentation |
| `lint` | Run Android, Python, shell, and Containerfile linters |
| `static-analysis` | Run compiler and Python semantic analysis |
| `quality` | Run the complete formatting/lint/static/syntax gate |
| `build-probe` | Build and inspect both independent probe variants |
| `probe-apk` | Build/verify the primary probe APK |
| `probe-canary-apk` | Build/verify the canary probe APK |
| `probe-canary-poc-build` | Build only the non-attestable canary APK offline below `.artifacts/poc/` |
| `probe-canary-poc-install` | Install the existing non-attestable canary POC APK without rebuilding |
| `probe-canary-poc-location` | Run one focused canary location session with POC-only reports |
| `probe-canary-poc-location-reuse` | Run a focused canary POC session in one already-running unchanged PID |
| `probe-canary-poc-location-trigger` | Run one non-spatial oracle-free POC session to trigger an upstream generation |
| `probe-canary-poc-server-vpn` | Run one namespaced server-VPN group in the installed canary POC APK |
| `probe-server-vpn-poc-build` | Build both flavors of the one universal non-attestable POC probe |
| `probe-primary-poc-install` | Install the existing universal primary POC flavor without rebuilding |
| `probe-server-vpn-poc-run` | Run one active server-VPN group in a selected universal POC flavor without rebuilding |
| `probe-server-vpn-poc-concurrent` | Run one low-level overlapping primary/canary server-VPN POC diagnostic |
| `probe-install` | Install/replace the primary probe APK |
| `probe-install-canary` | Install/replace the canary probe APK |
| `probe-install-existing` | Install/replace the already-built frozen primary probe APK |
| `probe-install-canary-existing` | Install/replace the already-built frozen canary probe APK |
| `probe-run` | Run one labelled detector group |
| `probe-location` | Run one labelled public location/GNSS observation session |
| `probe-results` | Recollect and validate one JSONL run |
| `probe-cleanup` | Stop only the selected probe registrations/processes |
| `check` | Run separate documentation and technical repository-quality gates without writing a receipt |
| `clean` | Remove generated state while retaining signing identity |
| `clean-signing` | Delete stable signing only with the exact confirmation token |

**Evidence:** `make docs-check` compares this exact set with `Makefile` and `mk/*.mk`.

### `AUT-012` - Zygisk artifact and dependencies
**Contract:** `make image` MUST acquire Zygisk API v5 (0BSD), LSPlant/DexBuilder
(LGPL-3.0-or-later), parallel-hashmap (Apache-2.0), and ShadowHook 2.0.1 (MIT) only from pinned
commits with checked SHA-256 archives. Ordinary combined-host builds MUST compile those sources offline
for only `arm64-v8a` and statically embed libc++ from pinned NDK 29 with local symbol binding; the
artifact MUST NOT depend on `libc++_shared.so` or `libandroid.so`. `make location-build` MUST
atomically export and inspect one deterministic Magisk ZIP containing the native module,
dependency-free ShadowHook linker helper, bridge DEX, `locationctl`, control-page schema metadata,
target/config metadata, guard scripts, and licenses; it MUST contain no APK, private config, or
second probe. Inspection MUST verify helper ABI, mode, native dependency closure, exported symbols,
fixed command strings, sealed-memfd protocol metadata, exactly one `PT_TLS` segment aligned to at
least 64 bytes for the pinned ARM64 Bionic loader, the global application hook and production
fail-closed lifecycle markers, pidfd identity/failure markers, absence of POC lifecycle markers,
and absence of coordinates or application-selection identities.

**Evidence:** Builder image assertions, source/license manifest, module ZIP inspector, and repeated
artifact hashes.

### `AUT-013` - Explicit location device workflow
**Contract:** Location install/update/uninstall, boot-config write, live-config write, controller
install/reinstall/open/status/root request, enable, disable, reboot, Raw GNSS mode change, recovery,
and log collection MUST each use an explicit Make target with rooted-adbd and runtime-state
preconditions where root device access is required. Build/probe/acceptance targets MUST NOT change
Magisk module state. These targets are development, diagnosis, recovery, and acceptance interfaces;
they MUST NOT define the production user lifecycle. A user who installs the module/controller,
enables the module in Magisk, and reboots MUST receive automatic server-VPN masking and a working
location controller with no ADB, Make, repository input, or additional feature activation. The
first controller Apply MUST be the only location activation action.
Uninstall MUST accept only the exact fully disabled live module and stage Magisk's normal remove
marker. The supported completion is `location-reboot EXPECTED_STATE=absent`; it MUST accept only
`remove_pending` as its same-boot source, use the normal durable reboot intent, and verify that the
module is absent and its native runtime is unmapped after the new boot. A generic/active/disabled reboot MUST NOT silently consume a
remove marker. Install MUST leave a fresh live or `modules_update` staged payload enabled by
default, preserve an existing valid one-way location configuration on update, validate its exact
configuration/runtime-ready marker, and be safely resumable after a completed Magisk staging operation. An explicit
development recovery or disabled-state target MAY create the disable marker named by that target.
The final controller workflow MUST use `location-controller-ensure-existing`. It MUST consume only
the already-built APK, perform a semantic no-op when the installed base APK is already exact,
install when absent, or use controlled replacement when a different build is present, then verify
the exact package/version/signature/hash. It MUST NOT rebuild, clear application data, edit Magisk
policy storage, or require the caller to guess install versus reinstall state.
An interrupted uninstall rerun MAY accept only the same exact live module already in
`remove_pending` and report a semantic no-op; it MUST NOT add another mutation or accept a different
state. An interrupted enable rerun MAY likewise accept only a valid exact module already in
`pending_reboot_enabled`, with valid waiting-or-active config and no disable marker, as a semantic
no-op. Enable/disable MUST preserve that config and report
the requested reboot boundary and validate state after boot. Disable MUST retain a pending-reboot
state while a staged payload or current native mapping exists, even when runtime-status attestation
is unavailable. Active validation MUST combine the schema-4 immutable runtime attestation bound to
current boot ID, `system_server` PID/start-time identity, companion PID/start-time identity and
retained control FD, boot configuration generation, Raw mode, and five-hook count with exact helper,
sealed-memfd, and mapped-page identity plus its persisted/published/applied generations. A descriptor
number or deleted-memfd pathname alone is never sufficient. Validation MUST require exact
kernel-created memfd mode 0777 while treating procfs/SELinux/root-helper attestation, not memfd DAC,
as the access boundary. It MUST also require the fixed module directory to be a root-owned mode-0755
directory and the helper to be a single-link root-owned mode-0755 regular file. A missing,
wrong-hash, wrong-mode, malformed, stale, reused, or identity-mismatched
helper/status/memfd/page MUST produce `active_control_failure`, not an active result. Recovery MUST
create the exact module disable marker
in every present live/staged payload, reboot, verify one stable `system_server` PID/start-time
identity, and collect bounded current/previous boot diagnostics without physical location. It MUST
remain usable when the host artifact or installed helper/native is unavailable; exact-generation
acceptance separately requires its recovery report to match the current host ZIP and installed
helper/native digests.
Bounded diagnostic sanitization MUST be idempotent and remove dollar-prefixed runtime tokens
case-insensitively before the case-insensitive report privacy guard runs. Lowercase or mixed-case
Java/Kotlin runtime tokens MUST neither survive in evidence nor cause a safe report to be rejected.
Boot configuration input MUST come from an ignored mode-0600 file and omit both the product-owned
`enabled` field and the internal `config_generation` field. `location-set` MUST validate the installed complete
configuration before mutation. This is a development-only boot-parameter/recovery interface and
MUST NOT be a prerequisite for the controller or ordinary product use. When every input-owned field already matches, it MUST perform no
write, retain the installed generation, and report an explicit semantic no-op. Otherwise it MUST
preserve the installed one-way activation state, assign exactly the next installed generation,
reject exhaustion before mutation, atomically write the complete device configuration, and verify
the resulting exact values. No caller or reusable
private input may manage this generation manually. Live configuration input MUST reach only the
fixed helper through stdin, retain only generation/config digests in reports, and validate that
module enablement and Raw GNSS mode did not change.
Reboot and recovery reports MUST record SHA-256 of the validated kernel boot ID, never the raw ID;
state-labelled acceptance MUST match that digest as well as the stable `system_server` PID/start-time
identity before reusing boot evidence.
Because the two features share one Magisk/Zygisk host, a state-labelled location phase MUST accept
boot evidence from any supported reboot-bearing ZygVeil command that reports the location state and
matches the current boot-ID digest plus `system_server` PID/start-time identity. In particular, the
freeze-bound disabled location phase after `server-vpn-final-reboot ... inactive` MUST consume that
command's `location_state=disabled` evidence and MUST NOT require a redundant `location-reboot`.
`location-reboot` and the reboot inside `location-recover` MUST use a mode-0600 durable host intent
containing only the operation/expected-state label, originating boot-ID digest,
and originating process identity. The intent MUST be written before reboot dispatch and removed only after
the complete post-boot state/stability check passes. Rerunning the same interrupted command MUST
wait for an offline device, detect a changed boot ID, and finish validation without dispatching a
second reboot; the unchanged originating boot MAY dispatch the still-pending reboot. A malformed,
mismatched, or superseded intent MUST stop before another mutation. Intent persistence MUST use a
no-follow, stable regular-file read plus file and containing-directory durability. Reboot-bearing
operations are host-single-flight: the presence of a different pending intent MUST stop the new
operation. After dispatch, automation MUST wait for a boot-ID digest different from the recorded
source digest before it may accept Android boot completion; observing `sys.boot_completed=1` on the
source boot is not a completed reboot.
The restore-bounded location stability target MUST pass UI readiness and complete both Activity-driven
probe sessions, including the force-stop/restart boundary, before it intentionally performs the
provider and screen off/on cycles. It MUST launch no Activity after that screen cycle, because a
credential keyguard may then require the next command to stop at the `AUT-009` owner boundary.

**Evidence:** `mk/location.mk`, typed automation, state-transition tests, and device reports.

### `AUT-014` - Controller artifact and inspection
**Contract:** `location-controller-build` MUST compile, sign, inspect, and atomically export
`dist/zygveil-location-controller-debug.apk` in the ordinary offline container. Inspection MUST verify
the exact package/version/signature, one exported `singleTop` activity and no other component, its
exact launcher and root-request action/category filters, disabled backup with fixed extraction rules,
empty requested-permission set, no native library, bounded DEX ownership, and absence of unrelated
module/framework, probe, network, analytics, and Android location code. Controller and Magisk ZIP
outputs MUST remain independently buildable and installable. The Java-only controller module MUST
disable AGP built-in Kotlin so its APK contains no automatically added Kotlin standard library.
Every defined DEX class MUST belong to the controller namespace except the exact pinned-D8 support
set for lambda metadata, `java.lang.Record`, `MethodHandles.Lookup`, and `VarHandle` desugaring.

`location-controller-install` and `location-controller-reinstall` MUST verify exported and installed
APK hashes, package, version, and certificate. `location-controller-open` MAY launch only its fixed
activity. `location-controller-root-request` MAY trigger only the fixed redacted helper status flow
and MUST stop for the owner's normal Magisk consent action. No target may edit Magisk policy storage.
Controller device evidence MUST reject unknown or generation-inconsistent helper state envelopes,
even when the app-private status file is otherwise syntactically valid. It MUST read that file only
through the fixed package's `run-as` identity after verifying a non-symlink, single-link,
mode-0600 regular file owned by that app identity.

**Evidence:** Offline controller build report, manifest/DEX/signature inspection, explicit Make
targets, installed-package checks, and root-grant workflow.

### `AUT-015` - Live-control automation and evidence privacy
**Contract:** `location-live-set` MUST read schema-1 private values from an ignored mode-0600 host
file, stream them to the fixed installed helper, and persist no values in argv, environment,
terminal output, reports, or retained device staging. `location-live-status` MUST use only redacted
helper output. Both targets MUST bind exact module/helper/page/boot/PID/start-time identity and
report only configuration digest, boot/published/applied generation, state, bounded reason, and
elapsed wait.
`EXPECTED_CONTROL_STATE` MAY require `accepted`, `applied`, either exact pending state,
`recovery_required`, `rejected`, `unavailable`, or `any`; the default live-set expectation MUST
accept only a successful applied or pending transition, while status defaults to observation
without changing state. Private stdin delivery through `adb shell` MUST POSIX-quote the complete
remote argv and retain a host self-test covering shell metacharacters, quotes, whitespace, empty
arguments, and newlines.

Live acceptance MUST distinguish `saved_pending_upstream`, `saved_pending_reboot`, `applied`,
`recovery_required`, and `rejected`; a bounded wait ending before an upstream hook entry is not
failure. Exact-point acceptance starting from `saved_pending_upstream` MUST first run one redacted,
oracle-free trigger session and require the generation to become `applied`; only then may it stage
the private oracle and treat observations as exact-point evidence. The trigger's possibly stale
cached last location is not exact-point evidence. Rejection MUST prove that the last
persisted/applied generation and persistent config digest were retained. `recovery_required` MUST
be non-success and prove that the last applied runtime generation remains active while either a
rejected generation remains persistent or an old generation rollback or new-generation persistence
has unproven directory durability.
Applied/upstream-pending states MUST use reason `none`; unavailable and rejected states MUST carry
a reason; every generation relation MUST match the exact control state. Probe
expected-center input MUST use the mode-private unlink-after-open path in `PRB-012`. Privacy
self-tests MUST recursively reject coordinate keys, privacy-distinctive canonical fractional input
values, their stripped decimal form, and their max-digits binary64 round-trip form, unredacted NMEA
fields, and private temporary paths from all generated evidence. Integer values without private
field context are not identities because public counts, generations, and exit codes use the same
domain.

**Evidence:** Typed location/controller automation, command/input state-machine tests, recursive
privacy scans, and redacted live device reports.

### `AUT-016` - Canary-first POC and consolidated attestation
**Contract:** Investigation and focused runtime development MUST use a distinct non-attestable POC
phase before release acceptance. A coverage failure MUST first be reproduced by the independent
canary through the same ordinary-client API family as the affected application. Iteration MUST then
use only the smallest affected offline build, focused host/unit checks, explicit POC installation,
and one focused canary device session. POC outputs MUST remain below `.artifacts/poc/`; they MUST NOT
replace `dist/`, update `VALIDATION.md`, satisfy an acceptance target, or be described as inspected,
reproducible, or accepted artifacts.

After the focused canary proves the intended behavior in the observed session, one unchanged candidate
MUST enter the ordered final flow in `AUT-018`. Documentation review and `docs-check` MUST finish as
a separate repository-quality phase; every broad technical formatting, static-analysis, unit,
model, topology, signing, network-denial, and confinement gate MUST then finish before the first
clean final artifact build, freeze, or immutable device-evidence action. Documentation is neither a
preflight prerequisite nor a receipt input. Those gates MUST NOT be rerun between ordinary POC edits
or after device evidence begins. A later text-only correction requires only `docs-check`; it does not
alter or reauthorize the final flow. Location commands MUST carry no
unrelated module/framework state labels, checks, transitions, artifact identities, or acceptance
phases.

The location delivery POC MUST use `location-poc-build`, `location-poc-stage`, and
`location-poc-reboot`, with `location-poc-run` as their single-command composition followed by the
focused canary. Its build MUST compile the ARM64 native module/helper with the explicit global
application POC definition, the Java bridge DEX, and the ShadowHook linker helper. Those four files
form one disposable runtime set. The build MUST reuse an already bootstrapped builder directly and skip
toolchain inventory, unit suites, ZIP packaging, deterministic repeat, artifact hashes, and
reproducibility. Stage MUST check only the fixed module ID, enabled configuration, absence of a
pending Magisk update, successful upload, and durable per-file replacement of
`zygisk/arm64-v8a.so`, `locationctl`, `bridge.dex`, and `libshadowhook_nothing.so`. It MUST preserve
the active `.app-control` delivery page until reboot so already-running applications retain the last
applied generation during the stage/reboot gap. It MUST NOT compare host/device hashes or run full
module, memfd, runtime, or report attestation. Reboot MUST wait only for completed
Android/rooted-adbd boot;
the focused canary is the POC behavioral gate and any non-`PASS` JSONL verdict MUST exit nonzero after
preserving its redacted report. POC live set/status MUST validate helper protocol behavior but skip
helper and persistent-config hash comparison. The focused POC canary MUST likewise skip the
configuration digest calculation/comparison and use only the non-attestable oracle sentinel defined
by `PRB-012`; with an empty `LOCATION_ORACLE`, it MUST derive the current applied point privately
in memory instead of omitting spatial verification. None of these targets may depend on an ordinary
location build.

After fail-open interception is proven, `location-candidate-build` MUST compile the same global path
without the POC definition and require production fail-closed lifecycle markers. Its output MUST
replace only the same disposable `.artifacts/poc/` four-file runtime-set slots. `location-candidate-run`
MUST compose that build with the same minimal stage, reboot, and focused canary steps. Neither
candidate target may package a ZIP, write `dist/`, compute an artifact/config hash, run
reproducibility, or produce acceptance evidence. When the candidate was already built, the
individual stage, reboot, canary, smoke, and live-reuse targets SHOULD be used to avoid rebuilding.

The POC native inspection MUST require the pidfd identity/failure markers without computing an
artifact digest. After the focused canary starts, `location-poc-smoke` MUST validate the active
schema-4 runtime, exactly one `anon_inode:[pidfd]` held by its declared control owner, and the
read-only application delivery mapping. It MUST record only the pidfd count and mechanism label,
never the PID, descriptor number, coordinates, or hashes.

`location-poc-live-reuse` MUST be a typed, no-build/no-reboot POC flow. It MUST retain the current
applied point only in memory, require a horizontally distinct ignored mode-0600 candidate, apply it
only through fixed-helper stdin, trigger a pending upstream generation with an explicitly
oracle-free canary session when necessary, and then pass the spatial canary without changing the
already-running canary PID. A `finally` path MUST restore and verify the original point even when the
candidate test fails. The flow MUST skip all artifact/config hashes and write only redacted POC
reports.

Full inspection MUST be a separate, explicit flow. `location-final-build` MUST first verify the
current `AUT-018` preflight receipt, then build and inspect the frozen combined-host ZIP, controller
APK, and probe APKs with their ordinary reproducibility and identity checks. After the explicit
final device workflow has collected evidence for those unchanged artifacts,
`location-final-attest` MUST verify the same receipt/freeze and evaluate only the complete current
location evidence. It MUST NOT rerun documentation, syntax, quality, unit, model, signing, network,
confinement, build, or device-mutation work. Neither target is a prerequisite of a POC target.

**Evidence:** Development and device runbooks, POC-only Make targets and output boundary, final
artifact exporters, and acceptance provenance checks.

### `AUT-017` - Server-VPN POC and final flow
**Contract:** Server-VPN development MUST use a non-attestable fast flow exposed through explicit
combined-host build/install, universal-probe pair build/install, reboot, status, paired probe, and
isolation targets. No target may compose an implicit rebuild, install,
and reboot of an unchanged candidate. The flow MUST reuse the bootstrapped offline builder, compile
only the affected combined-host native/bridge/policy runtime set plus both flavors from the one
universal probe source graph, write only below `.artifacts/poc/`, validate only the minimum
fixed generic Magisk host identity and runtime layout, install the immutable packaged
production policy durably without disabling or reconfiguring the running location
feature, reboot explicitly, and run the smallest source-specific target/canary oracle. It MUST skip deterministic
repeat, full ZIP/APK export and inspection, artifact/config/catalog hash comparison, broad
quality/unit/documentation gates, repository acceptance, and evidence promotion. A POC target MUST
never write `dist/` or `VALIDATION.md`, toggle VPN, inspect `deprecated/`, or depend on archived
build or acceptance code. It MAY compile the common host directly but MUST not invoke the
location final-build/acceptance flows during iteration. The focused active POC MUST validate exactly
one active VPN agent while automation performs no VPN transition. Module-disabled stock/active/
rollback differentials belong to the consolidated final flow, not the ordinary iteration loop. The
overlapping calibrated active primary/canary collection MUST bind one unchanged
privacy-safe agent fingerprint before and after both runs; the diagnostics residual MUST instead
collect both roles sequentially on one unchanged active boot. Cross-boot agent identity equality is
neither required nor claimed. Post-reboot POC validation MAY wait for at most 90 seconds for the owner-maintained
single VPN agent after Android reports completed boot; it MUST fail on timeout or multiple agents and
MUST NOT start, stop, reconfigure, or otherwise mutate VPN state.

The repeatable POC install target MUST consume only the already-built combined ZIP, allow a normal
new install or update, and keep an identical interrupted staging operation resumable. It MUST validate its fixed
identity/guard/layout and presence of the immutable packaged server-VPN policy with no private
target enrollment or APKs. It MUST NOT depend on an active VPN agent. POC reboot/status MUST accept
only a current combined host whose production policy automatically arms server-VPN, whose location
is either healthy waiting/5 or active/5, and whose `system_server` is stable; it deliberately
does not compare the disposable helper with a frozen `dist/` hash. Install and inactive validation
MUST NOT contain any obsolete-identity migration behavior.
Catalog preparation failures MAY retain only a bounded category and zero-based descriptor-row index
in POC status. Raw reflection exceptions, class/member names, package inventories, and runtime object
values MUST NOT enter status, reports, or logs.
The single-flavor server-VPN POC runner MUST use only the installed universal probe flavor, validate
schema/privacy/projection for the selected group, and force-stop that exact package in `finally`.
POC installation MUST validate the common host, production enablement, preserved location config,
and packaged VPN policy but MUST NOT require or inspect VPN-agent readiness; its next explicit
active reboot/status is the behavioral precondition. No server-VPN configuration staging target is
permitted.
Explicit module-disable POC recovery MUST likewise run without a VPN-agent precondition, reboot
once, and prove only stable current `system_server` plus absence of both feature runtimes. The
separate recovered-stock probe is responsible for waiting for one owner-maintained VPN agent and
producing rollback evidence. Recovery MUST preserve the complete packaged runtime/policy set and
location configuration; it MUST NOT build, attest, repair by ad hoc replacement, or migrate an
obsolete identity.

Every final server-VPN reboot-bearing command MUST use the same durable-intent semantics as
`AUT-013`, additionally binding the frozen generation ID. An interrupted `final-reboot` or
`final-recover` rerun MUST finish validation of an already changed boot without rebooting again;
same-boot resumption MAY dispatch the pending reboot. It MUST never accept an intent for another
expected state, operation, or frozen generation. A reboot intent MUST contain no ADB selector or
device identity; each invocation performs the current transport selection defined by `AUT-009`.

After hook feasibility is proven, a POC generation that already uses the complete catalog and exact
production all-or-none activation semantics becomes the disposable candidate in place; automation
MUST NOT rebuild or relabel byte-equivalent inputs merely to create a candidate phase. A distinct
`server-vpn-candidate-build` is required only if compile definitions, packaged runtime inputs, or
activation semantics actually differ. Individual no-build install, reboot, status, probe, isolation,
and recovery targets MUST remain usable so an unchanged generation is not rebuilt between checks.

Only a candidate with a current successful `AUT-018` preflight receipt MAY enter
`server-vpn-final-build`, which MUST verify that receipt without rerunning its gates, perform one
clean offline reproducible build and full ZIP/APK/DEX/ELF/config/catalog inspection, and atomically
export the shared artifact set plus a mode-0600 generation manifest. Every later final target MUST
reject a changed attestable input selector, content key, artifact, or installed runtime member.
`server-vpn-final-acceptance` MUST then bind that unchanged set to
owner-maintained VPN-ON state in every rebooted module-disabled stock, active target/non-target,
isolation/concurrency/data-plane/stability, and recovered-stock phase. The simultaneous active
target/non-target phase MUST retain one unchanged privacy-safe agent fingerprint; cross-reboot
fingerprint equality is not required. Cross-boot equality MUST apply the exact scalar and
IP-derived inventory volatility rules in `PRB-015`; it MUST NOT wait for or compare assigned IP
addresses, routes, DNS servers, proxy addresses, NAT64 prefixes, or DHCP address state.
Without explicit overrides, final acceptance MUST discover the latest complete strictly ordered
baseline/active/rollback phase sequence for the current frozen generation. It MUST fully validate
the selected manifests and their referenced evidence, ignore other generations, reject malformed
phase-directory entries, and never combine an incomplete newer attempt with an older sequence.
Overrides are diagnostic-only and MUST provide all three distinct phase IDs together; a partial
override or any cross-generation/order mismatch MUST fail before aggregation.
`server-vpn-final-attest` MUST verify the current preflight receipt and frozen generation, then
evaluate only the already-collected server-VPN and replacement-location evidence. It MUST NOT run
quality, static analysis, model/unit, documentation, topology, signing, network, confinement,
artifact build, device mutation, archived code, or retired pre-shared-host location evidence.
Because `ARC-029` selected the
shared host, the final flow MUST build one frozen combined host and run the complete affected
location reacceptance exactly once before promotion. Failure and invalidation routing MUST follow
`AUT-018`.

Final stock and active collection MUST use explicit suite targets over all five namespaced groups in
both main and secondary processes. Active calibrated callback-bearing groups (`server-vpn-async`,
`server-vpn-active`, and `server-vpn-link`) MUST measure target/canary overlap and run one additional
bounded stress round. Each target/canary pair MUST be prepared completely before launch and use two
ordered non-waiting `am start` invocations. Automation MUST launch canary, wait a bounded interval for
its exact app-private run-result readiness file created before detector execution, and dispatch
primary immediately after that handshake. Before either launch, automation MUST derive one bounded
future target from the current device `/proc/uptime` and pass the same value to both processes; both
MUST wait on `SystemClock.elapsedRealtime()` and begin detector execution at that rendezvous.
Concurrent Activity-start requests and `am start -W` are prohibited because the observed Android runtime can
respectively drop a pending launch or serialize competing foreground-resume waits. The pair MUST
reject malformed uptime, a missing readiness file, unequal/invalid rendezvous metadata, excessive
ready-to-dispatch delay, or either failed launch scheduling result before collection, and its
application-recorded intervals MUST independently retain positive overlap. The host syntax gate
MUST validate uptime/readiness parsing, require the coordinated launch helper, and reject
reintroduction of the `-W` flag or host parallel-launch primitive. It MUST also inspect the probe
configuration source and reject propagation of the initial rendezvous target through `copyTo` into
PendingIntent or callback delivery. Artifact inspection MUST require that both main and secondary
non-location work run in non-exported services sharing one lifecycle,
not an Activity-owned executor. Every stress-round run ID MUST be stored in the atomic active-phase manifest,
and final acceptance MUST reload and validate its metadata, JSONL, target/canary projection, and
measured overlap; a count or PASS label alone is not evidence. The diagnostics group MUST instead
validate the permission-bounded residual in
`PRB-015`. Before and after each suite, the same universal APKs
MUST run the feature-neutral `data-plane` group in both processes and both variants; only its
privacy-safe DNS/TLS/HTTPS outcome may enter the phase manifest. Final acceptance MUST require every
main, stress, and data-plane run ID to be globally unique across the selected
baseline/active/rollback sequence; one run cannot serve as evidence for two phases, groups, roles,
or checkpoints. Install, explicit enable/disable, and recovery remain separate repeatable safety transitions without
a VPN-readiness precondition; reboot/status and the three phase suites perform the declared VPN-ON
checks.
Final install MUST be a semantic no-op when the exact frozen combined generation is already live,
production-enabled, has no pending update, and contains the exact packaged server-VPN policy. It
MUST stage replacement when the existing host differs or the module is absent, preserve an existing
valid location configuration, and keep an interrupted completed Magisk staging operation resumable
without a second install. Formal baseline collection MUST then use the explicit development-only
`server-vpn-final-disable`, reboot with expected `inactive`, and run the stock suite. Active
collection MUST use `server-vpn-final-enable`, reboot with expected `active`, then run isolation and
the active suite. Rollback MUST use `server-vpn-final-recover` followed by the rollback stock suite.
All three suites require VPN ON but none may start, stop, or reconfigure the VPN provider.
Every probe or isolation Activity launch in POC and final collection MUST independently pass the
`AUT-009` UI-readiness gate. A suite that encounters a credential-protected keyguard MUST create no
phase manifest; after the owner unlocks the display, the unchanged suite is rerun without rebuilding,
rebooting, or repeating host gates.
Every final suite manifest MUST remain pending until the command, privacy guard, and atomic report
close all pass. Only then may it replace or create the accepted phase manifest. A failed or
interrupted invocation MUST never publish its pending candidate or destroy an older valid phase.

Every implemented target named here MUST be added exactly once to `AUT-011` and the server-VPN
runbook in the same change. Stateful targets MUST follow `AUT-009`; final build/attestation MUST be
device-nonmutating.

**Evidence:** Server-VPN Make dependency graph, POC-path and no-hash tests, typed state-machine and
redaction tests, final artifact provenance, and VPN-ON acceptance aggregate.

### `AUT-018` - Mandatory final preflight and phase ordering
**Contract:** Formal acceptance MUST use the following irreversible order for one unchanged
attestable code/data/build-input selector. Standalone textual documentation is not an attestable input:
all Markdown files and files below `docs/`, root license/REUSE metadata, and packaged license/notice
text are excluded from the selector. The implementation-owned server-VPN hook catalog remains an
ordinary source input. A textual
documentation edit MUST never invalidate a preflight receipt, frozen runtime generation, artifact
behavior evidence, or completed real-device attestation when the attestable code, hook catalogs,
oracles, runtime members, and tested APKs are unchanged.

Before entering this order, repository documentation MUST be reviewed and validated independently
with `docs-check`. That operation is not a Make prerequisite or input of `final-preflight`, is not
consumed by its gate graph, and cannot authorize or invalidate code attestation. Root `make
check` is only the convenience composition of that independent documentation gate and
`attestation-check`.

1. `final-preflight` MUST first run the fast device-nonmutating `location-input-check`, then run the
   complete device-nonmutating technical set before any final build, freeze, install, reboot, or
   immutable device collection. The host set is exactly root `make attestation-check`: supported
   repository privacy, supported topology and deprecated-code exclusion, current builder/dependency key validation, code-only
   formatting, lint, static analysis, syntax, location native and controller unit tests, server-VPN
   model and configuration tests, stable signing identity, network denial, and container
   confinement. Neither `docs-check` nor repository-wide `format-check` MAY be invoked by this graph.
   After the fixture check, its `prepare` step MUST validate the current content keys and materialized builder image,
   dependency manifest/archive identity and keystore, then bind their digest
   into the private preflight session. A materialized-input failure MUST stop before the expensive
   gate set. `record` MUST reject any change to that digest across the gate run.
2. Only after every gate passes, `final-preflight` MUST atomically write an ignored mode-0600 receipt
   that binds the complete attestable-input/build-input selector, builder/dependency keys, the
   actual content-tagged builder image identity, dependency-cache manifest/archive
   identity, current keystore bytes/signing identity, the complete contracted attestable gate set, and the
   successful report identities observed by `record`. The timestamp-bearing aggregate
   `attestation-check` report MUST NOT be bound because it duplicates that gate inventory. Once recorded, the receipt
   is the durable proof of those successful gate results: later report regeneration, deletion, or
   timestamp change MUST NOT invalidate it. A failed or interrupted preflight MUST leave no receipt
   that verifies for current inputs.
3. `final-preflight-verify` MUST be read-only and fast. It MUST reject a missing/malformed receipt,
   a changed attestable selector or bound input, malformed recorded gate evidence, or a recorded
   gate set that differs from this contract. It MUST validate the gate records embedded in the
   receipt and MUST NOT depend on mutable report files remaining present. It MUST NOT rerun a
   formatter, linter, analyzer, unit/model test, build, device command, or evidence aggregate.
4. Final build targets MUST depend on receipt verification, never directly on `attestation-check`,
   `check`, or their
   members. They MAY then perform the one clean offline artifact build, inspection,
   reproducibility check, and atomic freeze for that exact selector. An artifact build MUST NOT
   invoke a preflight formatter, linter, analyzer, unit/model test, documentation check, or
   confinement gate, and MUST NOT overwrite any report bound by the receipt. Verification MUST
   complete before any artifact build starts even under parallel Make execution; it MUST NOT be a
   sibling prerequisite that can race a build under `make -j`. Formal artifact recipes MUST use a
   no-bootstrap mode: a missing or changed builder image, dependency cache, or keystore MUST fail
   before container compilation and MUST NOT invoke online image/dependency recovery or signing
   initialization. The first Android artifact transport MUST validate the dependency archive before
   any container compilation begins.
5. Final device targets MUST depend on both receipt and frozen-generation verification. They MUST
   consume only the frozen artifacts and MUST NOT rebuild or invoke any preflight gate. Final attest
   targets are evidence-only aggregates over the same verified receipt/freeze and MUST be
   device-nonmutating. Materialized builder images, dependency caches, and keystore bytes are strict
   preflight/final-build inputs and MUST be revalidated immediately before compilation and freeze.
   After the generation is frozen, device and aggregate targets MUST validate their identities from
   the immutable preflight receipt, unchanged attestable input/content keys and descriptors, frozen build
   reports, and exact artifact hashes; they MUST NOT require those disposable host build inputs to
   remain materialized or rehash them during every phone phase. Before the first formal device mutation, `location-final-input-check` MUST
   read and validate every unchanged blocked/passthrough boot input, matching oracle, first live
   input, and edge input. It MUST reject wrong ownership/mode/schema, caller-managed boot
   generations, mode-fixture drift, boot/oracle disagreement, non-distinct live points, or an edge
   point that exercises neither an opposite hemisphere nor a bounded dateline/pole region, while
   retaining only role digests and boolean relations. A successful final input check MUST atomically
   write an ignored mode-0600 receipt binding those role digests and relations to the frozen
   generation. Every formal location phase target MUST re-read all six inputs, verify that receipt
   and the current frozen generation before selecting ADB or launching an application, and bind that
   generation ID into its atomic phase manifest. The final aggregate MUST repeat the same read-only
   input-receipt verification. The reusable no-module baseline remains artifact-independent as
   allowed by `VAL-013`; every other final location phase and the final aggregate MUST reject an
   unbound or different generation.
   Repeating the input check with identical content MAY be a semantic no-op, but it MUST NOT rebind
   different private inputs to the same frozen generation. A different receipt requires a newly
   preflighted and frozen generation before any replacement is written.
   A location phase manifest likewise MUST remain pending until its command, privacy guard, and
   atomic report close pass; failure MUST discard the candidate while preserving any prior accepted
   phase.
6. Only after every server-VPN and location evidence aggregate passes MAY `VALIDATION.md` be updated.
   It and every other textual documentation file are outside the attestable selector; immediately
   after any documentation change only `docs-check` MUST run. No broad source gate, build, freeze,
   artifact inspection, or device phase may be repeated merely because documentation was corrected,
   reorganized, or accepted evidence was recorded.

Failure routing is mandatory. A host/preflight failure MUST be fixed and checked first with only the
narrow failing target, then with one complete `final-preflight`; no artifact or device evidence is
lost because neither was allowed to start. An attestable code/data/build-input change after preflight
invalidates the receipt and returns to complete preflight. If it changes runtime behavior, artifact
contents, an oracle, or a device state machine, the affected focused POC/review gates MUST also pass
before preflight. An attestable code/data/build-input change after freeze invalidates only the evidence
whose executable artifact, tested APK, descriptor, oracle, or runtime semantics changed. A host
automation change requires a new preflight for a future build, but it does not retroactively
invalidate evidence for an already frozen and accepted artifact unless it changes how that evidence
is interpreted. A device-only failure with unchanged verified inputs MUST use the explicit recovery
path and repeat only the affected device phase plus dependent evidence aggregate; it MUST NOT
rebuild or rerun host gates. Every textual-document-only correction MUST run only `docs-check`.

**Evidence:** Make dependency graph, typed preflight and private-input receipt tests, source/input
mismatch and post-preflight report-preservation negative tests, final target provenance checks, and
evidence-only aggregate reports.
