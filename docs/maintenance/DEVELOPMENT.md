<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Development Runbook

Use the assertion map in `AGENTS.md` before editing. This runbook contains commands and sequencing;
normative behavior remains in `docs/contracts/`.

## Bootstrap

```text
make doctor
make bootstrap
make image-key
```

`bootstrap` may access the network only while preparing the builder and dependency cache. Once
prepared, source operations are offline. Import/export an existing builder with `make image-load`
and `make image-save` when appropriate.

## Iterate And Prove

Use `AUT-016` for behavioral investigation and focused runtime work. Reproduce a coverage defect in
the universal canary first, then iterate with only the smallest affected offline Make build,
focused unit or schema check, explicit POC install, and focused canary device session. POC artifacts
remain under `.artifacts/poc/`; they are disposable and cannot update `dist/` or acceptance evidence.

Build/install the ordinary-client canary POC once with `probe-canary-poc-build` and
`probe-canary-poc-install`. After it reproduces an escape, iterate on the
native/helper/bridge/linker-helper delivery
candidate with one `location-poc-run` command, or invoke its `location-poc-build`,
`location-poc-stage`, `location-poc-reboot`, and `probe-canary-poc-location` parts separately for
diagnostics. The POC build reuses the bootstrapped builder without running its inventory; stage and
reboot perform no artifact-hash, reproducibility, runtime-attestation, or report-identity checks. The
POC canary also skips configuration-file digest calculation/comparison; its fixed schema sentinel
cannot be used as acceptance evidence. Leave `LOCATION_ORACLE` empty to test the controller's
current applied point directly in memory; provide a private file only when the POC intentionally
targets a different known fixture. The
delivery candidate applies its fixed parcel-creator hook to every application process;
it performs no package/application-ID/UID/process filtering, obtains only a read-only control mapping
from the fixed root-owned derived delivery file before specialization, makes no application-side
companion request. Constructors, setters, and parcel writes remain unhooked, but the global creator
cannot distinguish provenance: an application-created point is transformed if it is later
unparceled through the hooked method; only in-process objects that do not cross that creator remain
untouched.

After the fail-open POC passes, compile and exercise the same source without the POC definition:

```text
make location-candidate-run RAW_GNSS_MODE=<actual-mode> OBSERVATION_WINDOW_MS=10000
```

This remains a non-attestable `.artifacts/poc/` flow, but it proves production fail-closed bridge
activation and ordinary lifecycle labels. When `location-candidate-build` has already succeeded,
run `location-poc-stage`, `location-poc-reboot`, `probe-canary-poc-location`, and
`location-poc-smoke` separately to avoid compiling it again.

After a clean spatial POC or production candidate passes, prove live consumption without another
build or reboot:

```text
make location-poc-live-reuse LOCATION_LIVE_FILE=.state/<distinct-private-point>.properties \
  RAW_GNSS_MODE=<actual-mode> OBSERVATION_WINDOW_MS=10000
```

This target keeps the current controller point only in memory, requires the same canary PID across
the temporary update, and restores the original point in `finally`.

Do not run full quality, reproducibility, hash, or final acceptance gates between POC edits. Location
commands accept no unrelated framework or network state labels and inspect no such state.

For server-VPN work, extend a source-specific group in the same universal probe. Build its existing
primary/canary flavors together with `probe-server-vpn-poc-build`, install each APK explicitly, and
build/install/reboot the production-enabled combined-host POC only when its source changes. The POC
ZIP contains the immutable global policy; there is no host-private config stage. Validate
`server-vpn-poc-status`, then use `server-vpn-poc-probe` repeatedly without a rebuild. The active
primary/control-canary sessions overlap and retain one unchanged VPN-agent fingerprint.
Callback concurrency uses a coordinated Activity handshake: automation schedules canary with a
non-waiting `am start`, waits for its exact app-private result file created before detector
execution, and immediately schedules primary. Both processes then begin detectors at one common
bounded future target derived from device uptime. That rendezvous is an initial-launch input only;
the probe never copies it into a PendingIntent or callback intent whose delivery may occur after
the bounded target window. The flow never races two Activity starts or uses `-W`, because an observed
runtime can respectively drop a pending launch or serialize competing foreground-resume waits.
All non-location detector work belongs to the probe's non-exported main/secondary services; the
launcher Activity only dispatches the intent. A callback session therefore survives normal
foreground Activity replacement during a coordinated pair. Launch scheduling, bounded readiness
timing, and application JSONL intervals are validated separately. After changing that launch
orchestration, keep the current active boot unchanged and run the shortest callback pair twice
before any new preflight:

```text
make probe-server-vpn-poc-concurrent \
  SERVER_VPN_CONCURRENT_GROUP=server-vpn-link
make probe-server-vpn-poc-concurrent \
  SERVER_VPN_CONCURRENT_GROUP=server-vpn-link
```

Both runs must report one common rendezvous, bounded canary readiness/primary dispatch timing, and
positive target/canary overlap. These are
non-attestable diagnostics; they prove the orchestration fix without rebuilding or repeating the
complete active suite.
The focused POC hook transaction remains global in `system_server`; authorization is applied only
at service ingress/egress and is never used to select hook installation. Full module-disabled
baseline/active/rollback differentials belong only to the consolidated final flow. The owner keeps
VPN configured ON for every behavioral phase and uses no VPN-OFF phase or automation toggle. POC
install and explicit development recovery do not require or inspect VPN readiness because they do
not claim behavioral evidence.

## Finalize And Verify

After the focused canary and implementation/security review pass, finish all code,
contract, Make, and runbook edits. Validate documentation independently, then enter the technical
preflight:

```text
make docs-check
make final-preflight
make final-preflight-verify
```

`final-preflight` first runs the fast private-fixture gate, which performs no build or device
operation and rejects location input defects before the expensive host gate. It then invalidates
any old receipt, performs a cheap materialized builder/cache/keystore precheck, and only
then runs `make attestation-check`: privacy, topology/deprecated-code exclusion, current content keys,
code-only formatting, lint, static analysis, syntax, all location/controller/server model and
configuration tests, stable signing identity, network denial, and confinement. Only after every
fresh report passes does it write the ignored mode-0600 attestable-input-bound receipt. `docs-check`
is a separate repository-quality operation and is neither invoked by preflight nor recorded in its
technical gate receipt. The timestamp-bearing aggregate `attestation-check` report is likewise not part of
the receipt identity.
`final-preflight-verify` validates the recorded gate evidence in the receipt; it does not rerun a
gate or require the mutable report files to remain byte-identical.

If preflight fails, do not build, freeze, install, or collect device evidence. Fix the source, run
only the narrow failed target while iterating, then rerun the complete `make final-preflight` once.
Materialized-input failures occur before the expensive gates and should be repaired at that
boundary.
Running `make check` composes documentation and technical repository quality but cannot authorize
the formal flow because it does not create a receipt. `format` remains the only supported formatter entry point and applies
only manifest-owned files returned by the confined builder.

After preflight passes, build and freeze the inspected artifacts with one command:

```text
make server-vpn-final-build
make location-final-input-check
```

The target verifies the receipt without running host gates, builds the one combined ZIP, separate
location controller, and universal probe pair, performs the final artifact inspections and
reproducibility work, and writes one ignored mode-0600 generation manifest bound to the receipt.
Probe artifacts are published to `dist/` by `build-probe`; the ZIP never embeds or installs an APK.
Every later final target revalidates the same receipt and generation. The second input check repeats
the fast fixture validation against that frozen generation, writes a private role-digest receipt,
and MUST pass before the first formal phone mutation. Every formal location phase and the final
aggregate re-read the inputs and reject a missing, changed, or differently bound receipt before ADB
selection.
Final build recipes use an internal no-bootstrap mode. They fail on a missing or changed builder
image, dependency archive, or keystore instead of running network-enabled bootstrap or creating a
new signing identity; repair those inputs before preflight, never during freeze. Once the frozen
generation exists, phone phases validate the immutable receipt, attestable input/content keys, build reports,
and artifact hashes without requiring the disposable builder/cache/keystore to remain present.

Any attestable code/data source or build-input change after preflight invalidates the receipt. A
change after freeze invalidates the evidence whose executable artifact, tested APK, descriptor,
oracle, or runtime semantics changed. Standalone textual documentation (`*.md`, root license/REUSE
metadata, and packaged license/notice text) is outside that selector: edit it when necessary, then run only
`make docs-check`. That operation never invalidates the receipt, frozen runtime generation, or
real-device evidence. Do not run formatters, linters, static analysis, units, or another build after
immutable device collection starts.

An automation defect discovered during a formal device suite is a source defect, not a retryable
device phase. Preserve the failed report, fix the owning contract and code, pass the narrow host
checks, prove the affected device primitive with its focused POC twice when timing/concurrency is
involved, and only then create a new preflight receipt and frozen generation. Never resume formal
collection or aggregate evidence from the technically invalidated generation. A
credential-unlock stop, transport interruption, or declared-state mismatch with unchanged
attestable inputs and artifacts remains a retryable device condition and follows the unchanged-phase
recovery rule below. A standalone textual-documentation edit does not affect that determination.

The final device phase MUST use the matching `*-existing` install/reinstall targets so it consumes
the frozen files without invoking another build.

## Acceptance

Run the device-nonmutating evidence aggregate once after all required final device evidence exists:

```text
make server-vpn-final-attest
```

The aggregate automatically selects the latest complete ordered baseline/active/rollback sequence
from the current frozen generation. All three `SERVER_VPN_FINAL_*_PHASE` variables may be supplied
together only for diagnostic replay; partial or mixed-generation overrides are rejected.

The location runtime matrix itself is collected by the freeze-bound `test-location-final-*` targets
and validated by `make location-final-attest`. Device collection and human state transitions follow
`DEVICE_OPERATIONS.md`. `server-vpn-final-attest` and
`location-final-attest` verify provenance and aggregate existing reports only; they do not run
quality/static/docs/unit/model/confinement gates, build artifacts, install APKs, reboot the phone, or
toggle device/VPN state.

If a device phase fails while source, receipt, and frozen artifacts remain unchanged, use the
explicit recovery path and repeat only that phase plus its dependent evidence aggregate. Do not
rebuild or rerun preflight. After both feature closures pass, update `VALIDATION.md` with the exact
accepted identities and results, then run only:

```text
make docs-check
```

## Documentation Changes

Place each fact in one owner only:

- topology and invariants in `ARCHITECTURE.md`;
- Android signatures/semantics in `PUBLIC_API.md`;
- detector schema/catalog in `PROBE.md`;
- operational interface/toolchain in `AUTOMATION.md`;
- current device/artifact/results in `VALIDATION.md`;
- threat boundary/privacy in `SECURITY.md`.

Maintenance files link assertion IDs and only explain commands. Update code, the owning assertion,
tests, and Make inventory together. Run `make docs-check` after every documentation change. A
text-only correction never requires `make check`, preflight, artifact rebuild, installation,
reboot, or device re-attestation; wording cannot change the identity of code already tested on the
phone. If new wording introduces a requirement not demonstrated by the current code/evidence, do
not claim that requirement as accepted until the owning implementation or evidence is actually
updated.

## Cleanup

```text
make clean
make clean-containers
```

The first preserves `.state/debug.keystore`; the second is limited to labelled project Podman
resources. Deleting the signing identity changes upgrade compatibility and requires the explicit
command documented by `AUT-010`.
