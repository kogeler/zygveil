<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Device Operations

This runbook covers only supported ZygVeil components. Source under `deprecated/` has no install,
scope, test, inspection, recovery, or acceptance procedure.

## State Rules

- Every device mutation is an explicitly named Make target.
- Build, status, probe, isolation, and acceptance targets do not install artifacts or change
  module, VPN, feature configuration, or persistent product state. Probe and isolation targets do
  perform their documented transient display wake, non-credential keyguard dismissal, application
  force-stop, Activity/service launch, and private run-file lifecycle.
- No target starts, stops, reconfigures, or toggles the VPN. The owner keeps VPN configured ON and
  every rebooted server-VPN phase validates exactly one active agent. Only the overlapping active
  callback-bearing primary/canary runs require one unchanged runtime-agent fingerprint.
- Module install, configuration, enable, disable, reboot, update, uninstall, and recovery remain
  separate actions.
- Before an Activity launch, automation first wakes the display and asks WindowManager to dismiss
  only a keyguard that needs no owner credential. It never supplies or bypasses an owner secret.
- If a credential-protected keyguard remains, automation stops before probe/controller state changes.
  The agent asks once for the owner to unlock the display, waits for confirmation, and reruns only
  that unchanged target; it does not rebuild, reboot, or guess repeatedly.
- `components/probe/` is the only probe project. Primary is an ordinary eligible server-VPN target
  and canary is the fixed non-target control; both variants also run location and future oracle groups.

## Production User Experience

Repository automation is not part of ordinary product activation. The supported user journey is:

1. Install the ZygVeil Magisk ZIP and the standalone ZygVeil Location APK.
2. The successful module install leaves ZygVeil enabled; reboot once. An owner who explicitly used
   Magisk to disable the whole module must explicitly re-enable it before this reboot.
3. Server-VPN masking starts from the packaged policy during that boot. There is no VPN UI, target
   enrollment, ADB command, Make target, or second feature switch.
4. Open ZygVeil Location, grant its fixed helper request through the normal Magisk UI, enter a point,
   and tap Apply. Before this first Apply, location reports `Waiting for coordinates` and stock
   location passes through. The first Apply persistently activates location masking; subsequent
   Apply operations only replace the synthetic point. Reboot and ordinary module update retain the
   active point.

Everything below is a development, diagnostic, recovery, or acceptance interface. Its explicit
state transitions do not add production setup steps.

With exactly one connected and authorized ADB transport, every target selects it automatically. If
multiple transports are present, the target stops without printing their selectors; rerun only that
target with a transient selector:

```text
make <target> ADB_SERIAL=<selector>
```

Automation never writes that selector to a report, state file, reboot intent, artifact, or error.
Every resumed command repeats transport selection instead of recovering a stored selector.

Use `make adb-root` or `make adb-unroot` only when an exact procedure requires an adbd identity
transition. Both commands restart adbd and verify the resulting UID.

## Read-Only Baseline

These commands do not mutate the device:

```text
make vpn-status
make location-status EXPECTED_STATE=any
make server-vpn-poc-status SERVER_VPN_POC_EXPECTED=<expected>
```

## Activity-Launch Readiness

Every probe, probe-isolation, controller-open, and controller-root/status target invokes the common
readiness operation immediately before its first application change or Activity launch. It reads
PowerManager and WindowManager state, sends a bounded wake event when needed, and uses the platform
keyguard-dismiss command only when Android can complete it without an owner credential. The same
operation can be checked explicitly:

```text
make device-ui-ready
```

`ui_ready=true` means the display is awake and WindowManager no longer reports a showing keyguard.
If the target reports `manual_unlock_required`, unlock the phone normally and rerun the same target.
Do not advance to the next suite and do not perform a host gate, build, reinstall, or reboot. The
readiness result is intentionally not cached: a long suite checks again before every later Activity
launch. The location stability target completes its probe restart before its intentional screen
off/on cycle, so a secure keyguard can only require owner action at the next command boundary.

## Universal Probe

Build and install the same primary/canary APK pair for every feature:

```text
make build-probe
make probe-install-existing
make probe-install-canary-existing
```

Use `probe-install` and `probe-install-canary` only when a rebuild is intended. Low-level diagnostic
runs are explicit and cannot satisfy feature acceptance alone:

```text
make probe-run VARIANT=<primary|canary> GROUP=<group> RUN_ID=<id>
make probe-results VARIANT=<primary|canary> RUN_ID=<id>
make probe-cleanup VARIANT=<primary|canary>
```

## Location Development Lifecycle

Build once, then consume the frozen ZIP without rebuilding:

```text
make location-build
make location-install-existing
make location-reboot EXPECTED_STATE=waiting
```

The install target stages the package without creating a disable marker. The explicit reboot proves
the same production default as an ordinary Magisk install: server-VPN active and location either
`waiting` for its first Apply or already active from a configuration preserved across update.

For a development-only Raw/model boot-parameter experiment, first enter the explicit disabled
recovery state and write a private mode-0600 boot configuration:

```text
make location-set LOCATION_CONFIG=.state/<private-config>.properties
```

The private input is declarative: include every schema-1 location field except `enabled` and
`config_generation`. The target preserves the phone's one-way location activation state. Never edit
or precompute a generation between mode changes. `location-set` retains the current generation
without writing when the requested values already match; otherwise it reads the installed
generation and assigns the next value atomically.

Re-enable this development fixture with two explicit transitions:

```text
make location-enable
make location-reboot EXPECTED_STATE=active
```

Disable and verify stock restoration through the same explicit boundary:

```text
make location-disable
make location-reboot EXPECTED_STATE=disabled
make test-location-restored
```

Ordinary updates preserve a valid location configuration and do not require disabling the product:

```text
make location-update-existing
```

Uninstall remains an explicit recovery operation and requires the disabled state:

```text
make location-uninstall
make location-reboot EXPECTED_STATE=absent
```

The second command is the repeatable Magisk removal boundary. It accepts only `remove_pending`,
persists a resumable reboot intent, and proves `absent` after a new kernel boot.

## Location Controller And Live Control

Build/install the controller separately from the Magisk ZIP:

```text
make location-controller-build
make location-controller-install-existing
make location-controller-open
```

The owner grants the fixed helper request through the normal Magisk UI. Automation must not edit
root policy. Normal use ends here: the first Apply in this UI activates location, and later Apply
operations replace the point. The following helper targets are development equivalents, not user
setup requirements:

```text
make location-controller-status
make location-live-set \
  LOCATION_LIVE_FILE=.state/<private-point>.properties
make location-live-status
```

Latitude, longitude, and both altitude values travel only through the controller UI, fixed helper stdin, or a
mode-0600 ignored file. They never appear in Make variables, command arguments, logs, reports, or
probe JSONL.

## Location Development POC

The fast loop is non-attestable and writes only below `.artifacts/poc/`:

```text
make probe-canary-poc-build
make probe-canary-poc-install
make location-poc-run \
  RAW_GNSS_MODE=<blocked|passthrough> OBSERVATION_WINDOW_MS=10000
```

When the candidate is already built, use the individual `location-poc-stage`,
`location-poc-reboot`, `probe-canary-poc-location`, and `location-poc-smoke` targets instead of
rebuilding. `location-poc-live-reuse` proves a temporary live update in one unchanged canary PID and
restores the original point in `finally`.

## Server-VPN Development POC

The server-VPN feature has no UI and no feature-level enable switch. The packaged production policy
in an enabled ZygVeil module causes the complete 14-hook transaction to attempt activation after
reboot. Install or update the already-built disposable combined host and validate that production
startup directly; there is no private configuration stage and no location activation precondition:

```text
make server-vpn-poc-build
make server-vpn-poc-install
make server-vpn-poc-reboot
make server-vpn-poc-status
```

The install leaves the Magisk module enabled. After reboot, server-VPN MUST be `active`; location
MAY be `waiting` before the controller's first Apply or `active` after coordinates already exist.
These POC targets model the installed product startup and MUST NOT create an activation dependency
on `location-set`, `location-enable`, or a host-only server-VPN configuration.

Build and explicitly install both flavors from the one universal probe project:

```text
make probe-server-vpn-poc-build
make probe-primary-poc-install
make probe-canary-poc-install
```

Run isolation and a focused active oracle without rebuilding or restaging:

```text
make server-vpn-poc-isolation
make server-vpn-poc-probe \
  SERVER_VPN_PROBE_GROUP=server-vpn-async
```

The probe target performs no build, stage, reboot, module transition, or VPN transition. It runs
primary and canary concurrently for calibrated callback groups, or sequentially for the explicit
diagnostics residual, validates active runtime state before collection, and rejects a changed
VPN-agent, boot, or `system_server` identity afterward. Reuse it for unchanged code instead of
repeating the build. A failed POC is never promoted to `dist/` or `VALIDATION.md`.

Run one additional active group in either installed flavor without rebuilding when focused
regression, rather than simultaneous callback delivery, is required:

```text
make probe-server-vpn-poc-run VARIANT=<primary|canary> \
  SERVER_VPN_GROUP=<server-vpn-group>
```

Explicit disable/rollback operations remain development-only diagnostics. They are not production
setup and are not prerequisites for the focused active POC.

## Final Evidence

POC success does not authorize a final build or phone transition by itself. First complete all
source/review/runbook work and run the mandatory device-nonmutating host preflight:

```text
make docs-check
make final-preflight
make final-preflight-verify
```

The first command is independent documentation quality and never affects an existing receipt or
device evidence. Stop on any technical preflight failure. Fix and run the narrow failed host target,
then rerun the complete preflight; do not freeze, install, reboot, or collect formal evidence before
its attestable-input-bound receipt passes. The strict gate set and failure routing are documented in
`AUT-018` and the development runbook. This target checks all six private location fixtures first; materialized
builder/cache/keystore defects are then checked by `prepare`, still before the expensive
gate set starts.

Freeze the one combined generation only after that PASS:

```text
make server-vpn-final-build
make location-final-input-check
```

The build verifies the receipt without rerunning host gates and binds its generation manifest to the
receipt. The input check is read-only and rejects every private fixture defect before phone work. A
successful check records only role digests and relations in a private generation-bound receipt;
every formal location phase and final aggregate revalidate it before ADB selection. A later
   attestable input/content-key/artifact or private-fixture change invalidates the applicable receipt.
Standalone textual documentation is outside both receipts and never invalidates the frozen
generation or its device evidence.
The already-frozen phone flow does not depend on retaining the disposable builder image, dependency
cache, or keystore on the host. From this point through the device
matrices, do not run formatting, lint, static analysis, units/models, broad repository gates, or
another build. A text correction is independent: run only `make docs-check`, which neither mutates
the phone nor changes attestation identity.

Install the frozen probe pair first. If the existing artifact-independent no-module baseline no
longer satisfies `VAL-013`, reach `absent` through the explicit disabled uninstall flow above,
capture a replacement, and only then install the frozen module. Otherwise reuse the matching
baseline and do not uninstall solely to repeat it:

```text
make probe-install-existing
make probe-install-canary-existing
make test-location-final-baseline
```

The last command is conditional as described above. Installation consumes only the frozen ZIP,
preserves an existing valid location configuration, leaves the module production-enabled, and does
not require VPN readiness. The immediately following disable is an explicit development evidence
transition, not product setup; it also handles a just-staged update and preserves both feature
inputs:

```text
make server-vpn-final-install
make server-vpn-final-disable
make server-vpn-final-reboot SERVER_VPN_FINAL_EXPECTED=inactive
make location-controller-ensure-existing
make test-location-final-disabled
```

The disabled location phase consumes the current-boot location state already recorded by the
preceding shared-host `server-vpn-final-reboot`. It must not add a second location-only reboot.

Capture the complete main/secondary stock suite:

```text
make server-vpn-final-stock-suite \
  SERVER_VPN_FINAL_PHASE_KIND=baseline
```

This target automatically wakes and dismisses a non-credential keyguard before every Activity
launch. If it stops with `manual_unlock_required`, unlock the screen and rerun this same baseline
suite; no baseline phase manifest was accepted and no earlier final step is repeated.

Enable the unchanged combined host explicitly, reboot, validate isolation, and capture the active
suite. There is no server-VPN configuration stage: the frozen ZIP already contains the immutable
global policy. All five server-VPN groups run in both processes; callback groups
include a second stress round, and the feature-neutral data-plane group runs for both APKs before
and after collection:

```text
make server-vpn-final-enable
make server-vpn-final-reboot SERVER_VPN_FINAL_EXPECTED=active
make server-vpn-final-status SERVER_VPN_FINAL_EXPECTED=active
make server-vpn-final-isolation
make server-vpn-final-active-suite
```

The isolation and active-suite targets apply the same readiness rule independently. A manual unlock
failure is resumed at the failed target against the unchanged active boot.

For every callback-bearing main or secondary group, the active suite writes both run states and
force-stops both packages before scheduling canary with a non-waiting Activity launch. It waits for
the exact canary run-result readiness file and then immediately schedules primary. The coordinated
path gives both processes one common boot-monotonic detector-start rendezvous; it neither races
Activity starts nor uses `am start -W`, because the observed Android runtime can drop or serialize those
requests. The report records the rendezvous and bounded ready/dispatch timing, and acceptance later revalidates the
mutually bound run metadata plus positive application-recorded overlap. A failed pair publishes no
active phase manifest. If source and frozen artifacts are unchanged and the failure is an external
device/ADB interruption, rerun this active-suite target on the same boot. If the failure exposes an
automation defect, stop formal collection: update the owning contract and code, run the focused
`probe-server-vpn-poc-concurrent` regression twice on the unchanged active boot, then repeat
preflight/freeze and the attestable-input-bound phases as specified by `DEVELOPMENT.md`.
The launcher Activities do not own detector executors: they hand every non-location session to the
probe's non-exported main or `:secondary` service before another Activity can replace them.

Recovery explicitly disables the shared module while preserving packaged VPN policy and location
configuration; it has no VPN precondition. The rollback suite performs the separate VPN-ON
evidence check:

```text
make server-vpn-final-recover
make server-vpn-final-stock-suite \
  SERVER_VPN_FINAL_PHASE_KIND=rollback
make server-vpn-final-acceptance
```

Acceptance automatically selects the latest complete ordered baseline/active/rollback sequence
for the frozen generation. An interrupted newer sequence is not combined with older evidence.

The rollback suite uses the same readiness/resume boundary; recovery and its reboot are not repeated
solely because the owner had to unlock the screen.

After server-VPN recovery and rollback collection, the shared module is disabled and the persisted
location activation is unchanged. Switch through passthrough and back to blocked with the unchanged
declarative inputs; generation assignment is automatic:

```text
make location-set \
  LOCATION_CONFIG=.state/location-boot-passthrough.properties
make location-enable
make location-reboot EXPECTED_STATE=active
make test-location-final-passthrough \
  LOCATION_ORACLE=.state/location-oracle-passthrough.properties

make location-disable
make location-reboot EXPECTED_STATE=disabled
make location-set \
  LOCATION_CONFIG=.state/location-boot-blocked.properties
make location-enable
make location-reboot EXPECTED_STATE=active
make test-location-final-blocked \
  LOCATION_ORACLE=.state/location-oracle-blocked.properties
```

Verify controller authorization on that same blocked boot. If it reports that Magisk consent is
still required, run `location-controller-root-request`, approve the fixed request in the Magisk UI,
and rerun only `location-controller-status`; do not repeat a reboot or phase:

```text
make location-controller-status
```

Apply two live generations and complete the same-runtime isolation, stability, failure, and stress
phases. A pending helper result is valid; the following formal phase triggers an upstream event and
requires the generation to become applied:

```text
make location-live-set \
  LOCATION_LIVE_FILE=.state/location-live-second.properties
make test-location-final-live \
  LOCATION_ORACLE=.state/location-live-second.properties
make location-live-set \
  LOCATION_LIVE_FILE=.state/location-live-edge.properties
make test-location-final-live-edge \
  LOCATION_ORACLE=.state/location-live-edge.properties
make test-location-final-isolation \
  LOCATION_ORACLE=.state/location-live-edge.properties
make test-location-final-stability \
  LOCATION_ORACLE=.state/location-live-edge.properties
make test-location-final-failures
make test-location-final-stress \
  LOCATION_ORACLE=.state/location-live-edge.properties
```

Perform exactly one active reboot for persistence, then use the explicit recovery route and capture
fresh restored-stock behavior:

```text
make location-reboot EXPECTED_STATE=active
make test-location-final-persistence \
  LOCATION_ORACLE=.state/location-live-edge.properties
make location-recover
make test-location-final-restored \
  LOCATION_ORACLE=.state/location-live-edge.properties
```

Every formal phase verifies and records the current frozen generation before selecting ADB. Do not
substitute the unbound development `test-location-*` targets. Run the single evidence-only aggregate:

```text
make server-vpn-final-attest
```

The three server-VPN phases independently require owner-maintained VPN ON. No VPN-OFF phase or
cross-boot VPN-agent identity comparison is required.

The final attest target verifies the receipt/freeze and reads existing evidence only. After it
passes, promote the exact identities and results to `VALIDATION.md`, then run only `make docs-check`.
Do not repeat host preflight, artifact build, or a device phase because any standalone textual
documentation changed.

## Recovery

For a location failure, capture bounded diagnostics before changing state:

```text
make location-logs
make location-recover
```

For server-VPN POC failure, use `server-vpn-poc-status` first and
`server-vpn-poc-recover` only when restoration is required. Never disable the VPN or clear unrelated
device state as part of recovery.

For a final device-only failure with unchanged attestable inputs, preflight receipt, and frozen
artifacts, use the explicit feature recovery target and repeat only the failed phase plus its
dependent evidence aggregate. Do not rebuild or rerun preflight.

If `location-reboot`, `location-recover`, `server-vpn-final-reboot`, or
`server-vpn-final-recover` is interrupted after dispatch, rerun that exact command with the same
expected-state variables. Transport selection is repeated from current ADB state: the sole transport
is automatic, while multiple transports require the transient `ADB_SERIAL` selector described above.
The selector is never recovered from or written into the private durable intent. That intent resumes
post-boot validation and does not send a second reboot after Android has entered a new boot. Do not
replace it with a status command or manually delete the intent. Only one reboot-bearing transition
may be pending on the host; a different command stops on that conflict. A resumed command waits for a
kernel boot-ID change, not merely an already-completed source boot.
