<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Validation Contract

### `VAL-001` - Evidence binding
**Contract:** Runtime evidence MUST bind the exact executable artifacts, probe/controller APKs,
configuration generation, process role, hook catalog, declared feature state, and observations used
by that evidence. It MUST NOT bind or disclose a phone model, manufacturer, product name, ADB/USB
serial, transport ID, build or vendor fingerprint, build/display ID, kernel release, telephony or
subscriber identifier, Android ID, host username, or absolute checkout path. Device observations
prove only the recorded session and MUST NOT establish compatibility with a phone or Android build.

**Evidence:** Artifact selectors, privacy checks, redacted phase summaries, and aggregate validators.

### `VAL-003` - Accepted artifact generations
**Contract:** An accepted generation MUST record immutable executable and APK hashes for the shared
host and each feature without including device identity. Rebuilding an executable, controller,
probe, packaged policy, or implementation-owned hook catalog invalidates the affected generation.
Standalone textual documentation remains outside runtime identity.

There is currently no promoted artifact generation or accepted runtime-session evidence for this source tree.
No release or compatibility claim may use older evidence. A future functional change MUST complete
the current final preflight, build, and device flows before evidence is promoted here.

**Evidence:** Final generation manifest and evidence aggregates when a generation is promoted.

### `VAL-008` - Repository acceptance
**Contract:** Repository acceptance MUST keep documentation quality and code attestation separate as
required by `AUT-018`. `make check` MAY compose the independent `docs-check` and
`attestation-check` operations, while `make final-preflight` executes only the technical gate set
and records its receipt. A documentation-only correction never requires a build or device rerun.
Repository acceptance MUST include the repository-input and exported-artifact privacy boundaries in
`SEC-005` and `AUT-008`.

**Evidence:** Successful documentation, privacy, quality, unit/model, signing, network-denial, and
confinement reports.

### `VAL-009` - Retest triggers
**Contract:** A change to hook behavior, policy, runtime lifecycle, probe/oracle semantics,
controller/control protocol, packaged input, build/signing input, or evidence interpretation MUST
invalidate the affected technical receipt or generation. Documentation-only changes do not
invalidate unchanged executable evidence. A transport retry with unchanged inputs may repeat only
the interrupted phase; a source defect requires a new preflight and frozen generation.

**Evidence:** Content selectors, failure routing, and aggregate validation.

### `VAL-012` - Compatibility non-claim
**Contract:** The repository, build artifacts, reports, and documentation MUST contain no supported
phone/build inventory and MUST make no compatibility or device-integrity guarantee. Runtime hook
resolution is best-effort against the installer's environment. Missing or changed private Android
implementation members MUST produce the transactional inactive/stock behavior defined by the
feature contracts where execution can safely reach that path; they MUST NOT trigger fuzzy fallback.
The installer remains responsible for choosing a device and for all resulting device or data loss.

**Evidence:** README disclaimer, absence of device descriptors/guards, fixed catalog inspection, and
transactional failure tests.

### `VAL-013` - Location acceptance generation
**Contract:** A location generation MUST NOT be accepted until one immutable module ZIP, controller
APK, boot configuration, and common probe pair bind disabled/no-op behavior, active blocked and
diagnostic passthrough modes, at least two no-reboot live changes, persistence, invalid-update
containment, process isolation, bounded stress, and restored stock behavior. Evidence MUST contain
no raw coordinates or device identity and MUST not be interpreted as cross-device compatibility.

**Evidence:** Freeze-bound location phase manifests and `location-final-attest`.

### `VAL-014` - Controller and authorization acceptance
**Contract:** Controller acceptance MUST prove the fixed helper command/path boundary, ordinary
Magisk owner authorization, first-Apply activation, later live replacement, pending-upstream
semantics, restart persistence, privacy, and non-root denial. Automation MUST NOT edit root policy
or turn its development operations into user setup requirements.

**Evidence:** Controller unit/device reports and location acceptance aggregate.

### `VAL-015` - Server-VPN acceptance generation
**Contract:** A server-VPN generation MUST NOT be accepted until one immutable combined host,
packaged policy, implementation-owned hook catalog, and common probe pair bind stock, active target,
simultaneous non-target, isolation, callback/PendingIntent, rollback, stability, and unchanged VPN
data-plane observations. Evidence MUST contain no device identity and proves only the observed
session, never compatibility or general VPN concealment.

**Evidence:** Freeze-bound server-VPN phase manifests and `server-vpn-final-attest`.
