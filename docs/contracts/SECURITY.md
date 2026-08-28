<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Security And Boundary Contract

### `SEC-001` - Covered caller
**Contract:** Supported server-VPN coverage MUST include every uniquely attributed ordinary
non-system, non-privileged application in Android user 0 whose package and UID state satisfy
`ARC-026` and `SEC-012`, except the fixed exclusions there. The universal primary probe MUST be an
eligible target and the universal canary MUST remain an explicit non-target control. Location delivery remains global to Android
application specializations without package, UID, or privilege filtering as bounded by `SEC-008`;
neither feature's target/configuration set MAY authorize the other feature.

**Evidence:** Authorization model tests, exact configuration, and primary/canary process-role
reports.

### `SEC-002` - Excluded callers and channels
**Contract:** Server-VPN virtualization MUST NOT claim coverage for system/privileged/carrier/device-owner/profile-
owner callers, the VPN provider, root/framework managers, the fixed product/control exclusions,
root, hidden/System
APIs, raw Binder, JNI/native sockets, procfs/sysfs/netlink, interface/route/DNS inspection, installed
package checks, UI/notification inspection, root/Xposed detection, Play Integrity, or hardware-backed
attestation. The `SEC-008` owner-lab exception permits the exact system-server location hooks in
`API-009`, the fixed controller/helper boundary in `SEC-011`, and only the explicitly non-attestable
POC in `ARC-022`/`API-015` plus the production global application delivery in
`ARC-023`/`API-017`. The `SEC-012` owner-lab exception separately permits only the fixed
Connectivity service hooks in `API-018` through `API-020`. Location and server-VPN authorization
and acceptance remain feature-local.

**Evidence:** Manifests, target authorization gates, source scan, and bounded claim.

### `SEC-003` - Traffic and remote inference exclusion
**Contract:** The module MUST NOT change routing, traffic policy, packets, DNS, external address, or
VPN-provider operation. IP reputation/geolocation, autonomous-system ownership, HTTP/TLS
fingerprinting, timing/path analysis, and server-side correlation remain out of scope. The universal
probe's feature-neutral `data-plane` group is an external reachability oracle, not a VPN-observation
detector; it stores no endpoint, address, response body, or TLS identity.

**Evidence:** Absence of data-plane mutation code in production, unchanged provider/runtime
observations, and the probe's feature-neutral reachability catalog.

### `SEC-004` - Fail-open behavior
**Contract:** Server-VPN discovery and hook installation MUST be all-or-none under `ARC-027`.
Per-call authorization, shape, donor, and detached-copy failures MUST preserve stock service
behavior; fatal VM/thread failures MAY propagate only where the runtime cannot safely continue.
Location activation MUST retain its separately contracted fail-safe behavior and MUST NOT be changed
by a VPN failure.

**Evidence:** Transactional hook tests, policy negative cases, failure injection, and bounded status.

### `SEC-005` - Logging and evidence privacy
**Contract:** Per-call hook failure diagnostics MUST be bounded once per method/failure category and
limited to event, method key, stage, and exception class. Normal lifecycle diagnostics MAY contain
fixed process roles and counts, but no diagnostic path may attach
network/request objects, physical provider data, coordinates, raw GNSS observations, addresses,
routes, DNS, interfaces, or raw connectivity/location dumps. Owner-selected and evidence-fixture
synthetic coordinates MUST be absent
from process arguments, environment variables, intents, logcat, helper redacted status, host/device
reports, probe JSONL, generated test evidence, and committed files. They MAY exist only in the local
controller UI/full-status pipe, the root-owned persistent configuration, bounded control payloads,
short-lived mode-private input files, and ignored mode-0600 owner state. Committed schema examples
MAY contain only the non-private placeholder values required by `ARC-019`. Host evidence containing
sensitive derived identity MUST use only explicitly contracted private digests and ignored mode-0600
owner state. Committed files, probe records, reports, durable intents, and attestation summaries
MUST contain no ADB serial, USB transport ID, phone model/manufacturer/product, build or vendor
fingerprint, build/display ID, kernel release, IMEI, MEID, Android ID, SIM/subscriber identifier,
host username, or absolute checkout path. Device selection values MAY exist only transiently in the
process invoking ADB and MUST never be logged or persisted. No compatibility guard or evidence
binding may reintroduce those values or hashes derived solely from them.

**Evidence:** Reporting redaction checks, location privacy tests, and server-VPN privacy scanners.

### `SEC-006` - Deprecated backend isolation
**Contract:** Supported source, build, test, device, and evidence flows MUST NOT inspect, build,
install, execute, configure, or derive authorization from the archived backend under `deprecated/`.
No supported workflow MAY require an application-process hooking framework or its scope state.
Caller-supplied wildcards and provider, module, system, privileged, framework-manager, or
root-manager server-VPN eligibility remain prohibited independently of this archival boundary.

**Evidence:** `make topology-check`, supported Make inventory, source-transport exclusion, and
server target negative tests.

### `SEC-007` - Bounded claim
**Contract:** A successful server-VPN generation proves only that the exact covered public API
observations for eligible ordinary applications match the contracted projection during tested
owner-maintained VPN-ON phases, while the simultaneous excluded canary remains stock and the VPN/data path
remains active. Cross-boot network-agent identity is not claimed; the active overlapping
target/canary phase MUST retain one unchanged privacy-safe agent fingerprint.
Structural-only coverage and residual observations MUST remain explicit. The result MUST NOT be
described as general VPN undetectability or as bypassing banking, payment, fraud, regional, account,
or integrity controls.

**Evidence:** README wording, validation aggregate, and documentation check.

### `SEC-008` - Owner-lab location boundary
**Contract:** The fixed-location simulator is an owner-operated, best-effort stationary QA tool with
no supported phone/build inventory and no compatibility guarantee. The ordinary module MUST NOT provide
mock-location APIs, RF/HAL emulation, Raw GNSS synthesis, framework-file patching,
boot/firmware modification, root/Zygisk concealment, or claims against integrity/fraud controls.
It MAY transform public application-visible location, status, and NMEA observations and suppress Raw
GNSS listener delivery only through the fixed system-server hooks in `API-009`. It MAY expose the
fixed root helper and separate offline controller in `ARC-021` solely to change the global synthetic
center and both configured altitudes. It MAY additionally use only the fixed global application parcel
delivery hook and a read-only application mapping of the fixed derived `ARC-020` delivery file in
`ARC-023`/`API-017`. The companion may mirror only the authoritative memfd's applied generations
into that file and bind its lifetime only to a validated kernel pidfd for the attested `system_server`;
applications MUST make no companion request and the delivery path MUST receive no application
identity or selection data. The compile-disabled POC in
`ARC-022`/`API-015` MUST remain outside ordinary distribution, validation, and acceptance paths.

**Evidence:** Package/source inspection, transactional runtime failure tests, and bounded docs.

### `SEC-009` - Location fail-safe and privacy
**Contract:** The combined module MUST install Magisk-enabled while the location feature starts in
`waiting` when no owner coordinates exist. It MUST refuse every material runtime/config mismatch,
activate atomically on the first valid controller Apply, and retain a disable-marker recovery path.
Before that one-way activation it MUST keep all hook/control infrastructure ready but fail open to stock;
after activation it MUST fail closed for Raw GNSS, server/application transformed location, status,
and NMEA events rather than expose mixed physical observations. For the global application hook,
fail-closed means that loss of the active derived-page identity or an unsuccessful object
transformation discards the once-created original and returns no physical `Location`; a bad newer
generation may retain only the last complete synthetic model. It MUST not persist or log physical
coordinates, full Raw GNSS records, navigation bits, or unredacted location dumps. Valid live updates MUST be
atomic and strictly newer; rejected, corrupt, interrupted, or unauthorized updates MUST retain the
last valid synthetic generation. Synthetic coordinates MAY be displayed only through the local
controller/full-status path; all other status and evidence MUST remain redacted.
Controller coordinate editors MUST opt out of Autofill; private preset persistence MUST be
transactional so a storage failure cannot expose an uncommitted in-memory state.
Neither production UI nor installation may expose a location disable/re-arm action. Explicit
development disable/enable operations MAY control only the shared Magisk marker and MUST preserve
the persisted location activation and coordinates.
An unprovable persistent rollback MUST be classified as `recovery_required`, not as rejection or
success; it MUST leave the last applied in-memory synthetic generation and Raw firewall active.

**Evidence:** Guard/config tests, bounded logging, report sanitizers, device recovery, and ignored
state checks.

### `SEC-010` - Location residual risks
**Contract:** Acceptance MUST state that Wi-Fi, cell, IP, timezone, sensors, radio state, missing Raw
GNSS events, root/Zygisk presence, and absence of upstream callbacks can reveal inconsistency. A
cached synthetic last location MAY remain on the previous generation until the next upstream
location result even after another upstream GNSS/NMEA event applies the new model. It MUST NOT claim
orbital/raw emulation, callbacks without an upstream provider callback, ROM-update compatibility,
or compatibility outside an observed runtime session. The global parcel-creator hook transforms every `Location`
unmarshaled through that creator regardless of whether the parcel originated in Android, GMS, or the
application itself; only application-created objects that never cross the creator are outside that
effect. `blocked` MUST be described as suppression of a supported channel, not unsupported hardware.

**Evidence:** `ARC-018`, status wording, probe summary, and `VALIDATION.md` limitations.

### `SEC-011` - Live-control privilege boundary
**Contract:** Live control MUST expose no public Binder service, provider, receiver, socket, HTTP
server, JavaScript bridge, permanent daemon, hidden/System-API client, arbitrary root command, or
caller-selected path. The ordinary controller MUST have no Internet, location, package-query,
storage, accessibility, device-admin, or background permission. The only privilege transition is a
supported Magisk `su` request for one constant helper path and fixed `apply`, `status`, or
`status-ui` subcommand; authorization requires the owner's normal Magisk grant and MUST NOT be
created by editing Magisk's policy database.

The helper MUST validate its own root identity, running executable inode, fixed installed
executable/module path, command, bounded stdin, configuration schema, file type, owner, group,
exact mode, link count, and page identity. It MUST reject
symlinks, traversal, arbitrary arguments, oversized input/output, generation wrap/regression, and
boot-field changes. It MUST use a minimal fixed environment, bounded acknowledgement wait, and
coordinate-free diagnostics. To reach the waiting-or-active page it MAY follow only the fixed companion
proc-descriptor link constructed from exact current-boot schema-4 runtime status, never a caller
value, and MUST revalidate both server and companion PID/start-time identities, memfd
name/access/mode, exact root UID/GID, link count, size, seals, and page identity after open. The exact
kernel-created memfd mode 0777 MUST be
treated only as an attested identity value: authorization depends on the root-owned status path,
procfs access checks, SELinux, and the root-only fixed helper, and server specialization MUST NOT
weaken policy or attempt the denied mode change. The internal Zygisk companion exchange MAY accept
only the distinct fixed-token location and server-VPN status descriptors plus one fixed
control-page registration descriptor from pre-server. It MUST accept no application request,
coordinate, pathname, command, acknowledgement, package, UID, process name, or caller-selected
payload and MUST send no descriptor to an application.
The registered handler MAY retain one bounded monitor that acquire-reads complete validated
generations under `ARC-020` and mirrors them into the fixed root-owned mode-0600 single-link 4096-byte
`.app-control` file. Applications MUST open that file read-only through the fixed module-directory
descriptor before specialization, validate and map it read-only, prove write upgrade is unavailable,
and close the descriptor; they MUST retain no socket, pidfd, or writable file mapping. Before
creating that file, the companion MUST bind the registered exact server PID/start-time pair to one
CLOEXEC `anon_inode:[pidfd]`, revalidate that pair around `pidfd_open`, and retain the pidfd privately
beside the authoritative control descriptor. The monitor MUST use only pidfd readiness to detect
that server's exit and close both descriptors; it MUST reject another registration while that exact
server remains live. The companion MUST schema-validate each feature-specific, coordinate- and
network-value-free status body, durably acknowledge readiness before activation, serialize each
root-owned atomic status replacement, and reject
a status write once its originating `system_server` PID/start-time identity is no longer live. Its
control descriptor registration MUST reject a competing live server, wait only a bounded interval
for an exited server's monitor to mark its page inactive and clear both descriptors, and reject the
replacement if that cleanup does not complete. It MUST also reject mismatched page identity,
unexpected access mode, ancillary data, or token, and retain no historical descriptor. Its
terminal activation claim MUST make timeout and activation mutually exclusive so an obsolete or
PID-reused companion cannot enable hooks late or replace newer status. Schema validation MUST reject
control characters, additional separators, coordinate field names, and any NMEA sentence marker
embedded in a runtime reason. Helper,
controller, companion, or page failure MUST NOT toggle module enablement, Raw GNSS mode, or any
unrelated subsystem state.
The status and control channels themselves MUST be size/seal/name/type/mode/link/access and
expected-owner validated before either side maps it. A failed native unhook MUST retain an inactive
pass-through runtime and all still-reachable JNI objects until `system_server` death; it MUST never
release an object still reachable from an installed hook.
The direct root-only `protocol-self-test` MAY validate fixed protocol constants but MUST accept no
caller-selected path or value and MUST remain unreachable from the controller.

**Evidence:** Manifest and source inspection, command/input negative tests, root-denial workflow,
file-integrity tests, privacy scans, and device failure containment.

### `SEC-012` - Owner-lab server-VPN boundary
**Contract:** System-server VPN virtualization is an owner-operated, best-effort tool with no
supported phone/build inventory or compatibility guarantee. It MUST be limited to eligible ordinary
applications in user 0 under the fixed packaged policy in `ARC-026` and the service-boundary
semantics in `API-018` through `API-020`. It MAY use only the fixed hidden Connectivity
implementation hooks required by that boundary; missing or changed runtime members MUST fail the
transaction without introducing fuzzy discovery.
It MUST NOT add application hooks, raw-Binder/JNI client interception, framework/APEX patching,
traffic or provider changes, root/Zygisk concealment, integrity bypass,
per-application enrollment, or claims against banking, payment, fraud, regional, account, or integrity
controls. Acceptance MUST retain the owner's VPN continuously ON and compare stock, active target,
active non-target, and rollback observations without requesting or automating a VPN-OFF epoch.

**Evidence:** Hook/config source audit, VPN-status epoch binding,
target/canary differential, data-plane checks, and bounded documentation wording.

### `SEC-013` - Server authorization and privacy
**Contract:** The server-VPN feature and its packaged runtime payload MUST contain no controller
APK, launcher UI, Binder service,
provider, receiver, socket, HTTP endpoint, live target editor, arbitrary root command, or
caller-selected path. The immutable production policy MUST be packaged in every supported module
ZIP and loaded automatically at boot; it MUST NOT depend on a host-private file or typed Make
activation workflow. Development automation may replace a candidate policy only inside explicit
non-production POC/recovery flows. The running VPN feature MUST never reread that file; staging a newer generation MUST not
disable, reconfigure, or impersonate the independently active location feature. Runtime status MUST be
read-only, bounded, and free of package inventory beyond fixed role labels, network objects,
capabilities, addresses, routes, interfaces, DNS, traffic endpoints, certificate bytes, and raw
framework dumps. Logs and retained evidence MAY contain only catalog/artifact digests, bounded
lifecycle stages, counts, stable role labels, and exception classes.

**Evidence:** ZIP/manifest/string inspection, configuration parser negatives, helper/IPC absence,
status schema tests, log scans, and recursive report privacy checks.

### `SEC-014` - Server failure and coexistence boundary
**Contract:** Before transactional activation, any descriptor, authorization, copy, or engine
failure MUST preserve stock Connectivity behavior. After activation, a per-call copy or shape
failure MUST return origin behavior only for that recipient without mutating shared state; engine or
catalog integrity failure MUST enter the inactive pass-through state in `ARC-027`. The module MUST
never disable the VPN, kill its provider, restart networking, clear system state, or conceal a
failure. Independent engine ownership is rejected by `ARC-029`; the server-VPN feature MUST use the
selected generic host and MUST never initialize, unhook, or release a second LSPlant/ShadowHook
owner. Before publication, either feature's failed activation MUST preserve stock behavior without
activating the other feature. Every object reachable by an incompletely rolled-back hook MUST remain
retained. After publication, location callbacks retain the fail-closed behavior in `SEC-009`, while
an inactive or rolled-back server-VPN transaction retains the stock/pass-through behavior in
`ARC-027`; one feature MUST NOT silently change the other's failure policy.

**Evidence:** Failure-injection model tests, provider/data-plane health, terminal status,
independent-owner control, accepted shared-owner transactional rollback, and crash/watchdog
inspection.
