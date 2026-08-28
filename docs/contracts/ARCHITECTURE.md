<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Architecture Contract

### `ARC-001` - Bounded product objective
**Contract:** ZygVeil MUST be one Magisk/Zygisk module with one hook-engine owner and
feature-isolated location and server-VPN transactions. Location MUST simulate one stationary
application-visible position. Server-VPN MUST virtualize only the covered Connectivity service
observations for explicitly authorized ordinary applications while leaving the real VPN, routing,
traffic, DNS, and provider operation unchanged. Neither feature MAY claim general concealment or
cross-feature activation authority.

**Evidence:** Supported component graph, fixed hook catalogs, independent feature status, and
feature-specific acceptance reports.

### `ARC-002` - Component ownership
**Contract:** `components/zygisk-host/` MUST own the single Magisk/Zygisk lifecycle and hook engine;
`components/location/controller/` MUST own only the standalone location controller;
`components/server-vpn/runtime/` MUST own server policy, fixed bridge/catalog inputs, immutable
configuration, native status, and the VPN transaction; and `components/probe/` MUST own the one
extensible primary/canary public-API oracle used by every current and future feature. Host
orchestration MUST live under `tools/automation/` behind `mk/*.mk`. Supported component code MUST
NOT exist at retired root paths or depend on `deprecated/`.

**Evidence:** `make topology-check`, Gradle project mappings, CMake paths, package namespaces, and
supported artifact inspection.

### `ARC-014` - Zygisk host
**Contract:** `components/zygisk-host/` MUST produce one ordinary Magisk/Zygisk module without a
device model, build fingerprint, hardware identifier, or compatibility allowlist. It MUST NOT
depend on an application-process hooking framework at runtime, patch framework files or the GNSS HAL, and MUST package only
`arm64-v8a`. The module MAY package its fixed native `locationctl` helper and control-page schema
metadata, but MUST NOT package or install the separate controller APK. Its embedded ART
mechanism MUST be built from the pinned source revisions and licenses owned by `AUT-012`.
Runtime class/member resolution is best-effort: this contract does not claim compatibility with any
phone or Android build, and a mismatch MUST follow the feature transaction's normal inactive or
stock failure path rather than a device-identity gate.

**Evidence:** Component source graph, combined module ZIP inspection, dependency manifest, and
the frozen combined-host build report.

### `ARC-015` - Zygisk lifecycle containment
**Contract:** When disabled or when the fixed runtime-ready/delivery-page inputs fail, `preAppSpecialize` MUST
install no hook, load no DEX, start no thread, open no persistent endpoint, perform no package logic,
and MUST request `DLCLOSE_MODULE_LIBRARY`; `postAppSpecialize` MUST then do nothing. Under an active
runtime, every application specialization MUST instead follow the unfiltered, bounded
application-delivery lifecycle in `ARC-023`. Only `system_server` MAY retain one initialization
thread and the writable runtime control-page mapping in `ARC-020`; only the existing root Zygisk
companion MAY retain the corresponding descriptor and its private server pidfd.
Pre-server work MUST be limited to boot configuration, fixed readiness and module-file reads,
retaining bounded bytes for ShadowHook's inert linker helper, one bounded companion-backed status
channel per compiled feature, and the control-page registration in `ARC-020`. The companion MAY
receive only the distinct fixed-token location and server-VPN status memfds and, after every active
location input is validated, the fixed control memfd. Each channel MUST validate its exact token,
feature-specific memfd identity, and descriptor identity before mapping or retention. Disabled and
failed pre-server paths MUST create no control page. Because Zygisk loads this module only after the target
process has forked and a new private pre-specialization descriptor cannot survive server FD cleanup,
the active pre-server path MUST create, size, seal, initialize, and map the control memfd, then
transfer its descriptor to the existing root companion and close the local descriptor before
specialization. The linker helper MUST be loaded from a fresh short-lived memfd only when
ShadowHook performs its linker scan after specialization; the adapter MAY normalize only the exact
`/memfd:libshadowhook_nothing.so (deleted)` name for the pinned XDL and `soinfo` lookup. All helper
and transient companion-channel file descriptors MUST close immediately after use. The active
server MUST retain only its writable mapping until process death; the companion MUST retain exactly
one authoritative control descriptor and one validated pidfd for the current live `system_server`.
Application specializations MUST retain neither descriptor nor a writable mapping; they MAY retain
only the read-only delivery mapping and hook state in `ARC-023`. Each initialization-status portion
MUST retain only its bounded shared-memory mapping until its feature-specific companion write
completes; neither channel may become a persistent endpoint.
The native ART engine MUST be initialized synchronously in `postServerSpecialize`, before that
callback lets the Java `system_server` startup continue, so its internal ART patches cannot race
concurrent framework class initialization. Framework class resolution and the five simulator hook
installations MUST then run on the deferred worker with a bounded deadline. JNI references returned
by the pinned hook engine MUST follow that engine's documented ownership rules. JNI allocation,
class/member resolution, and array construction failures MUST clear pending exceptions before
cleanup or thread detach and MUST NOT continue with a null JNI reference; an active per-event
transformation failure MUST drop that event under the fail-closed policy. A failed activation
transaction MUST deactivate fail-closed bridges, unhook every acquired method, and release every
module-owned JNI global reference before the initialization thread detaches. If the pinned engine
reports that an acquired hook could not be removed, the inactive runtime, backup bridge, JNI
references, mapping, and descriptor MUST instead remain retained in `system_server` until process
death; residual callbacks MUST invoke their original backup, status MUST remain inactive with
`control_fd=0`, and no freed bridge or runtime object may remain reachable.
The shared hook host MUST hold each bridge monitor across LSPlant publication and backup assignment;
a location callback that initially observes no volatile backup MUST acquire that monitor and read it
again before dispatch so acquisition remains origin-pass-through.
Any module thread-local storage retained for callback reentrancy MUST have at least 64-byte ELF TLS
alignment so the pinned ARM64 Bionic linker can load the Zygisk entry before specialization.

**Evidence:** Zygisk lifecycle source; exact current-artifact ELF and mapping comparison between
`system_server` and application processes; application thread/descriptor/bridge inspection; and
`make test-location-isolation`.

### `ARC-016` - Atomic activation and recovery
**Contract:** Location, GNSS status, NMEA, measurement filtering, and navigation-message filtering
MUST form one activation transaction. Hooks MUST remain passthrough while arming; configured
`blocked` activation MUST publish active status only after every required hook has a backup and the
bridge is ready. Any guard/config/signature/install failure MUST unhook acquired methods, leave stock
behavior, publish one exact inactive reason, and stop retrying after the bounded deadline. After
activation, Raw GNSS handlers MUST fail closed per event. The module MUST install enabled after its
fixed packaged runtime prerequisites validate and retain a Make-wrapped disable/reboot recovery route for
development and recovery only. A valid boot with no owner coordinates MUST install the complete
hook topology in origin-passthrough standby and expose the control plane required for the first
controller Apply; it MUST NOT claim active masking or transform the packaged placeholder.
`guard-status.properties` MUST use
exact fields `schema_version=1`, `state`, and `mismatches`; `runtime-status.properties` MUST use schema 4 fields
`state`, `reason`, `raw_gnss_mode`, `hook_count`, `system_server_pid`, `config_generation`, and
`boot_id`, plus `system_server_start_ticks`, `control_owner_pid`,
`control_owner_start_ticks`, and `control_fd`. Active status requires `hook_count=5`, positive server
and companion process start times and a companion-retained control FD, and exact agreement with the current boot,
`system_server` PID/start-time identity, boot configuration generation, and Raw GNSS mode.
Schema-4 `ready` status is the identity-bearing standby/active infrastructure state and requires
the same five-hook, process-owner, and control descriptor identity as active masking; the writable
control page is authoritative for `waiting` versus `active` masking. Other non-active status MUST
publish both process-owner fields and `control_fd` as zero. Live attestation MUST combine that
immutable boot status with the opened memfd and control-page boot/PID identity and its
published/applied generation; `runtime-status.properties` MUST NOT be rewritten for every live
update. A deleted-memfd pathname or descriptor number alone is diagnostic only and MUST NOT be used
as the active identity. Failure and arming status MUST NOT claim partial coverage.
The root companion status channel MUST accept only a complete coordinate-free schema-4 body whose nonempty reason
is at most 256 printable ASCII bytes and contains neither an additional `=` nor coordinate/NMEA
fields, serialize atomic mode-0644 status replacements under a root-owned mode-0600 lock, and
revalidate the originating live `system_server` PID and the proc-stat start ticks captured in its
private status channel while holding that lock. It MUST use one fixed same-directory temporary name
recoverable by the next serialized writer. File and directory `fsync` are required. The
initialization worker and companion MUST atomically claim one terminal activation outcome: a
companion timeout MUST force hook rollback and prevent late activation, while a committed activation
MUST never be overwritten by timeout status. The retained inactive pass-through fallback in
`ARC-015` is required only when the native engine reports that unhook itself failed. A retired
companion from a dead or PID-reused server process MUST NOT overwrite the status of a newer server
process. Because the companion request begins before server specialization, the companion MUST wait
for a bounded interval shorter than the worker-ready deadline until the unchanged PID/start-time
identity reports the exact `system_server` command, then revalidate that identity under the status
lock before the initial durable write. Activation MUST additionally wait for a bounded
companion-ready acknowledgement after that write; a missing, invalid, or failed companion handshake
MUST claim timeout and prevent hook activation.

**Evidence:** Activation state tests, runtime status, hook rollback source, first-Apply,
disabled-boot, and recovery device runs.

### `ARC-017` - Shared stationary model
**Contract:** Every `Location` in each incoming `LocationResult` MUST be copied and transformed by
one process-wide deterministic stationary state before last-location caching, permission-dependent
coarsening, passive propagation, and listener delivery. The model MUST use correlated east/north,
vertical, and accuracy processes; radial clamping; provider-aware accuracy; synthetic displacement
for speed; thresholded bearing; preserved provider/mock/extras and valid timestamps; consistent
ellipsoid/MSL altitude; and finite, complete output. It MUST never reuse physical position, motion,
altitude, bearing, or accuracy fields after activation. East/north MUST use
`rho=exp(-dt/tau)` and `offset=rho*previous+sigma*sqrt(1-rho^2)*normal`, followed by radial clamp and
local WGS84 conversion. Current accuracy bounds MUST be GPS 3-12 m, fused 4-20 m, network 20-150 m,
passive 4-30 m, and unknown providers 5-50 m. Speed MUST be low-pass filtered, deadbanded, and
clamped; bearing and bearing accuracy MUST be jointly absent below `bearing_min_speed_mps`.
Local conversion MUST reflect latitude across either pole and rotate/normalize longitude so every
sample remains in `[-90,90]` latitude and `[-180,180]` longitude, including centers exactly at a
pole.
The same model mutex MUST own a live reconfiguration operation that accepts only a complete,
validated, strictly newer generation with unchanged boot fields. Reconfiguration MUST atomically
replace the center and both configured altitudes; reset east/north/vertical/accuracy state, filtered motion,
bearing, latest sample, Gaussian spare state, generation-derived deterministic PRNG state, and NMEA
sequence; and retain only the elapsed-time floor required for monotonic output. Its initialized
latest sample MUST use the new center so a status or NMEA callback arriving before the next
`LocationResult` cannot reuse the prior generation. Each transformed batch or GNSS/NMEA callback
MUST consume one coherent model generation.

**Evidence:** `LocationModel`, deterministic host tests, target hook signature, and location probe
sessions.

### `ARC-018` - GNSS consistency and Raw firewall
**Contract:** Upstream GNSS status and NMEA cadence MAY trigger output, but active output MUST use
the shared synthetic sample and deterministic satellite model. `blocked` MUST preserve registration
and capability reporting while dropping both measurement and navigation-message events at the
application-listener dispatch boundary. `passthrough` MUST be explicit diagnostics with a physical
observation warning. `unsupported` MUST be rejected until its target behavior is implemented and
validated; the module MUST NOT synthesize raw measurements, navigation bits, or capability absence.
The current status model MUST expose 16 valid GPS-constellation satellites, 10 used in fix, with
ephemeris/almanac/carrier/baseband fields and slowly time-varying azimuth/elevation/C/N0. One
upstream NMEA callback MUST deliver one item from a deterministic GGA/RMC/GSA/GSV sequence, never a
timer-generated burst.
At every one of the five hook entries, the runtime MUST check `ARC-020` before consuming model state.
The first upstream event that observes a valid newer generation MUST apply it before transformation;
that event and all later events MUST use the new generation. Publication alone MUST NOT synthesize a
location, status, NMEA, measurement, or navigation callback.

**Evidence:** Exact hooks in `API-009`, model/NMEA tests, structured runtime status, and Raw GNSS
probe counts.

### `ARC-019` - Boot and live configuration
**Contract:** Location configuration MUST use schema 1, validate every finite range and enum before
arming, and default to `enabled=false` and `raw_gnss_mode=blocked`. In the packaged configuration,
`enabled=false` means only that the owner has not yet supplied the first coordinates; it is not a
production feature switch. Every field is required and an unknown field MUST reject activation:

```text
schema_version enabled raw_gnss_mode
center_latitude_deg center_longitude_deg
altitude_ellipsoid_m altitude_msl_m
horizontal_jitter_sigma_m horizontal_jitter_radius_m horizontal_correlation_time_s
vertical_jitter_sigma_m accuracy_correlation_time_s
speed_deadband_mps speed_max_mps bearing_min_speed_mps
random_seed config_generation
```

Latitude/longitude MUST be finite in `[-90,90]`/`[-180,180]`; both altitudes MUST be finite in
`[-12000,100000]` metres; horizontal jitter sigma/radius and vertical jitter sigma MUST be finite in
`[0,10000]` metres; correlation times MUST be finite in `(0,86400]` seconds; speed values MUST be
finite in `[0,1000]` metres per second; speed thresholds MUST satisfy
`deadband <= bearing threshold <= maximum`; seed MUST be unsigned 64-bit; generation MUST be a
positive, monotonically replaced integer in `[1,2^62-1]` so the shared acknowledgement token can
encode its state without wrap. Schema 1 accepts only `blocked` and diagnostic `passthrough`;
`unsupported` is a recognized but rejected target generation.

`raw_gnss_mode`, all jitter/correlation/speed/bearing parameters, and `random_seed` are
boot-immutable. `enabled` permits exactly one live `false` to `true` transition made by the first
valid controller Apply; `true` to `false` is invalid, and no production command or UI may request
it. Changing any other boot field requires an atomic mode-0600 persistent write while the Magisk
module is disabled and a controlled reboot. The installed device boot configuration uses the
complete key set above.
The private host input consumed by `location-set` MUST use the same exact key set except `enabled`
and `config_generation`, and MUST reject either supplied field as unknown. Automation MUST preserve
the installed one-way `enabled` state and owns boot-generation assignment: it MUST validate the
currently installed complete configuration, compare all input-owned fields, leave an identical
configuration byte-for-byte unchanged with its current generation, and assign exactly `current + 1`
only when content changes.
It MUST reject generation exhaustion before writing and MUST NOT derive a generation from a clock,
random value, filename, or manually maintained host state.

Only latitude, longitude, ellipsoid altitude, and MSL altitude are ordinarily live-mutable;
`config_generation` is assigned by the helper and MUST strictly increase. A live request MUST
publish a complete schema-1 configuration and MUST be rejected if any boot-immutable field differs
from the armed configuration. The first valid request MUST additionally set `enabled=true` in that
complete configuration. Every later request MUST retain it as true. A valid live request MUST first atomically persist the complete
mode-0600 configuration and then publish it to the current boot. Repository examples MUST contain
only synthetic placeholders; host-side private configuration MUST remain below ignored `.state/`
with mode 0600. A normal module update MUST preserve an existing valid persistent configuration so
the one-way activation survives product upgrades. Magisk module enablement and Raw GNSS mode remain
boot-only; hook installation occurs in both waiting and active production states.

**Evidence:** Configuration parser/tests, example, ignore rules, and Make config/status targets.

### `ARC-020` - Live control page
**Contract:** The only authoritative current-boot runtime-control state resource MUST be an anonymous
memfd named `zygveil-location-control`, created in the active pre-server path with close-on-exec and
sealing enabled after every boot/configuration/guard input is validated. It MUST be an exact 4096-byte,
root-owned `0:0`, kernel-created mode-0777, zero-link regular file with exactly `F_SEAL_GROW`,
`F_SEAL_SHRINK`, and `F_SEAL_SEAL`; no path may attempt an SELinux-forbidden mode change. The inode
mode is an identity invariant, not an authorization boundary: the fixed Zygisk companion channel,
root-owned status path, procfs process-access checks, SELinux, exact descriptor/page attestation,
and root-only helper provide access control. Before server specialization, the module MUST initialize
and map the page read-write, transfer the descriptor through one fixed-token SCM_RIGHTS registration
to the existing root Zygisk companion, validate the companion's bounded receipt, close the local
descriptor, and retain only the writable mapping. The companion MUST retain exactly one descriptor
for the authoritative control page plus one private validated pidfd for the current live
`system_server`, and replace them only after the prior monitor has completed and an attested newer
server registers. Application processes MUST never receive either descriptor. The POC/production
application delivery path in `ARC-023` MAY additionally use one derived root-owned `.app-control`
file and read-only application mappings as specified below. No module-owned daemon, application
socket, or additional persistent resource may retain the authoritative memfd. A separate zero-length
`.locationctl.lock` MAY persist only as helper synchronization metadata and MUST carry no
configuration or runtime state. Helpers MUST serialize on its whole-file POSIX `fcntl` write lock
with interruption-safe retry.

Schema-4 runtime status MAY expose only the companion-owned control descriptor number together with
attested boot, `system_server` PID/start-time identity, and companion PID/start-time identity. A root
helper MAY follow exactly one internally constructed
`/proc/<attested-companion-pid>/fd/<attested-control-fd>` link; no caller may supply any part of that
path. Before and after mapping, it MUST validate both live process identities, runtime status file
identity/schema, exact deleted-memfd name, root UID/GID, mode, zero link count, size, exact seals,
read-write access, and mapped page identity. This fixed helper proc-descriptor link is the only
symlink-following exception in the control path.
The pidfd number MUST remain companion-private and MUST NOT appear in runtime status, helper output,
application state, or reports; focused smoke MAY report only the count and mechanism label.

The same companion control-registration handler MAY retain one bounded monitor execution for the
live `system_server`. It MUST acquire-read only the authoritative page's applied generation and
mirror complete valid generations into exactly one `.app-control` file in the fixed module
directory. That file MUST be a root-owned `0:0`, mode-0600, single-link, exact 4096-byte regular file
opened with `O_NOFOLLOW`; it is derived current-boot transport, never configuration authority. The
monitor MUST initialize it while the source is arming, publish it as `waiting` after the
authoritative page reaches waiting, and release-publish it active when the authoritative page is
active. For the one-way first activation it MAY mirror the complete validated pending generation so
already-running applications can arm without a restart, but the derived page MUST remain `waiting`
and MUST NOT acknowledge that generation until the authoritative page is active. After activation
it may copy only strictly newer applied generations with the same boot-field digest. It MUST mark the file inactive when the
source/server dies or validation fails and retain no historical generation resource.

Every application pre-specialization MUST open that fixed file read-only through its already
validated module-directory descriptor, with no companion call. It MUST validate read-only access,
exact root ownership/mode/link/size, map it `PROT_READ`, prove that write upgrade is unavailable,
close the descriptor before specialization, and then validate page schema, boot ID, live
`system_server` PID/start time from schema-4 status, boot configuration generation, applied slot,
and armed boot-field digest. Any race, stale file/page, mismatched identity, or failed validation
MUST close transient resources and fail without hook activation. The monitor/file are bounded
delivery infrastructure only: applications receive no authoritative pending generation or helper
acknowledgement state.

The page MUST contain two fixed-size configuration slots, a release-published 64-bit generation,
and a release-published acknowledgement with `pending`, `applied`, or `rejected` state and a bounded
non-coordinate reason code. Slot storage MUST be an explicitly typed array of lock-free 64-bit
atomic words; access through an aliasing pointer to an unrelated structured payload type is invalid.
A waiting page MUST accept only a complete, strictly newer `enabled=true` generation whose other
boot fields match. An active page MUST reject every `enabled=false` generation. A publisher MUST
serialize helpers, fully write the slot selected by
generation parity, store a checksum over the fixed wire payload, and release-publish its generation
last. A reader MUST acquire-load the generation, copy and validate the selected slot, then
acquire-reload the generation and accept only an unchanged value. Partial writes, invalid checksum,
identity mismatch, generation regression, wrap, or boot-field mismatch MUST leave the last applied
model active and publish only a rejection code when it is safe to do so.

`config.properties` is authoritative across reboot. The helper MUST replace it using one fixed
same-directory mode-0600 temporary file, file `fsync`, atomic rename, and directory `fsync` before
publishing the page. The next serialized helper MUST validate and remove an owned single-link stale
temporary file left by an interrupted predecessor and MUST reject any other identity. A helper
death before rename changes nothing; a death after rename but before
publication leaves the persisted generation to be loaded on reboot or republished by a later valid
request. Each valid boot MUST create a fresh page from the validated boot configuration. A missing,
stale, reused, or corrupt runtime page MUST never prevent the next boot; after activation, an invalid
publication MUST retain the last applied model and MUST never disable active hooks.
If a rejected published generation remains persistent because the helper died or could not
durably complete its rollback, redacted status MUST report `recovery_required`, never ordinary
`rejected` or an accepted pending state. The active runtime MUST retain its last applied generation;
an explicit newer update, reboot into the valid persistent generation, or the documented disable
recovery route is then required.
`persisted_runtime_rejection` and `rollback_failed` MUST describe
`persisted=published>applied`; `rollback_persistence_uncertain` MUST describe
`published>persisted=applied` after the old configuration was renamed back but its directory
durability could not be proven; and `persistence_uncertain` MUST describe
`persisted>published=applied` after the candidate was renamed into place but its directory
durability could not be proven. The helper MUST publish both uncertainty recovery markers into the
page so later status calls preserve them for the remainder of the boot.

**Evidence:** Shared protocol header/static assertions, parser/protocol concurrency and corruption
tests, helper tests, runtime attestation, and recovery device runs.

### `ARC-021` - Controller and root-helper boundary
**Contract:** `components/location/controller/` MUST build one ordinary APK with package
`dev.zygveil.location.controller`, version code 1, version name `0.1.0`, and label
`ZygVeil Location`. It MUST have no production/probe project dependency, Internet or
Android location permission, analytics, hook-framework/native-module dependency, exported privileged
service/receiver/provider, or background component. Its exported launcher activity MAY initiate
only the fixed `status`, `status-ui`, and `apply` helper flows and MUST accept no coordinate, path,
or command input from intents. The fixed external root-request action MUST select only redacted
`status`; all other external actions and every extra MUST be ignored.

The APK MAY request Magisk root only by executing the constant commands
`/data/adb/modules/zygveil/locationctl status`,
`/data/adb/modules/zygveil/locationctl status-ui` and
`/data/adb/modules/zygveil/locationctl apply`. The latter MUST receive bounded
schema-1 decimal coordinate/altitude input through stdin; no user value may enter a command argument,
environment variable, intent, log, exception, or status report. `locationctl status` MUST be
redacted for automation, while `status-ui` MAY return the configured synthetic coordinates only to
the local controller process. Every active helper response MUST bind the current boot and
`system_server` PID/start-time identity; an identity-free failure envelope MUST set both process
fields to zero. The external root-request flow MUST atomically replace one redacted, single-link
mode-0600 status file in no-backup app-private storage; it MUST contain no coordinates.
Coordinate fields in `status-ui` MUST use fixed decimal notation, omit binary64 expansion artifacts,
and stay within the controller's eight-fraction-digit coordinate and three-fraction-digit altitude
limits. Rendering this UI-only view MUST NOT mutate the persisted or applied configuration.
The helper MAY resolve the control memfd only through the fixed, current-boot schema-4 runtime-status
and companion proc-descriptor flow in `ARC-020`; the controller MUST NOT select a PID, descriptor,
or path. Presets MUST remain in no-backup app-private storage.
The packaged helper MAY additionally expose a direct root-only, no-input `protocol-self-test`
diagnostic; the controller, exported root-request action, and ordinary live-control automation MUST
NOT invoke it. A coordinate-bearing response to `status` or `apply` MUST be rejected as a protocol
failure. Superseded or destroyed activity operations MUST NOT update controller UI state.
The UI MUST distinguish upstream-pending, reboot-pending, rejected, and recovery-required states;
it MUST also render a non-error `waiting for first coordinates` state and keep Apply available in
that state. The first successful Apply MUST be sufficient to persist and activate location masking;
the controller MUST expose no disable or re-arm action. Neither the controller nor helper may
require ADB, Make, repository state, or a host-generated private input for normal use.
coordinate editors MUST be explicitly excluded from Autofill and associated with their visible
labels. Every parsed helper response and exit code MUST agree on success or the exact supported
failure class; an `apply` response and exit code MUST additionally agree on accepted versus
rejected/recovery state. A failed preset write MUST leave the prior in-memory and on-disk list
unchanged.

**Evidence:** Controller source and APK inspection, fixed-command tests, helper identity/input tests,
manifest/dependency checks, and supported Magisk grant workflow.

### `ARC-022` - Application-delivery POC
**Contract:** A non-attestable application-delivery POC MAY be compiled only by the explicit
canary-first workflow in `AUT-016`. The build option MUST default to disabled, the ordinary
`location-build` artifact MUST contain no POC application path, and POC outputs MUST remain below
`.artifacts/poc/`; they MUST NOT enter `dist/`, `VALIDATION.md`, release inspection, reproducibility,
or acceptance evidence.

When compiled, the POC MUST retain the Zygisk module and attempt the same fixed hook in every
application specialization. It MUST NOT inspect or filter application ID, UID, package name,
process name, `nice_name`, data directory, signing identity, foreground state, or caller-supplied
target list. The retained path MUST validate the same waiting or active persisted configuration and
fixed runtime-ready marker as `system_server`, read only the already packaged bridge and linker-helper bytes
before specialization, initialize synchronously after specialization, and install only the exact
boot-class parcel-creator hook in `API-015`. It MUST create no thread, control page, companion
request, retained socket, Binder endpoint, or file watcher; it MAY retain only the read-only derived
mapping in `ARC-020`.

This POC is deliberately fail-open and non-attestable, but it MUST exercise the same read-only
shared-generation delivery page as `ARC-023`; it MUST leave the application running with origin
behavior if any input, ART, bridge, or hook step fails. A
working POC establishes only that the application delivery boundary closes the measured canary and
Google Maps escape in that observed session. The ordinary module MUST compile the same hardened
shared-generation path unconditionally with the production failure semantics in `ARC-023`. The POC
definition MAY select only fail-open application-callback behavior and POC lifecycle labels; it
MUST NOT enable or disable the global path, delivery page, companion monitor, pidfd binding, hook
signature, or configuration semantics.

The observed Zygote SELinux domain cannot independently inspect the live
`/proc/<system_server>` command line during application pre-specialization. Before creating the
derived page, the root companion MUST therefore bind the attested server PID/start-time pair to a
CLOEXEC kernel pidfd, validate its exact `anon_inode:[pidfd]` identity, and revalidate the start-time
pair around `pidfd_open`. The companion monitor MUST use pidfd readiness rather than PID polling to
mark the page inactive when that exact process dies. Applications MAY validate current boot ID,
root-owned schema-4 status, active derived-page state, server PID/header, boot generation/digest,
applied slot, and checksum; they MUST neither receive nor open the pidfd. Promotion to `ARC-023`
requires focused host and runtime-session proof that this non-procfs application-side liveness binding
works before the production failure semantics are enabled.

**Evidence:** Compile-definition inspection, ordinary/POC ELF comparison, fixed-method DEX inspection,
absence of application selection logic, POC-only Make outputs, and the focused canary
session.

### `ARC-023` - Global application delivery and shared generation
**Contract:** An enabled ordinary module MUST retain its native runtime in every Android
application specialization without inspecting or filtering application ID, UID, package, process
name, `nice_name`, data directory, signature, foreground state, or caller identity. Before
specialization, each application MUST validate the fixed runtime-ready marker, open and validate the fixed derived
delivery file in `ARC-020` read-only, map it read-only, read the already packaged bridge and
linker-helper bytes, and close every file descriptor. After specialization it MUST initialize ART
synchronously, install exactly `API-017`, and retain only the native library, bridge and hook
references, one read-only
4096-byte mapping, and model state. It MUST create no application thread, writable mapping, retained
descriptor, companion request/endpoint, Binder endpoint, file watcher, or per-package state.

Applications MUST validate the immutable page identity, current live `system_server` PID/start
identity, waiting-or-active state, applied generation, slot checksum, boot fields, and decoded
complete configuration before installing the hook. A waiting application MUST install the hook in
origin-passthrough standby and retain it so the first valid generation can activate without an
application restart. The derived page MUST mirror the authoritative `ARC-020` generations according
to its one-way activation rule and MUST never expose an `enabled=false` generation as active.

Before creating or activating the derived page, the root companion MUST open a CLOEXEC pidfd for
the exact attested server PID, revalidate the expected start-time ticks before and after that open,
validate the exact `anon_inode:[pidfd]` descriptor identity, and retain it beside the authoritative
control descriptor. The single monitor MUST make the derived page inactive on pidfd readable,
hang-up, error, or invalid state; it MUST reject a second registration while the first exact server
is live and close both retained descriptors after that server exits. Applications MUST never
receive, open, poll, or retain the pidfd.

Production application initialization MUST activate the bridge's fail-closed state after the exact
hook is installed and before the native runtime becomes active. In waiting state the bridge MUST
remain fail-open and call the original creator; the first callback that observes an active delivery
generation MUST reconfigure the model and activate fail-closed before transforming that same
callback. A missing or invalid delivery
mapping before hook installation MUST leave the process on stock behavior and unload the module.
Once the hook is active, loss of page identity or active state MUST suppress that callback rather
than return the original physical object; a corrupt or rejected newer slot MAY continue using only
the last complete valid synthetic generation.

For a live update, the existing publisher MUST leave `applied_generation` unchanged while a complete
candidate is pending. The server MUST release-publish the new applied generation only after its
model accepts that candidate. Every hooked application MUST acquire-read only that applied
generation on parcel callbacks, atomically reconfigure to a valid strictly newer generation, and
otherwise retain its last valid synthetic generation. The persisted configuration remains
authoritative across reboot; the sealed memfd is bounded current-boot transport, not additional
configuration authority or acceptance evidence. The derived application file is likewise bounded
delivery state and never becomes authority.

**Evidence:** Shared protocol/unit tests, exact authoritative-memfd and derived-file mapping identity,
application lifecycle and negative-selection inspection, live-generation main/secondary canary
sessions, and recovery.

### `ARC-024` - System-server VPN backend
**Contract:** Hook-free code under `components/server-vpn/runtime/` MUST implement the Zygisk backend that
virtualizes covered VPN observations at the Connectivity service boundary inside `system_server`.
Its packaging and engine host MUST follow the evidence-backed outcome in `ARC-029`: a
feature-isolated payload inside the one generic Magisk host under `components/zygisk-host/`. A
separate server-VPN Magisk/Zygisk artifact and an application-process VPN backend are forbidden on
the supported graph. Installing/enabling the selected host MUST activate the complete VPN catalog
automatically after the next reboot using the immutable packaged production policy; it MUST require
no controller, ADB/Make action, host-private input, target enrollment, launcher UI, live arm switch,
or application-process configuration channel.

**Evidence:** Component dependency inspection, distinct feature payload identities, boot lifecycle
tests, and server-VPN Make target dependency graphs.

### `ARC-025` - System-server-only lifecycle
**Contract:** The selected host's application branch MUST perform no server-VPN package selection,
bridge loading, hook work, thread creation, or endpoint creation. The shared host MAY continue only
the location application lifecycle in `ARC-023`. Only the `system_server` specialization MAY
load the VPN bridge, resolve the
Connectivity catalog, install its hooks, and publish VPN status; VPN bridge classes,
configuration, hook state, threads, and status identities MUST be absent from every application
process. A missing fixed runtime-ready marker before server specialization MUST remove any
server-VPN status left by an earlier boot; `guard-status.properties` is authoritative for that
failure because a current server status cannot be bound before the new `system_server` exists.

**Evidence:** Zygisk lifecycle tests, maps/FD/thread inspection for server and application roles,
fixed identity allow/deny lists, and target/canary process isolation reports.

### `ARC-026` - Server target authorization
**Contract:** Server-side transformation MUST use one root-owned, non-symlink, single-link packaged
policy of at most 8192 bytes. It is immutable product input, not owner configuration. Schema 2 MUST
contain exactly the following property keys; leading printable-ASCII `#` metadata lines, including
the repository license header, are ignored and MUST NOT enter the parsed property set:

```text
schema_version backend_id catalog_version config_generation target_mode
```

`schema_version` MUST equal 2, `catalog_version` MUST equal 1, and `target_mode` MUST equal
`eligible_user0_apps`;
`backend_id` MUST equal `zygveil_server_vpn`; `config_generation` MUST be in `[1,2^62-1]`. Missing, duplicate, unknown,
non-printable, oversized, or malformed fields MUST reject the complete VPN transaction. At every
service boundary a caller MUST resolve in user 0 to exactly one ordinary non-shared application
package and its authoritative package claim, when present, MUST match. Unknown packages, shared
UIDs, system/updated-system/privileged applications, stale UID-to-package bindings, the exact VPN
provider, ZygVeil controller, universal canary control, and framework/root managers MUST receive
stock behavior. No production allowlist, certificate enrollment, or per-application activation is
permitted. Authorization MUST be recomputed when package or UID identity changes.

**Evidence:** Configuration parser and authorization model tests, PackageManager identity capture,
negative fixtures, and target/canary device sessions.

### `ARC-027` - Transactional runtime activation
**Contract:** The fixed server-VPN hook catalog, hook-engine revision, class loaders, classes,
methods, fields, and copy mechanisms required by the server-VPN transaction MUST resolve before
activation. There is no phone/build compatibility gate and no compatibility guarantee. Hook
acquisition MUST be all-or-none. After server
specialization begins, discovery or installation failure MUST leave stock service behavior and
publish a terminal coordinate- and network-value-free failure status. The earlier boot-guard
rejection is instead represented exactly as specified by `ARC-025`. A later failure MUST atomically switch every reachable hook to
pass-through, then unhook in reverse order; if unhook cannot be proven complete, all reachable
runtime objects MUST remain retained and inactive until `system_server` exits. Install, enable,
disable, recovery, and rollback development targets MUST use explicit reboot boundaries, while
status is read-only. These targets MUST NOT define or gate the production user activation lifecycle
in `ARC-024`.
All installed bridges MUST consult one global volatile activation gate. The runtime MUST commit the
single terminal activation claim before flipping that gate once for the complete catalog; it MUST
never enable bridge instances sequentially. Rollback MUST clear the same gate before reverse unhook.
For each acquired hook, the shared host MUST allocate retained target/bridge references and hold the
bridge monitor from before LSPlant publication through backup assignment. A server-VPN callback that
observes an unset volatile backup MUST acquire that same monitor and read it again before dispatch;
once the backup is present, ordinary callback execution MUST remain monitor-free. Therefore no
published server-VPN callback may transform or fail an origin invocation merely because installation
has not yet returned its backup method.
Catalog resolution MUST use `AccessibleObject.setAccessible(boolean)` after fixed
class/member/type/modifier validation and MUST NOT introduce a fuzzy API or signature fallback.

The read-only `server-vpn-runtime-status.properties` file MUST be atomically replaced as root-owned
mode `0644` schema 1 data with exactly these fields: `schema_version`, `feature`, `state`, `reason`,
`system_server_pid`, `system_server_start_ticks`, `boot_id`, `artifact_generation`,
`config_generation`, `catalog_version`, `catalog_hook_count`, `hook_count`, `target_set_sha256`,
`engine_owner`, and `owner_generation`. An active record MUST bind
the current boot/PID/start tuple, nonzero configuration and target digest, the selected shared
owner, and all 14 catalog hooks; every non-active record MUST report zero installed hooks. Its
companion channel MUST be a sealed private memfd with one terminal claim, bounded waiting, stale
PID rejection, a root-owned mode `0600` lock, fixed temporary path, and durable replacement; it may
publish status but MUST NOT accept commands. Durable automation reports MUST hash the raw boot ID
and omit target package and certificate values.
If the main companion wait expires after the runtime has committed its terminal activation claim,
the companion MUST use a separate bounded commit-grace wait. A still-delayed committed transaction
MAY publish `arming/0`, but MUST NOT publish `inactive/0` because the global gate can still flip.

**Evidence:** Fixed catalog and artifact inspection, transactional hook tests, failure injection,
read-only status checks, and disabled/active/recovery device reports.

### `ARC-028` - Detached service-boundary data flow
**Contract:** The server-VPN backend MUST determine the authoritative caller or registration owner
at the service boundary before identity is cleared or work is deferred. It MUST transform only
detached request or result copies and MUST never mutate a caller object, service-owned cache,
shared callback payload, network agent state, routing, DNS, sockets, or the data plane. Each
synchronous result and asynchronous delivery MUST be independently projected for its resolved
recipient. At the two exact asynchronous egress hooks it MAY replace the current invocation's
`NetworkAgentInfo` argument with one eligible donor reference, without editing either agent, so the
original service code remains solely responsible for constructing and redacting the recipient's
detached Bundle or Intent. A per-call Binder identity is valid only for that synchronous/ingress
invocation; no process-global or thread-global "current caller" state may authorize deferred work.

**Evidence:** Hook-free policy/copy tests, mixed target/non-target concurrency tests, service cache
identity checks, callback ownership tests, and data-plane preservation.

### `ARC-029` - Hook-engine ownership and coexistence
**Contract:** One generic host under `components/zygisk-host/` MUST initialize LSPlant/ShadowHook
once and
dispatch feature-isolated location and VPN bridges, catalogs, activation transactions, status, and
rollback. The independent-owner configuration is unsupported because focused runtime evidence
showed that enabling its second owner destabilized an otherwise stable disabled boot. A separate
server-VPN Zygisk module therefore MUST NOT be built, installed, or accepted. The supported shared
owner is the supported combined-host architecture. Every activation, deactivation, or rollback
loop MUST select only records owned by that feature; delayed first-coordinate location activation
MUST never invoke a location bridge method on a server-VPN record. Acceptance of a combined
generation MUST bind all five location hooks, all 14 server-VPN hooks, transactional rollback,
stable `system_server`, application-process isolation, and absence of a second engine/helper
identity. Any shared-engine or common-host runtime change is a shared retest trigger under
`VAL-009`; exact accepted generations and closures belong only in `VALIDATION.md`.

**Evidence:** Independent-owner disabled/enabled control, accepted shared-owner location and VPN
transactions, stable process/mapping inspection, rollback, and location coexistence closure.

### `ARC-030` - ZygVeil product identity
**Contract:** The repository and product MUST use the canonical name `ZygVeil`, repository slug
`zygveil`, owned Java namespace root `dev.zygveil`, generic host directory
`components/zygisk-host/`, Magisk module
ID `zygveil`, release ZIP `dist/zygveil.zip`, and common native SONAME `libzygveil.so`. The one
Magisk ZIP MUST carry independently reported `location` and `server_vpn` feature transactions
through the single hook-engine owner in `ARC-029`. Location owns persistent owner coordinates;
server-VPN owns only its immutable packaged production policy. Those features
MUST NOT communicate through feature-to-feature IPC or require one another to activate. Supported
source, automation, contracts, runbooks, artifacts, and acceptance MUST use only the canonical
identity. Obsolete product-identity literals are permitted only inside the excluded `deprecated/`
source archive and the explicit negative scanner/test denylist that proves they are absent
everywhere else; those literals MUST NOT become an active path, package, artifact, command, report
identity, or acceptance input.

**Evidence:** Product-identity source scan, Gradle/package and Magisk ZIP inspection, deprecated-tree
exclusion, and complete renamed location/server-VPN acceptance.

### `ARC-031` - Deprecated source boundary
**Contract:** `deprecated/lsposed-vpn/` MAY retain the retired libxposed module, policy model, and
their former automation only as source archaeology. It MUST be absent from root Gradle settings,
dependency resolution, source transport, formatting, lint, unit tests, Make targets, device
automation, release artifacts, compatibility claims, security claims, and current acceptance.
Supported automation MAY inspect only the `deprecated/` boundary path and its root README to prove
this exclusion. The repository-wide privacy scanner MAY additionally perform a content-blind
forbidden-pattern scan below `deprecated/`; no other supported automation may read or inspect the
archived implementation. Supported code MUST NOT import, build, install, scope, or execute that
tree. Historical evidence MAY remain only when explicitly labelled superseded and MUST NOT satisfy
a current gate.

**Evidence:** `make topology-check`, root Gradle and Make graphs, container source manifest, and
`deprecated/README.md`.
