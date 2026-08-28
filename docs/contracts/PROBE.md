<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Probe Contract

### `PRB-001` - Independent adversarial application
**Contract:** The probe MUST attempt to detect VPN through every calibrated public API signal and
observe location/GNSS through the public APIs owned by `PUBLIC_API.md`; it MUST remain separate from
the production module and controller. It MUST NOT depend on production classes, shared UID, shared
signature permission, root, hidden APIs, package inventory, accessibility, device administration,
or a `VpnService`.

**Evidence:** `components/probe/` dependency graph and manifest, source ownership inspection, and
production artifact DEX checks.

### `PRB-002` - Two controlled variants
**Contract:** Primary `dev.zygveil.probe.primary` and canary `dev.zygveil.probe.canary` MUST use one
extensible source graph and different application IDs. Every location, server-VPN, or future oracle
group MUST be implemented in this project and use its common lifecycle/schema framework; a
feature-specific probe project or application ID is forbidden. Location
build/acceptance MUST select only the location-source identity and schema-4 sessions. The canary
MUST additionally contain only the public Google Play services location adapter in `PRB-013`; the
primary MUST remain free of that dependency so it is an independent Android `LocationManager`
baseline. Their exports are
`dist/zygveil-probe-primary-debug.apk` and `dist/zygveil-probe-canary-debug.apk`; the normalized
detector hash is `dist/probe-detector-source.sha256`. Both MUST use version code 1, version name
`0.2-probe`, compile/min/target SDK 36, and exactly `ACCESS_NETWORK_STATE`, `INTERNET`,
`CHANGE_NETWORK_STATE`, `ACCESS_COARSE_LOCATION`, `ACCESS_FINE_LOCATION`, `FOREGROUND_SERVICE`, and
`FOREGROUND_SERVICE_LOCATION` Android permissions. The canary MAY additionally request only its
GMS-generated package-local signature permission
`dev.zygveil.probe.canary.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`; the primary MUST NOT contain
it. The canary manifest MAY additionally contain only the dependency-owned non-exported
`com.google.android.gms.common.api.GoogleApiActivity`; every project-owned component and its
exported state MUST otherwise exactly match the primary manifest boundary.

**Evidence:** `make build-probe`, artifact inspection, and primary/canary module matrix roles.

### `PRB-003` - Status and verdict model
**Contract:** Each stable detector ID MUST emit exactly one of `POSITIVE`, `NEGATIVE`,
`INCONCLUSIVE`, `UNAVAILABLE`, or `ERROR`. The app-side raw verdict MUST be `VPN_DETECTED` when any
mandatory detector is positive, `NO_PUBLIC_VPN_SIGNAL` when at least one mandatory detector is
negative and no mandatory detector has another status, and `INCONCLUSIVE` otherwise. Host acceptance
MUST additionally require the exact catalog, complete cleanup, and no detector `ERROR` before using a
run as evidence. `NO_PUBLIC_VPN_SIGNAL` MUST NOT be described as proof that no VPN exists.

**Evidence:** `ProbeStatus`, `ProbeRecord`, host parser schema checks, and native/module summaries.

### `PRB-004` - Exact detector catalogs
**Contract:** The synchronous group MUST contain exactly 28 IDs: fourteen `sync.active` capability
and getter observations, seven `sync.all` observations, four `matcher.*` cases, and three independent
`legacy.*` cases. The exact synchronous IDs are:

```text
sync.active.transport.vpn
sync.active.capability.not_vpn
sync.active.capabilities.not_vpn
sync.active.transport_info.vpn_token
sync.active.caps_string.vpn_token
sync.active.getter.down_kbps
sync.active.getter.up_kbps
sync.active.getter.signal_strength
sync.active.getter.owner_uid
sync.active.getter.enterprise_ids
sync.active.getter.network_specifier
sync.active.getter.subscription_ids
sync.active.copy.consistency
sync.active.parcel.consistency
sync.all.transport.vpn
sync.all.capability.not_vpn
sync.all.capabilities.not_vpn
sync.all.transport_info.vpn_token
sync.all.caps_string.vpn_token
sync.all.copy.consistency
sync.all.parcel.consistency
matcher.default
matcher.vpn_inclusive
matcher.vpn_exclusive
matcher.mixed
legacy.active
legacy.network
legacy.all
```

The schema-only diagnostic group MUST contain exactly:

```text
schema.self_test
```

Passive/active asynchronous execution MUST contain these 16 logical IDs in both main and secondary
roles:

```text
callback.default
callback.default_handler
callback.broad
callback.broad_handler
callback.vpn_inclusive
callback.vpn_exclusive
callback.vpn_mixed
callback.vpn_exclusive_other_uid
callback.best_matching
pending.listen.vpn_exclusive
request.callback.default
request.callback.timeout
request.callback.handler
request.callback.handler_timeout
request.pending.vpn_exclusive
reserve.signature
```

Every independently maskable signal MUST retain its own ID. Mandatory metadata controls raw verdict
aggregation but MUST NOT remove calibrated discriminators from production coverage.

The server-VPN feature MUST expose five namespaced execution groups in the same APK:
`server-vpn-sync`, `server-vpn-async`, `server-vpn-active`, `server-vpn-link`, and
`server-vpn-diagnostics`, plus the corresponding `secondary-` forms. The async, active, and link
groups MUST reuse exactly the ID sets above. `server-vpn-sync` MUST contain the 28 synchronous IDs
above plus exactly:

```text
sync.default_proxy
scalar.active_metered
scalar.active_multipath
scalar.all_multipath
structure.link.active.parcel
structure.request.default.copy
structure.request.default.parcel
```

`server-vpn-diagnostics` MUST contain exactly:

```text
diagnostics.lifecycle
diagnostics.connectivity_report
diagnostics.data_stall_report
diagnostics.connectivity_result
```

The feature-neutral `data-plane` group MUST contain exactly:

```text
data_plane.dns
data_plane.tls_https
data_plane.lifecycle
```

It MUST use ordinary application DNS and HTTPS/TLS APIs from the selected probe UID. It may record
only bounded success booleans and MUST NOT serialize the host, URL, resolved address, response body,
TLS version/cipher/certificate, provider data, or original exception text.

**Evidence:** `DetectorCatalog`, `EXPECTED_TEST_IDS`, parser exact-set checks, and native calibration.

### `PRB-005` - Asynchronous lifecycle
**Contract:** Callback records MUST preserve ordered names for available, capabilities, link
properties, blocked, losing, lost, and unavailable events without synchronous callback-time
re-query. Registrations run sequentially with bounded timeouts and release in `finally`.
PendingIntent delivery MUST use an explicit non-exported receiver in the owning process and produce
one coordinator-owned record. Cleanup failure is a failed run.
For a non-location run, `ResultStore` MUST create and fsync its empty app-private JSONL
destination before detector execution. The empty file is a lifecycle-ready handshake only; it is
not a record and MUST never be accepted as completed evidence.
For a coordinated server-VPN pair, both runs MUST carry one identical bounded positive
`SystemClock.elapsedRealtime()` start target. After publishing readiness, each process MUST wait for
that boot-monotonic target and stamp its record start time only when detector execution begins.
The rendezvous target is initial-dispatch control data only. It MUST NOT be copied into a
PendingIntent or any other callback intent because callback delivery may occur after the bounded
target window; callback reconstruction MUST use only the persistent run identity and expectation
labels required to own the resulting record.

**Evidence:** `ProbeCoordinator`, receiver/service components, callback raw observations, and host
cleanup validation.

### `PRB-006` - Process model
**Contract:** `ProbeActivity` MUST be the only shell-launch boundary. Every non-location run MUST be
dispatched immediately to a non-exported service so detector lifetime never depends on whether the
Activity remains foreground. Main and secondary non-location services MUST share one base lifecycle;
secondary groups run in the service's `:secondary` process. The `location` and
`secondary-location` groups MUST use distinct non-exported foreground services of type `location`
in the main and `:secondary` processes respectively so bounded public-API registrations remain
active under keyguard and screen-off restrictions. A secondary PendingIntent MUST target the
non-exported receiver in that same process. Before creating run metadata, force-stopping a package,
or crossing the `ProbeActivity` boundary, every ordinary or concurrent host launch MUST run the
shared `AUT-009` UI-readiness operation. Generic `probe-run` MUST validate package, process,
schema, and exact detector catalog. Server-VPN acceptance wrappers MUST validate owner-maintained
VPN-ON state in every rebooted phase, one unchanged active-agent fingerprint across the overlapping
callback-bearing target/non-target runs, declared ZygVeil state, current installed/exported common probe identity,
target/non-target roles, and fresh server hook generation. Location wrappers MUST bind only the
location artifact, target, configuration/oracle, process, and probe identities defined by
`VAL-013`. The `data-plane` group MUST be available in both main and secondary roles and
remain a feature-neutral schema-1 oracle.

**Evidence:** Probe manifest, `BaseProbeService`, `ProbeService`, `SecondaryProbeService`, `LocationProbeService`,
`SecondaryLocationProbeService`, receivers, `tools/automation/probe.py`, and feature role reports.

### `PRB-007` - JSONL record
**Contract:** Each detector line MUST include `schema_version`, `record_type`, `run_id`, `variant`,
`application_id`, `process`, `vpn_expected`, `module_expected`, `group`,
`test_id`, `mandatory`, `status`, `raw_observations`, `exception`, `started_at`, `elapsed_ms`, and
`cleanup_status`. Reusable unnamespaced network groups remain schema 1. Every namespaced
`server-vpn-*` detector record MUST use schema 2 and add exactly one `projection_outcome` from
`absent`, `present_sanitized`, `present_stock`, `unavailable`, `inconclusive`, or `error`;
its summary MUST remain free of that detector-only field. Server-VPN exception messages MUST be
redacted while retaining only the exception class. The final app-side JSONL summary MUST add status
counts, verdict, and detector count. Immutable host summaries MUST bind ordered IDs, the common
probe source hash, artifact identity, repetitions, roles, and state pairing. App-private JSONL and
bounded logcat are collection transports; host collection MUST use `run-as` through Make.

**Evidence:** `ResultStore`, `ProbeRecord`, parser self-tests, and `make probe-results`.

### `PRB-008` - Differential oracle
**Contract:** Existing connectivity detector groups MUST remain reusable public-observation building
blocks, but MUST NOT define a supported legacy module matrix or require a VPN-OFF epoch. Current
server-VPN acceptance MUST use the same common probe generation and the VPN-ON
stock/target/non-target/rollback differential in `PRB-015`. A detector with
`raw_observations.comparison` MUST use only that privacy-safe projection for repeat stability and
differential comparison, subject to the explicit runtime-volatility normalization in `PRB-015`;
diagnostic values MUST not define equivalence.

**Evidence:** Universal probe catalog/source tests and the server-VPN host oracle.

### `PRB-009` - LinkProperties differential block
**Contract:** The `link` group MUST observe synchronous active/all-network and passive default/broad
callback `LinkProperties` without callback-time synchronous re-query. It MUST expose exactly 46
non-mandatory IDs:

```text
link.active.interface
link.active.addresses
link.active.routes
link.active.dns
link.active.mtu
link.active.private_dns
link.active.proxy
link.active.nat64
link.active.dhcp
link.active.wake_on_lan
link.active.signal_strength
link.all.interface
link.all.addresses
link.all.routes
link.all.dns
link.all.mtu
link.all.private_dns
link.all.proxy
link.all.nat64
link.all.dhcp
link.all.wake_on_lan
link.all.signal_strength
link.callback.default.interface
link.callback.default.addresses
link.callback.default.routes
link.callback.default.dns
link.callback.default.mtu
link.callback.default.private_dns
link.callback.default.proxy
link.callback.default.nat64
link.callback.default.dhcp
link.callback.default.wake_on_lan
link.callback.default.signal_strength
link.callback.default.lifecycle
link.callback.broad.interface
link.callback.broad.addresses
link.callback.broad.routes
link.callback.broad.dns
link.callback.broad.mtu
link.callback.broad.private_dns
link.callback.broad.proxy
link.callback.broad.nat64
link.callback.broad.dhcp
link.callback.broad.wake_on_lan
link.callback.broad.signal_strength
link.callback.broad.lifecycle
```

The application MUST discard raw interface names, addresses, gateways, DNS servers, domains,
proxies, DHCP addresses, and NAT64 prefixes before writing JSONL. Address and route observations MAY
retain only counts, address families, prefix lengths, flags/scopes, route types, presence booleans,
and interface-equality relations. Exact signal strength MAY appear only under `diagnostic`; its
`comparison` is the `specified`/`SIGNAL_STRENGTH_UNSPECIFIED` semantic state. `secondary-link` MUST
run the same catalog in the controlled secondary process.

Native calibration MUST classify structured hashes even when every detector status is unchanged.
The accepted device has 35 structurally differential and 11 state-invariant IDs per process.
The 11 `link.all.*` IDs and 12 `link.callback.default.*` IDs MUST remain measured residual
boundaries as specified by `API-021`; server-VPN equality is defined only by `PRB-015`.

**Evidence:** `LinkPropertiesDetectors`, `DetectorCatalog`, exact host catalog validation, privacy
tests, and server-VPN structured comparison.

### `PRB-010` - Location and GNSS session
**Contract:** The existing primary/canary APK MUST expose a `location` group, with no second app,
that performs one bounded session covering provider inventory, last-known/current location,
continuous and batched provider updates, fused delivery where available, GNSS capabilities/status,
NMEA, Raw GNSS measurement registration/events, navigation-message registration/events, and a final
summary. The exact observation types MUST be `provider_inventory`, `last_known`, `current`,
`location_update`, `location_batch`, `gnss_capabilities`, `gnss_status`, `nmea`,
`raw_measurement_status`, `raw_measurement_event`, `navigation_status`, `navigation_event`,
`gms_last_known`, `gms_current`, `gms_location_update`, `gms_location_batch`,
`gms_location_availability`, `gms_pending_intent`, `process_isolation`, and `location_summary`.
Registration cleanup MUST run in `finally` and be part of acceptance. A callback-executor drain
timeout or interruption MUST fail the session, and the
coordinator MUST close callback observation writes before aggregate records and the final summary
so no late callback can append after that summary. The session MUST run in the `PRB-006`
foreground-service boundary so screen state does not silently deactivate its GNSS registrations.
Location launch and service intents MUST omit network-module state labels, and location metadata
MUST contain no such fields. Real satellite visibility, physical movement, and receipt of a GNSS
status or NMEA callback during the bounded window MUST NOT be acceptance prerequisites. Every
received status/NMEA callback MUST still pass the complete virtual satellite and cross-channel
model checks; deterministic native tests provide unconditional model coverage.
Exact physical or synthetic latitude, longitude, and NMEA position fields MUST remain in memory
only and MUST NOT be serialized to JSONL. An oracle-backed session MUST fail unless it observes at
least one platform `Location` and every scalar or batched public `Location` is complete, has the
required accuracy/altitude/speed model fields, satisfies all finite/range/stationary bounds, and lies
within the configured-center radius. The host parser MUST independently repeat those object checks,
reject a `PASS` that violates them, and preserve a structurally valid sanitized `FAIL` run.

Ordinary host runs MUST force-stop the selected probe before launch. The non-attestable main-canary
location POC MAY instead request explicit process reuse only when exactly one canary PID already
exists; the runner MUST record and require the same PID after the bounded session. The activity MUST
dispatch a new run from both initial creation and `onNewIntent`, using that exact intent for the
session, so reuse does not silently retain the preceding run ID or skip foreground-service startup.
The host reuse launch MUST request a new no-history activity task, rather than depend on delivery to
the currently top activity, and MUST fail if Android replaces the process while doing so.
This mode exists only to prove live-generation consumption in an already-hooked process and MUST NOT
replace clean process acceptance sessions. The same POC runner MAY explicitly disable its in-memory oracle only
for an upstream-event trigger; that session is never spatial evidence and MUST be followed by an
applied-generation check and an oracle-backed session.

**Evidence:** Location coordinator, public-API callbacks, exact parser catalog, and
`make probe-location`.

### `PRB-011` - Location record schema 4
**Contract:** Location JSONL MUST use schema 4 while reusable unnamespaced network-detector JSONL
remains schema 1 and namespaced server-VPN detector JSONL uses schema 2; all three MUST remain
readable by the same host consumer. Every schema-4 line MUST include `schema_version`,
`record_type`, `session_id`, `variant`, `application_id`, `process`,
`observation_type`, `monotonic_ns`, `wall_time_ms`, `source`, `status`, and sanitized `payload`;
the final summary MUST additionally bind configured Raw GNSS mode, observation window, callback
registration/capability results, measurement/navigation event counts and first-event latencies,
unexpected-event state, ordinary location/status/NMEA counts, GMS client/surface state and
source-specific counts, platform/GMS getter and object-state comparison counts and maximum distances,
cleanup state, and session verdict.
Schema 4 MUST NOT contain `vpn_expected`, `module_expected`, scope, framework-generation, or
unrelated artifact fields. Those schema-1 detector fields are not accepted as location metadata.
Location and NMEA payloads MUST retain only provider/timing/presence fields, finite/range flags,
privacy-safe displacement and configured-center distance metrics, and consistency bounds. Exact
coordinates, packed NMEA position fields, full measurements, and navigation bits MUST never enter
the JSONL, host parser output, or reports.

**Evidence:** Schema codecs and compatibility tests, host parser, privacy assertions, and redacted
device reports.

### `PRB-012` - Private location oracle
**Contract:** Location acceptance MAY provide each probe variant one schema-1 expected-center oracle
through a bounded mode-private app-sandbox file written without intent extras or command arguments.
The probe MUST open that exact path with no symlink following, validate its descriptor identity,
unlink it before registering callbacks, and confirm through the already-open descriptor that its
link count became zero; only the in-memory session may retain its coordinates. A stale path,
including a dangling symlink, MUST be removed or fail the session closed. Without an oracle, records
MAY expose only relative displacement from an in-memory first sample. With an oracle, records MAY
expose only distance from the expected center and cross-channel consistency bounds.

The oracle MUST remain independent of production code and MUST NOT influence callback registration,
provider selection, or module behavior. Primary/canary and main/secondary acceptance MUST use the
same private expected generation while reporting only its non-reversible configuration digest and
generation number. The host MUST bind every private expected coordinate and altitude to the
authoritative persisted configuration by requiring both decimal spellings to decode to the same
finite IEEE-754 binary64 value; a field that decodes differently MUST prevent acceptance. This
permits the native configuration's round-trip serialization to differ textually from its private
input without weakening the applied point identity. On an active boot the binding MUST require the
current applied runtime generation. On a module-disabled/recovery boot it MUST instead require the
inactive/unavailable helper envelope and the same persisted generation while accepting the
one-way activation flag in its retained `enabled=true` state; it MUST NOT require or manufacture an
activation regression to `enabled=false`. Cleanup or parse failure MUST be explicit and
MUST prevent acceptance. For every successful platform or GMS scalar/batch `Location`, the private
oracle MUST emit only sanitized distance and consistency fields; both the APK verdict and host parser
MUST prevent acceptance of a missing object sample, an object outside the expected radius, or an
incomplete model while retaining its sanitized failed-session evidence.

The explicitly non-attestable POC runner MUST retain the coordinate, generation, Raw-mode, and
current-runtime comparisons but MUST NOT calculate or compare a configuration-file digest. Its
in-memory oracle and JSONL MUST carry the fixed all-zero 64-character digest sentinel required by
the schema, and the redacted POC report MUST state `config_hash_comparison=skipped`. That sentinel
MUST be rejected by ordinary acceptance and cannot identify or promote an artifact. When no
mode-private host oracle is supplied, the POC runner MUST obtain the current point only from the
fixed helper's `status-ui` response, require an active `applied` generation, keep the values in
memory, and never place them in a host file, command argument, JSONL, or report.

**Evidence:** Probe oracle parser/lifecycle tests, JSONL privacy scans, host stdin/file delivery,
primary/canary live-generation sessions, and absence of coordinate keys in all reports.

### `PRB-013` - Canary Google Play services location client
**Contract:** The canary location session MUST use the pinned public
`com.google.android.gms:play-services-location:21.4.0` client owned by `API-014`, with
`org.checkerframework:checker-qual:4.1.0` present only on the canary compile classpath for its
published nullness annotations; it MUST NOT use
reflection, hidden APIs, raw Binder, production-module code, or mock-location APIs. It MUST exercise
both last-location overloads, both current-location overloads, availability, executor callback and
listener updates, batched `LocationResult` delivery with flush, and a non-exported mutable
PendingIntent receiver in the same main or secondary process as the session. Every registration,
Task completion/failure/cancellation, delivered location count, and cleanup result MUST be explicit.
The canary adapter MUST independently verify both fine and coarse location grants before any
permission-protected GMS call and report a sanitized failing observation if either grant is absent.

The primary MUST emit `UNAVAILABLE` GMS observations with reason `variant_not_enabled`. The canary
MUST fail its session when the GMS client cannot start, a required request family cannot register,
or any one of last-known, current, callback, listener, or PendingIntent delivery produces no
`Location`. It MUST also fail when no fresh Android/GMS getter and object-state comparison is possible,
either comparison is inconsistent, or any delivered GMS object violates the private oracle's complete
synthetic model and configured-center radius. Each comparison MUST cover both public
latitude/longitude getters and the independent public `Location.distanceTo()` object-state oracle in
`API-016`; a getter-only match with divergent object state MUST fail. Only distances, booleans,
counts, timing, and provider/presence metadata may be serialized; exact coordinates remain
memory-only. The required regression oracle catches both an isolated GMS escape and the case where
Android and GMS are mutually consistent but both still expose the physical point.
The APK verdict and host parser MUST bind coverage to successful scalar/batch object records from all
seven exact sources: both last-location overloads, both current-location overloads, callback,
listener, and PendingIntent. Family summary counts alone cannot satisfy the canary.

**Evidence:** Variant dependency/source inspection, GMS adapter tests, schema/privacy self-tests,
and focused main/secondary canary device sessions.

### `PRB-014` - Universal server-VPN probe group
**Contract:** The existing `components/probe/` project MUST add the server-VPN group to primary
package `dev.zygveil.probe.primary` and canary package `dev.zygveil.probe.canary` without creating a
second project or package pair. Primary MUST exercise the same global eligible-user-app policy as
any ordinary application; canary is the fixed excluded non-target control. Both MUST exercise main and explicit secondary
processes, use only public API 36 connectivity calls and ordinary application permissions, and
contain no production, controller, root, hidden API, raw Binder, JNI detector, package inventory,
mock VPN, or shared-UID dependency. Extending this group MUST change the one common probe
source/artifact generation and trigger location plus server-VPN reacceptance. The exact execution
groups are the five namespaced groups and their secondary forms in `PRB-004`; generic
feature-specific APK components, services, receivers, or launch activities are forbidden. The
feature-neutral `data-plane` group shares those same packages/process boundaries and adds no
component.

**Evidence:** One Gradle project with two flavors, normalized common source hash, manifest/DEX
inspection, exact installed identities, group-separation tests, and target/canary role reports.

### `PRB-015` - Server-VPN records and differential oracle
**Contract:** A feature-specific server-VPN record group within the common probe schema and exact
stable catalog MUST independently record
synchronous active/all-network snapshots, detached Parcelable structure, local request/matcher
residuals, direct default proxy, metered/multipath scalar controls, request registrations, ordinary
callbacks, PendingIntent delivery, public connectivity-diagnostics reports, legacy results, cleanup,
main/secondary roles, and measured concurrent target/non-target delivery. Each source-specific
record MUST distinguish absent, present-sanitized, present-stock, unavailable, inconclusive, and
error outcomes without inferring success from a family summary. Its host oracle MUST compare
module-disabled combined-host stock behavior, active primary projection,
active canary stock
behavior from the same unchanged boot, and recovered stock restoration. Every rebooted phase MUST independently
observe exactly one active VPN agent while automation performs no VPN transition. Because loading
or removing the boot-time hook transaction requires a reboot, cross-boot network-agent identity is
not an equality requirement. Active target/canary runs for `server-vpn-async`,
`server-vpn-active`, and `server-vpn-link` MUST overlap and retain one unchanged privacy-safe agent
fingerprint across the active suite; `server-vpn-sync` MAY execute sequentially on that same
unchanged active boot. For each overlapping pair, automation MUST finish both run-state writes and
both force-stops before launch. It MUST schedule the canary with a non-waiting `am start`, wait a
bounded interval for that run's exact app-private empty-or-populated JSONL readiness file, and only
then immediately schedule the primary with another non-waiting `am start`. Concurrent Activity-start
requests and `am start -W` are prohibited for the pair because an observed Android runtime can drop a
competing pending launch or serialize foreground Activity-resume waits. Both processes MUST then
begin detectors at the same prevalidated boot-monotonic rendezvous. Evidence MUST record and bind
that common target, bound canary-ready latency and ready-to-primary-dispatch delay, validate both
scheduling results independently, and still prove positive overlap from the two
application-recorded run intervals; the lifecycle handshake and rendezvous are not substitutes for
the in-app overlap oracle.

`ConnectivityDiagnosticsManager` is a public registration surface, but the observed acceptance session
delivers a network's reports only to the network-stack UID, an administrator/owner of that network,
or the UID owning a VPN over it. The ordinary non-VPN probe identities intentionally satisfy none
of those roles. Therefore `server-vpn-diagnostics` MUST remain an explicit permission-bounded
residual in main and secondary processes: registration and cleanup MUST succeed, no callback may be
invented, and the exact no-delivery projection MUST remain identical across stock, active target,
active canary, and rollback. It MUST NOT be promoted as a functional masking differential; hook
semantics for that ingress remain covered by the exact catalog, model, and DEX gates. The oracle
MUST bind exact APK/source/catalog/runtime identities and reject partial catalogs, non-overlapping
calibrated callback concurrency, a changed diagnostics residual, stale processes, cleanup failure,
missing VPN-ON state, or an active-phase agent change.

The schema-2 `projection_outcome` is expectation-aware metadata, not proof by itself. A positive
calibrated signal is `present_stock`; an active primary target's negative signal or structural
control is `present_sanitized`; an inactive/disabled primary or canary mandatory negative is
`absent`; a non-mandatory stock control is `present_stock`; and the remaining three outcomes map
one-to-one to `UNAVAILABLE`, `INCONCLUSIVE`, and `ERROR`. Host acceptance MUST independently
check this mapping and the source-specific raw observation before using the outcome.
For a callback request that can match multiple simultaneous networks, the bounded observation MUST
accumulate whether any delivered capabilities contained VPN; a later physical callback MUST NOT
overwrite an already observed VPN signal. Event ordering itself remains diagnostic and is excluded
from stable projection equality.
The raw downstream/upstream bandwidth estimates and signal-strength value MUST remain recorded as
integer getter observations, but their numeric values are runtime-volatile and MUST be excluded from
stable projection equality across rebooted phases. Their detector status and integer shape remain
equality-bound. IP-derived `LinkProperties` inventories are likewise runtime-volatile: the exact 24
`link.{active,all,callback.default,callback.broad}.{addresses,routes,dns,proxy,nat64,dhcp}` detector
payloads MUST retain their schema and privacy validation, detector status, and
`projection_outcome`, but their network/link counts and sanitized inventory details MUST be
excluded from stable equality between rebooted stock, active-canary, and rollback phases. Owner
UID, enterprise IDs, network-specifier shape, subscription IDs, non-IP link controls, and every
VPN-identifying or copy-consistency observation remain strictly equality-bound; volatility MUST NOT
be generalized to those fields.
For an active primary target only, a successfully registered VPN-exclusive callback or
PendingIntent request that remains silent for the bounded window MAY be classified as
`NEGATIVE/present_sanitized`; this is valid only when the overlapping canary observes the
corresponding stock VPN source and cleanup completes. The same silence in a stock/canary run remains
`INCONCLUSIVE`.

Records and reports MUST contain no address, route, DNS, interface, traffic endpoint, raw
capability/link/request/object dump, package inventory, unrelated process mapping, private path, or
incidental `toString()` ordering. Structural comparison MUST use explicitly encoded fields and
canonical ordering. Application isolation MAY report only presence/absence and digests for the
common `libzygveil.so` mapping, forbidden second/server-only ELF identities, VPN
bridge/generated-hook backing identities, feature threads, and descriptors. The common ELF is
expected because the supported location feature is globally resident; its presence is not a
server-VPN isolation failure. Accepted location bridge, delivery-page, and hook identities are
neither detector inputs nor failures. During the non-attestable POC only, host isolation MAY bind
the exact single read-only 4096-byte location delivery mapping and defer common-ELF content-digest
attestation to final location acceptance; it MUST still reject every VPN-specific mapping, thread,
descriptor, bridge, and second-owner identity in each controlled application.
The same active and stock phase manifests MUST bind successful primary/canary `data-plane` runs in
both main and secondary processes; these runs prove only DNS resolution plus a completed TLS/HTTPS
204 transaction and are not projection detectors.

**Evidence:** Exact catalog/schema tests, privacy scanner, source-specific APK verdicts, host
differential/concurrency parser, and application-process isolation oracle.
