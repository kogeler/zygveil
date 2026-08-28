<!--
SPDX-FileCopyrightText: 2026 kogeler
SPDX-License-Identifier: MIT
-->

# Public Android API Contract

The implemented location framework boundary begins at `API-009`; the system-server VPN
service boundary begins at `API-018`. The universal probe compiles against the Android 16/API 36
public SDK, but runtime availability is never inferred only from compilation. Source retained under
`deprecated/` defines no supported public API behavior.

### `API-009` - Fixed framework hooks
**Contract:** Active location simulation MUST attempt exactly these five Java/ART hooks and no
fuzzy/reflection fallback signature. Their presence is not guaranteed on any phone or build; failure
to resolve the complete required set MUST follow the inactive transaction path:

```text
com.android.server.location.provider.LocationProviderManager.onReportLocation(
    android.location.LocationResult): void
com.android.server.location.gnss.GnssStatusProvider.onReportSvStatus(
    android.location.GnssStatus): void
com.android.server.location.gnss.GnssNmeaProvider$1.lambda$apply$0(
    long, android.location.IGnssNmeaListener): void
com.android.server.location.gnss.GnssMeasurementsProvider.$r8$lambda$S8pdLPl99PS7zjoxENRN9LwkjGc(
    android.location.GnssMeasurementsEvent,
    android.location.IGnssMeasurementsListener): void
com.android.server.location.gnss.GnssNavigationMessageProvider.$r8$lambda$f-SZ_rst97IBLhPC3S2XayaZh7U(
    android.location.GnssNavigationMessage,
    android.location.IGnssNavigationMessageListener): void
```

The first hook MUST run before framework caching/coarsening/delivery. The last two MUST suppress only
the final Binder-listener invocation while leaving provider registration and framework-internal GNSS
production intact.

**Evidence:** Fixed source catalog, runtime hook status, unit tests, and focused device observations.

### `API-010` - Location result transformation
**Contract:** The location hook MUST preserve batch order/count, provider, valid wall and elapsed
timestamps, elapsed uncertainty, extras, and incoming mock state for copied objects. It MUST replace
latitude, longitude, horizontal accuracy, altitude, MSL altitude, vertical/MSL accuracy, speed,
speed accuracy, bearing, and bearing accuracy according to `ARC-017`; bearing and its accuracy MUST
both be absent below the configured speed threshold. Invalid or stale elapsed timestamps MUST be
made monotonic without assigning one common timestamp to a batch. A transformation failure after
activation MUST drop that result rather than expose a physical observation.
Transformed latitude/longitude MUST remain within the Android public ranges even when jitter crosses
a pole or the antimeridian.

**Evidence:** Shared model and JNI adapter tests, batch probe observations, and model-bound checks.

### `API-011` - GNSS status and NMEA
**Contract:** Active GNSS status MUST contain deterministic slowly evolving, valid-range SVID,
constellation, carrier frequency, azimuth, elevation, C/N0, ephemeris, almanac, and used-in-fix
fields. Active upstream NMEA callbacks MUST emit valid-checksum GGA, RMC, GSA, and GSV sentences
whose UTC, position, altitude/geoid separation, speed/course availability, fix quality, satellite
counts, and DOP agree with the latest shared synthetic sample and satellite state. No independent
timer/generator loop is allowed. Each upstream callback MUST produce at most one synthetic sentence
while the process-wide sequence covers every required type. A formatter/delivery failure MUST drop
physical NMEA/status data.

**Evidence:** Deterministic status/NMEA tests and structured probe summaries.

### `API-012` - Raw GNSS modes
**Contract:** Schema-1 `raw_gnss_mode=blocked` MUST leave application-visible measurement/navigation
capabilities and normal registration behavior unchanged while delivering zero physical measurement
and navigation events. `passthrough` MUST call exact backups and publish a warning.
`unsupported` MUST fail configuration validation on this generation. Failure to arm either Raw GNSS
hook MUST prevent all simulation; once active, either drop callback MUST return without I/O, large
allocation, exception escape, or fallback to the physical event.

**Evidence:** Mode/config tests, exact hook status, and simultaneous location/GNSS probe sessions.

### `API-013` - Live generation semantics
**Contract:** A complete valid live configuration with a generation strictly newer than the applied
generation MUST become visible atomically at the next entry to any hook in `API-009`. The entry that
applies it MUST reset the shared stationary model before transforming or suppressing its upstream
event. Each `LocationResult` batch, GNSS status callback, and NMEA callback MUST expose one complete
old or new generation, never a mixed field set. Location, NMEA, and GNSS state after the switch MUST
agree with the new center and altitude model; speed and bearing MUST restart from the stationary
reset state while elapsed timestamps remain monotonic.

Before coordinates have ever been applied, every location hook MUST be installed in passthrough
standby and the application delivery hook MUST be retained globally in the same standby. The first
valid Apply MUST publish the sole permitted `enabled=false` to `enabled=true` transition. Each
system-server or application callback that first observes that generation MUST activate its bridge
before handling that same callback. No later public or controller operation may return to standby.

Publishing a generation MUST NOT invoke an Android callback. Until an upstream event arrives, the
helper/controller MUST report the persisted generation as pending and an already cached synthetic
last location MAY remain from the previous generation. A malformed, stale, unauthorized,
non-finite, out-of-range, checksum-invalid, or boot-field-changing request MUST retain the last
valid synthetic generation. After activation, update handling failure MUST drop the affected
physical event or continue with the last valid synthetic model; it MUST never fall back to physical
location, status, NMEA, measurement, or navigation data.

**Evidence:** Model/runtime protocol tests, publication/acknowledgement tests, live device sessions,
and unchanged `system_server`/five-hook identity.

### `API-014` - Ordinary Google Play services location observation surface
**Contract:** Location coverage measurement MUST include the current public Google Play services
`FusedLocationProviderClient` 21.4.0 surface used by an ordinary fine-location application. The
independent canary MUST call `getLastLocation()` and
`getLastLocation(LastLocationRequest)`, both `getCurrentLocation` overloads,
`getLocationAvailability()`, `requestLocationUpdates` through executor `LocationCallback`, executor
`LocationListener`, and explicit non-exported `PendingIntent`, `flushLocations()`, and the matching
three `removeLocationUpdates` methods. PendingIntent results MUST be decoded only with public
`LocationResult` and `LocationAvailability` helpers. Mock mode/location, geofencing, activity
recognition, orientation, hidden APIs, raw Binder, and deprecated `GoogleApiClient` are outside this
measured surface.

This assertion defines the observation oracle, not a production interception mechanism. A
production hook for a failing GMS path requires a separate fixed method/process contract and
security-boundary update after the canary reproduces it.

**Evidence:** Canary-only compile dependency and adapter, observation records, host schema
validation, and a focused differential session.

### `API-015` - Fixed application-delivery POC method
**Contract:** The temporary `ARC-022` POC MUST hook only the fixed implementation method
`android.location.Location$1.createFromParcel(android.os.Parcel): android.location.Location` inside
every application process specialized while the POC module is enabled. A covariant bridge returning
`Object` may also exist; method resolution MUST select only the typed implementation committed by
this contract. No application ID,
package, UID, process, or caller selection is permitted.

After invoking the original parcel creator, the POC MUST make a defensive `Location` copy and replace
its physical position, altitude, accuracy, speed, and bearing fields with one complete stationary
model sample while preserving provider, mock/extras, and valid timestamps. It MUST return the copy
only after all transformations and `isComplete()` succeed; otherwise it MUST return the untouched
original result. It MUST NOT hook getters, setters, constructors, distance/bearing methods, Google
Play services classes, raw Binder methods, or native sockets. In-process application-created
route/destination objects that never cross this creator remain unaffected. The identity-free hook
cannot determine parcel provenance, so any `Location` later unmarshaled through the fixed creator,
including application-originated parcel content, is transformed.

This non-public implementation hook is permitted only by the non-attestable POC boundary. The POC
MUST consume only the applied generation from the global
read-only derived mapping in `ARC-020`; it MUST make no companion request, and its mapping and hook
attempt MUST remain independent of application identity. A focused POC proves live generation
convergence only for the measured runtime session and cannot satisfy production coverage;
production behavior and acceptance are owned exclusively by `API-017` and `VAL-013`.

**Evidence:** Fixed-method DEX inspection, POC hook table/dispatch, absence of application selection
logic, and focused platform/GMS getter plus object-state comparison.

### `API-016` - Ordinary `Location` object consistency oracle
**Contract:** Coverage measurement MUST treat a delivered `android.location.Location` as more than
its latitude/longitude getter pair. The canary MUST retain in-memory defensive copies of fresh
Android and GMS observations and compare both their public getter coordinates and public
`Location.distanceTo(Location)` behavior between the two copies and against an in-memory anchor
created from the platform observation. A getter-only interception is sufficient for this oracle only
when those independent public geodesic operations also remain within the threshold.

Only comparison counts, maximum non-negative finite distances, thresholds, and consistency
booleans MAY leave memory. Exact coordinates, `Location.toString()`, parcel contents, and complete
objects MUST NOT enter JSONL or host/device reports. Bearing/distance against caller-created route
points that remain in process, geofencing, native consumers, and arbitrary constructor/setter use
remain outside this focused delivery oracle until separately contracted; unparceling any such object
crosses `API-015`/`API-017` and is not outside the hook.

**Evidence:** Canary comparison implementation, schema/privacy validation, pre-fix failure, and
post-fix focused session.

### `API-017` - Production application parcel delivery
**Contract:** The ordinary module MUST attempt the same single global method hook as
`API-015` in every application process, with no application-identity selection at mapping, hook, or
callback time. On each callback it MUST first acquire the latest valid
applied configuration from `ARC-023`, invoke the original creator exactly once, make a defensive
copy, and replace every physical location/model field using one coherent stationary sample before
return. Provider, mock/extras, and valid timestamps MUST be preserved; latitude, longitude,
ellipsoid/MSL altitude, horizontal/vertical/MSL accuracy, speed, speed accuracy, bearing, and bearing
accuracy MUST be synthetic and complete.

Application-created `Location` constructors, setters, getters, distance/bearing methods, static
utilities, and parcel writes MUST remain unhooked. Objects remain unaffected only while they stay
outside the exact creator; any application-originated parcel content returned by that creator is
transformed because the global identity-free callback cannot distinguish provenance. Before active
delivery-page validation or after initialization failure the application path MAY fail open for
stability and MUST emit only bounded coordinate-free lifecycle diagnostics. After hook activation,
an event transformation failure MUST return no physical `Location`; the bridge MUST be activated
fail-closed before the native runtime is published. A lost or inactive delivery-page identity MUST
invoke the original creator exactly once, discard its result, and return `null`. A pending, corrupt,
or rejected newer generation MUST never replace the last complete valid synthetic model and MAY
continue transforming from that model. This hidden implementation hook has no phone/build
compatibility guarantee and MUST use only the fixed signature committed in `API-015`.

**Evidence:** Fixed DEX method identity, hook table, full-field transformation tests, global process
inspection, strengthened canary, and live update sessions.

### `API-018` - Server synchronous result projection
**Contract:** When every fixed runtime member resolves, the server-VPN catalog MUST cover every service method
actually responsible for ordinary-application synchronous delivery of active/all-network handles,
`NetworkCapabilities`, `LinkProperties`, default `ProxyInfo`, and legacy `NetworkInfo` observations
exercised by `PRB-014`. For an eligible caller, a raw VPN result MUST be returned only as a
detached projection
whose covered VPN-identifying capability, transport-info, link, and connected legacy fields match
the committed server policy. `getActiveNetwork()` and `getAllNetworks()` MUST remain unhooked and
return the stock network handles and ordering; a later covered capability, link, or legacy query for
one of those handles is the projection boundary. Nullability, retained-entry order, non-VPN entries,
unrelated fields, and service-owned origin objects MUST otherwise remain unchanged. A non-target,
ambiguous caller, unsupported overload, copy failure, or shape mismatch MUST receive stock behavior.
Every fixed class/method/descriptor/loader and argument/return role MUST be committed in the
server-VPN hook catalog before the first installable hook POC; fuzzy names and reflection
fallbacks are prohibited.

The exact ordinary public-to-service map is:

| Public observation | Exact service hook ID | Target transformation |
|---|---|---|
| `getActiveNetwork()` | none | Preserve the stock handle. |
| `getAllNetworks()` | none | Preserve all stock handles and their order. |
| `getNetworkCapabilities(Network)` | `sync.network_capabilities` | If the detached result identifies a VPN, return the exact service backup's detached capabilities for one eligible donor. |
| `getLinkProperties(Network)` | `sync.link_properties` | If the queried handle identifies a VPN, return the exact service backup's detached link properties for the same donor policy. |
| `getActiveNetworkInfo()` | `sync.legacy_active` | Mask a connected VPN result; preserve null or a non-VPN result. |
| `getNetworkInfo(int)` | `sync.legacy_type` | Mask a connected VPN result; preserve null or a non-VPN result. |
| `getNetworkInfo(Network)` | `sync.legacy_network` on `getNetworkInfoForUid(Network,int,boolean)` | Treat the explicit UID argument only as the query subject, authorize by Binder caller, and mask a connected VPN result. |
| `getAllNetworkInfo()` | `sync.legacy_all` | Return a new array with connected VPN entries removed and retained order unchanged. |
| `getDefaultProxy()` | `sync.default_proxy` on `getProxyForNetwork(Network)` | Preserve a global proxy; otherwise substitute the detached proxy for the donor when the nullable process-bound/default source is a VPN. |

The donor algorithm MUST first accept exactly one declared underlying handle that resolves to a
different, connected, non-VPN network with `NOT_VPN`, `INTERNET`, and `VALIDATED`. If that source is
absent it MAY accept exactly one candidate with the same properties from the exact stable service
enumerator. Zero, multiple, stale, or structurally invalid candidates are ambiguous and MUST retain
the stock result. Donor selection consumes no link addresses, routes, DNS, interface names, or
traffic values. The synchronous bridge MUST call exact backups so the service performs its normal
permission redaction and returns a new object; it MUST never read a donor field and expose that
shared object directly. The hidden `getActiveLinkProperties()` method is outside the ordinary SDK
surface and MUST NOT be hooked.

**Evidence:** Exact Connectivity DEX/service map, committed catalog, detached-copy model tests,
target/canary synchronous records, and origin-object identity checks.

### `API-019` - Server request ingress normalization
**Contract:** For every exact service ingress used by the ordinary public request APIs exercised by
`PRB-014`, the backend MUST resolve the calling UID/package before any identity clear or asynchronous
handoff. Only an eligible caller's network-request payload MAY be replaced by a detached copy that
adds `NET_CAPABILITY_NOT_VPN` when it is absent. It MUST NOT remove
`TRANSPORT_VPN`: an exclusive VPN request must remain unsatisfiable in the sanitized view, while a
mixed VPN/physical request may still match its physical alternative. The caller-owned request,
callback/PendingIntent identity, attribution, timeout, handler/executor behavior,
subscription/specifier/other-UID constraints, and cleanup token MUST be preserved. Non-target,
shared-UID, ambiguous, malformed, null-default, or unsupported calls MUST remain stock.

All public callback overloads collapse to these exact ingress hooks:

| Public family | Exact service hook ID | Request treatment |
|---|---|---|
| `registerNetworkCallback(request, callback[, handler])` | `ingress.listen` | Normalize a detached non-null capability payload. |
| `registerNetworkCallback(request, PendingIntent)` | `ingress.pending_listen` | Normalize a detached non-null capability payload. |
| `registerBestMatchingNetworkCallback(...)` | `ingress.request` with stock `LISTEN_FOR_BEST` type | Normalize the non-null payload; preserve the request type. |
| Four `requestNetwork(request, callback, ...)` overloads | `ingress.request` with stock `REQUEST` type | Normalize the non-null payload; preserve timeout, Messenger, Binder, flags, and type. |
| `requestNetwork(request, PendingIntent)` | `ingress.pending_request` | Normalize a detached non-null capability payload. |
| `reserveNetwork(request, handler, callback)` | `ingress.request` with stock `RESERVATION` type | Normalize the non-null payload; preserve reservation semantics. |
| Two `registerDefaultNetworkCallback(...)` overloads | `ingress.request` with stock `TRACK_DEFAULT` type | Preserve the null payload and use the egress donor rule in `API-020`. |
| `ConnectivityDiagnosticsManager.registerConnectivityDiagnosticsCallback(...)` | `ingress.connectivity_diagnostics` | Replace the detached `NetworkRequest` with an otherwise identical copy whose capabilities include `NOT_VPN`; service-owned diagnostic reports then originate only from matching physical networks. |

The hook runs before the service clears identity or constructs `NetworkRequestInfo`, but original
service permission, AppOps, request validation, UID restriction, and copying still run exactly once.
The Binder calling UID, its unique authoritative user-0 package identity, and the supplied package
claim must all agree before normalization; the `asUid` argument is never an authorization substitute.

**Evidence:** Exact ingress catalog, copy truth tables, caller-object immutability tests, request
registration records, and mixed target/non-target sessions.

### `API-020` - Server callback and PendingIntent egress
**Contract:** Callback and PendingIntent delivery MUST use the authoritative owner captured by the
exact registration path, not the thread delivering the later event. Each authorized recipient MUST
receive its own detached `NetworkCapabilities`, `LinkProperties`, `NetworkInfo`, or request snapshot
projection; a shared source object MUST never be mutated or reused across differently authorized
recipients. Registration replacement, unregister/release, callback death, PendingIntent
cancellation, UID/package removal, and `system_server` teardown MUST revoke ownership without
leaking a target decision to another registration. An unresolved or stale owner MUST receive stock
behavior or no new transformed delivery according to the origin lifecycle, never a guessed target
projection.

`egress.callback` MUST authorize only from exact `NetworkRequestInfo.mUid`. When its source
`NetworkAgentInfo` is a VPN, it may replace that argument with the one eligible donor reference
before invoking the original method; the service then performs its normal per-recipient permission
redaction and constructs a new Bundle, `Network`, capabilities, and link snapshot. It MUST NOT edit
either agent. Null `UNAVAILABLE`/`RESERVED` sources and already physical sources remain stock.
`egress.pending_intent` applies the same owner and donor decision before the service constructs the
Intent; the original method remains the sole sender and lifecycle owner. Explicit requests normally
arrive here already matched to a physical network because of `API-019`; donor substitution is also
required for target default-network delivery and is a defensive boundary for any raw VPN source.
Connectivity diagnostics need no separate egress hook: their normalized service-owned
`NetworkRequestInfo` can match only physical agents, and the original diagnostics implementation
remains solely responsible for constructing each detached `ConnectivityReport` or
`DataStallReport`. In the observed acceptance session, ordinary non-owner probe UIDs were not eligible to
receive reports for either the external VPN or its underlying network. `PRB-015` therefore records
this public registration as a permission-bounded residual; no-delivery in one session is not evidence
that the ingress transformation executed.

The module MUST keep no callback/PendingIntent ownership registry: service-owned
`NetworkRequestInfo` lifetime, replacement, Binder death, cancellation, and release are
authoritative. Therefore the final Bundle sender and both release methods are deliberately not
hooked. Package/UID/privilege revalidation is still required at every egress boundary so a replaced,
shared, excluded, or removed caller returns to stock behavior without waiting for reboot.

**Evidence:** Registration ownership model tests, callback/PendingIntent lifecycle records,
concurrent target/canary delivery, removal/death cleanup, and shared-payload identity assertions.

### `API-021` - Projection consequences and residual surface
**Contract:** Public getters, parcel copies, equality, hash, and string output that operate on a
detached server-delivered object MAY naturally reflect its projected fields and require no
application-process hook. Caller-created objects that never cross a covered service boundary,
purely local `NetworkRequest` matching/inspection, unsupported service paths, hidden/raw Binder or
JNI use, stock network-handle count/identity, package/interface/route/DNS inspection, and remote
traffic inference MUST remain outside the server-VPN claim. A target may therefore retain an extra
opaque network handle compared with a VPN-absent device, while every covered service query of that
handle returns the contracted projection. VPN provider teardown/replacement and VPN-OFF transitions
are outside the fixed VPN-ON acceptance epoch; the backend MUST NOT claim callback lifecycle
equivalence for such transitions. `isActiveNetworkMetered()` and `getMultipathPreference()` remain
measured stock scalar consequences because neither exposes a transport, capability, link, proxy,
legacy type, or request payload; a calibrated differential in either would require a new exact
boundary before acceptance. Coverage MUST be defined only by `API-018` through `API-020` and the
exact server-VPN group in the universal probe catalog.

The service-only feasibility decision is `GO` only while all six conditions remain true: exact
backups provide detached synchronous donor values; all non-null public request payloads reach one of
the five committed ingresses; `NetworkRequestInfo.mUid` remains the callback/PendingIntent owner;
the original service remains the detached asynchronous payload builder; authorization can
revalidate one eligible user-0 package/UID/privilege tuple at every boundary; and all 14 hooks can be
armed or deactivated as one transaction. A missing exact method/field, a need to edit an agent or
service request, an application-process dependency, ambiguous donor acceptance, or an ownership
decision based on delivery-thread identity is a no-go condition and MUST prevent activation. Local
matching and the other residuals above do not block activation because they are explicitly outside
the claim and remain measured by `PRB-015`.

**Evidence:** Parcelable/copy structural tests, local-only residual records, exact catalog audit,
and bounded claim review.

## Authoritative Android Sources

- [NetworkCapabilities](https://developer.android.com/reference/android/net/NetworkCapabilities)
- [NetworkRequest](https://developer.android.com/reference/android/net/NetworkRequest)
- [NetworkRequest.Builder](https://developer.android.com/reference/android/net/NetworkRequest.Builder)
- [ConnectivityManager](https://developer.android.com/reference/android/net/ConnectivityManager)
- [LinkProperties](https://developer.android.com/reference/android/net/LinkProperties)
- [NetworkInfo](https://developer.android.com/reference/android/net/NetworkInfo)
- [Android 16 public connectivity API](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/heads/android16-release/framework/api/current.txt)
