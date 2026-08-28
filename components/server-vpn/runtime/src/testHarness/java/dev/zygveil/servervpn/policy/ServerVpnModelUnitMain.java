// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.IntStream;

public final class ServerVpnModelUnitMain {
  private static final String PACKAGE = "dev.target.app";
  private static final int TARGET_UID = 10_321;
  private static final int NOT_VPN = 15;
  private static int tests;

  private ServerVpnModelUnitMain() {}

  public static void main(String[] arguments) {
    testAuthorization();
    testDonorSelection();
    testRequestNormalization();
    testIngressArguments();
    testSnapshotProjection();
    testLegacyProjection();
    testEgressDecision();
    testEgressArguments();
    testCatalog();
    System.out.println("schema_version=1");
    System.out.println("status=PASS");
    System.out.println("tests=" + tests);
    System.out.println(
        "categories=authorization,donor,request,ingress_arguments,snapshot,legacy,egress,egress_arguments,catalog,properties");
  }

  private static void testAuthorization() {
    TargetAuthorization.ResolvedIdentity valid = identity(TARGET_UID, List.of(PACKAGE), PACKAGE);
    TargetAuthorization.Decision accepted = TargetAuthorization.authorize(valid, PACKAGE, true);
    check(accepted.authorized(), "eligible ordinary app is authorized");
    check(accepted.uid() == TARGET_UID, "authorized UID is retained");
    check(PACKAGE.equals(accepted.packageName()), "authorized package is retained");
    check(
        TargetAuthorization.authorize(valid, "", false).authorized(),
        "egress identity needs no caller package claim");
    TargetAuthorization.ResolvedIdentity authoritativeUnconventionalName =
        identity(TARGET_UID, List.of("Dev.Owner.App"), "Dev.Owner.App");
    check(
        TargetAuthorization.authorize(authoritativeUnconventionalName, "Dev.Owner.App", true)
            .authorized(),
        "package-manager identity is authoritative without a naming regex");

    assertAuthorizationReason(
        null, PACKAGE, true, TargetAuthorization.Reason.UNRESOLVED_IDENTITY, "missing identity");
    assertAuthorizationReason(
        identity(110_321, List.of(PACKAGE), PACKAGE),
        PACKAGE,
        true,
        TargetAuthorization.Reason.UNSUPPORTED_UID,
        "non-user-0 identity");
    assertAuthorizationReason(
        identity(1_000, List.of(PACKAGE), PACKAGE),
        PACKAGE,
        true,
        TargetAuthorization.Reason.UNSUPPORTED_UID,
        "system UID range");
    assertAuthorizationReason(
        identity(TARGET_UID, List.of(PACKAGE, "dev.shared.app"), PACKAGE),
        PACKAGE,
        true,
        TargetAuthorization.Reason.SHARED_OR_DIFFERENT_UID,
        "shared UID");
    assertAuthorizationReason(
        identity(TARGET_UID, List.of(PACKAGE), "dev.other.app"),
        PACKAGE,
        true,
        TargetAuthorization.Reason.PACKAGE_MISMATCH,
        "resolved package replacement");
    assertAuthorizationReason(
        valid,
        "dev.other.app",
        true,
        TargetAuthorization.Reason.CLAIM_MISMATCH,
        "caller package claim");
    for (String excluded :
        List.of(
            "com.wireguard.android",
            "dev.zygveil.location.controller",
            "dev.zygveil.probe.canary",
            "com.topjohnwu.magisk")) {
      assertAuthorizationReason(
          identity(TARGET_UID, List.of(excluded), excluded),
          excluded,
          true,
          TargetAuthorization.Reason.EXCLUDED_PACKAGE,
          "fixed exclusion " + excluded);
    }
    for (int flag = 0; flag < 3; flag++) {
      TargetAuthorization.ResolvedIdentity privileged =
          new TargetAuthorization.ResolvedIdentity(
              TARGET_UID, List.of(PACKAGE), PACKAGE, flag == 0, flag == 1, flag == 2);
      assertAuthorizationReason(
          privileged,
          PACKAGE,
          true,
          TargetAuthorization.Reason.PRIVILEGED_IDENTITY,
          "privileged flag " + flag);
    }
  }

  private static void assertAuthorizationReason(
      TargetAuthorization.ResolvedIdentity identity,
      String claimedPackage,
      boolean claimRequired,
      TargetAuthorization.Reason reason,
      String description) {
    TargetAuthorization.Decision decision =
        TargetAuthorization.authorize(identity, claimedPackage, claimRequired);
    check(!decision.authorized() && decision.reason() == reason, description + " is rejected");
    check(decision.uid() == -1, description + " does not retain an authorized UID");
    check(decision.packageName().isEmpty(), description + " does not retain a package");
  }

  private static void testDonorSelection() {
    Object donor = new Object();
    DonorSelection.Candidate<Object> eligible = candidate(donor, 0);
    DonorSelection.Selection<Object> declared =
        DonorSelection.select(List.of(eligible), List.of(candidate(new Object(), 0)));
    check(declared.outcome() == DonorSelection.Outcome.UNIQUE, "declared donor is unique");
    check(declared.source() == DonorSelection.Source.DECLARED_UNDERLYING, "declared source wins");
    check(declared.value() == donor, "declared donor identity is retained");

    DonorSelection.Selection<Object> enumerated =
        DonorSelection.select(List.of(), List.of(eligible));
    check(enumerated.outcome() == DonorSelection.Outcome.UNIQUE, "enumerated donor is unique");
    check(
        enumerated.source() == DonorSelection.Source.STABLE_ENUMERATION,
        "enumeration is fallback only");
    check(
        DonorSelection.select(null, List.of(eligible)).outcome() == DonorSelection.Outcome.UNIQUE,
        "null underlying list means absent source");
    check(
        DonorSelection.select(List.of(candidate(donor, 1)), List.of(eligible)).outcome()
            == DonorSelection.Outcome.AMBIGUOUS,
        "invalid declared source blocks enumeration fallback");
    check(
        DonorSelection.select(List.of(eligible, candidate(new Object(), 0)), List.of()).outcome()
            == DonorSelection.Outcome.AMBIGUOUS,
        "multiple declared donors are ambiguous");
    check(
        DonorSelection.select(List.of(), List.of(eligible, candidate(new Object(), 0))).outcome()
            == DonorSelection.Outcome.AMBIGUOUS,
        "multiple enumerated donors are ambiguous");
    check(
        DonorSelection.select(List.of(), null).outcome() == DonorSelection.Outcome.NONE,
        "missing enumerator has no donor");

    for (int failedPredicate = 0; failedPredicate < 8; failedPredicate++) {
      DonorSelection.Selection<Object> selection =
          DonorSelection.select(List.of(), List.of(candidate(donor, failedPredicate + 1)));
      check(
          selection.outcome() == DonorSelection.Outcome.NONE,
          "donor predicate " + failedPredicate + " fails closed");
      check(selection.value() == null, "failed donor never leaks a value");
    }
    check(
        DonorSelection.select(List.of(), Arrays.asList(null, eligible)).outcome()
            == DonorSelection.Outcome.UNIQUE,
        "null candidate is ignored");
  }

  private static DonorSelection.Candidate<Object> candidate(Object value, int failedPredicate) {
    return new DonorSelection.Candidate<>(
        failedPredicate == 1 ? null : value,
        failedPredicate == 2,
        failedPredicate != 3,
        failedPredicate != 4,
        failedPredicate == 5,
        failedPredicate != 6,
        failedPredicate != 7,
        failedPredicate != 8);
  }

  private static void testRequestNormalization() {
    for (int mask = 0; mask < 256; mask++) {
      boolean authorized = (mask & 1) != 0;
      boolean supported = (mask & 2) != 0;
      boolean hasNotVpn = (mask & 4) != 0;
      boolean vpnOnly = (mask & 8) != 0;
      boolean mixed = (mask & 16) != 0;
      boolean otherUid = (mask & 32) != 0;
      int subscription = (mask & 64) != 0 ? 42 : -1;
      int timeout = (mask & 128) != 0 ? 9_999 : 0;
      List<Integer> transports = vpnOnly ? List.of(4) : mixed ? List.of(4, 1) : List.of(1);
      List<Integer> capabilities = hasNotVpn ? List.of(12, NOT_VPN) : List.of(12);
      RequestNormalization.RequestShape origin =
          new RequestNormalization.RequestShape(
              transports,
              capabilities,
              "specifier-token",
              subscription,
              otherUid,
              "attribution-token",
              7,
              timeout,
              3);
      RequestNormalization.Result result =
          RequestNormalization.normalize(authorized, supported, origin, NOT_VPN);
      if (!authorized || !supported) {
        check(result.action() == RequestNormalization.Action.ORIGIN, "non-target request is stock");
        check(result.value() == origin, "stock request preserves identity");
        continue;
      }
      RequestNormalization.RequestShape detached = result.value();
      check(result.action() == RequestNormalization.Action.NORMALIZED, "target request normalizes");
      check(detached != origin, "normalized request is detached");
      check(detached.capabilities().contains(NOT_VPN), "normalized request has NOT_VPN");
      check(
          detached.capabilities().stream().filter(value -> value == NOT_VPN).count() == 1,
          "NOT_VPN is not duplicated");
      check(detached.transports().equals(origin.transports()), "transport constraints are exact");
      check(detached.specifierToken().equals(origin.specifierToken()), "specifier is preserved");
      check(detached.subscriptionId() == subscription, "subscription is preserved");
      check(detached.otherUid() == otherUid, "other-UID flag is preserved");
      check(
          detached.attributionToken().equals(origin.attributionToken()),
          "attribution is preserved");
      check(detached.requestType() == 7, "request type is preserved");
      check(detached.timeoutMs() == timeout, "timeout is preserved");
      check(detached.flags() == 3, "flags are preserved");
      check(origin.capabilities().equals(capabilities), "caller capabilities are not mutated");
    }
    check(
        RequestNormalization.normalize(true, true, null, NOT_VPN).action()
            == RequestNormalization.Action.ORIGIN,
        "null default request stays stock");
  }

  private static void testSnapshotProjection() {
    Object origin = new Object();
    Object donor = new Object();
    Object detached = new Object();
    DonorSelection.Selection<Object> unique =
        DonorSelection.select(List.of(), List.of(candidate(donor, 0)));
    SnapshotProjection.Result<Object> projected =
        SnapshotProjection.project(
            true, true, origin, unique, new SnapshotProjection.BackupResult<>(detached, true));
    check(projected.action() == SnapshotProjection.Action.SUBSTITUTE, "detached donor substitutes");
    check(projected.value() == detached, "detached backup identity is returned");
    check(origin != detached && donor != detached, "detached backup shares no source identity");

    checkSnapshotOrigin(false, true, origin, unique, detached, true, "non-target");
    checkSnapshotOrigin(true, false, origin, unique, detached, true, "physical origin");
    checkSnapshotOrigin(true, true, null, unique, detached, true, "null origin");
    checkSnapshotOrigin(true, true, origin, null, detached, true, "missing donor");
    checkSnapshotOrigin(true, true, origin, unique, null, true, "null backup");
    checkSnapshotOrigin(true, true, origin, unique, detached, false, "shared backup");
    checkSnapshotOrigin(true, true, origin, unique, origin, true, "origin alias");
  }

  private static void testIngressArguments() {
    Object receiver = new Object();
    Object originPayload = new Object();
    Object callback = new Object();
    Object cleanup = new Object();
    Object packageClaim = new Object();
    Object[] origin = {receiver, originPayload, callback, cleanup, packageClaim};
    Object detachedPayload = new Object();
    Object[] replacement = IngressArguments.replacePayload(origin, 1, detachedPayload);
    check(replacement != origin, "ingress argument array is detached");
    check(origin[1] == originPayload, "caller payload slot is unchanged");
    check(replacement[1] == detachedPayload, "detached payload occupies only its exact slot");
    for (int index = 0; index < origin.length; index++) {
      if (index != 1) {
        check(replacement[index] == origin[index], "ingress identity slot " + index + " is exact");
      }
    }
    check(
        IngressArguments.replacePayload(origin, 0, detachedPayload) == origin,
        "receiver replacement fails open");
    check(
        IngressArguments.replacePayload(origin, origin.length, detachedPayload) == origin,
        "out-of-range payload replacement fails open");
    check(
        IngressArguments.replacePayload(origin, 1, null) == origin,
        "null detached payload replacement fails open");

    List<Object> concurrentPayloads =
        IntStream.range(0, 64).mapToObj(ignored -> new Object()).toList();
    List<Object[]> concurrentReplacements =
        concurrentPayloads.parallelStream()
            .map(payload -> IngressArguments.replacePayload(origin, 1, payload))
            .toList();
    for (int index = 0; index < concurrentReplacements.size(); index++) {
      Object[] concurrent = concurrentReplacements.get(index);
      check(concurrent != origin, "concurrent ingress array is detached " + index);
      check(
          concurrent[1] == concurrentPayloads.get(index),
          "concurrent payload identity is isolated " + index);
      check(
          concurrent[2] == callback && concurrent[3] == cleanup,
          "concurrent lifecycle identities are exact " + index);
    }
    check(origin[1] == originPayload, "concurrent normalization leaves caller array unchanged");
  }

  private static void checkSnapshotOrigin(
      boolean authorized,
      boolean rawVpn,
      Object origin,
      DonorSelection.Selection<Object> donor,
      Object backup,
      boolean detached,
      String description) {
    SnapshotProjection.BackupResult<Object> backupResult =
        backup == null ? null : new SnapshotProjection.BackupResult<>(backup, detached);
    SnapshotProjection.Result<Object> result =
        SnapshotProjection.project(authorized, rawVpn, origin, donor, backupResult);
    check(result.action() == SnapshotProjection.Action.ORIGIN, description + " stays stock");
    check(result.value() == origin, description + " preserves origin identity");
  }

  private static void testLegacyProjection() {
    LegacyValue physical = new LegacyValue("physical", false, true);
    LegacyValue vpnDisconnected = new LegacyValue("vpn-disconnected", true, false);
    LegacyValue vpnConnected = new LegacyValue("vpn-connected", true, true);
    LegacyProjection.ConnectedVpnClassifier<LegacyValue> classifier =
        value -> value.vpn() && value.connected();
    check(LegacyProjection.mask(true, vpnConnected, classifier) == null, "connected VPN is masked");
    check(
        LegacyProjection.mask(true, vpnDisconnected, classifier) == vpnDisconnected,
        "disconnected VPN is retained");
    check(
        LegacyProjection.mask(false, vpnConnected, classifier) == vpnConnected,
        "non-target legacy result is stock");

    LegacyValue[] origin = {null, vpnDisconnected, vpnConnected, physical};
    LegacyValue[] filtered = LegacyProjection.filter(true, origin, classifier);
    check(filtered != origin, "changed legacy array is detached");
    check(
        Arrays.equals(filtered, new LegacyValue[] {null, vpnDisconnected, physical}),
        "legacy order and placeholders are retained");
    check(origin.length == 4 && origin[2] == vpnConnected, "legacy source array is unchanged");
    check(
        LegacyProjection.filter(false, origin, classifier) == origin,
        "non-target legacy array preserves identity");
    LegacyValue[] physicalOnly = {physical, vpnDisconnected};
    check(
        LegacyProjection.filter(true, physicalOnly, classifier) == physicalOnly,
        "unchanged target legacy array preserves identity");
    check(LegacyProjection.filter(true, null, classifier) == null, "null legacy array stays null");
  }

  private static void testEgressDecision() {
    TargetAuthorization.Decision owner =
        TargetAuthorization.authorize(identity(TARGET_UID, List.of(PACKAGE), PACKAGE), "", false);
    Object vpn = new Object();
    Object physical = new Object();
    DonorSelection.Selection<Object> donor =
        DonorSelection.select(List.of(), List.of(candidate(physical, 0)));
    EgressDecision.Result<Object> substituted =
        EgressDecision.decide(owner, true, vpn, true, donor);
    check(
        substituted.action() == EgressDecision.Action.SUBSTITUTE,
        "current target egress substitutes");
    check(substituted.source() == physical, "egress uses exact donor identity");

    checkEgressOrigin(null, true, vpn, true, donor, "unresolved owner");
    TargetAuthorization.Decision rejected =
        TargetAuthorization.authorize(identity(110_321, List.of(PACKAGE), PACKAGE), "", false);
    checkEgressOrigin(rejected, true, vpn, true, donor, "rejected owner");
    checkEgressOrigin(owner, false, vpn, true, donor, "stale registration");
    checkEgressOrigin(owner, true, null, true, donor, "null event source");
    checkEgressOrigin(owner, true, physical, false, donor, "physical event source");
    checkEgressOrigin(owner, true, vpn, true, null, "missing donor");
    DonorSelection.Selection<Object> same =
        DonorSelection.select(List.of(), List.of(candidate(vpn, 0)));
    checkEgressOrigin(owner, true, vpn, true, same, "donor aliases source");
  }

  private static void checkEgressOrigin(
      TargetAuthorization.Decision owner,
      boolean current,
      Object source,
      boolean sourceVpn,
      DonorSelection.Selection<Object> donor,
      String description) {
    EgressDecision.Result<Object> result =
        EgressDecision.decide(owner, current, source, sourceVpn, donor);
    check(result.action() == EgressDecision.Action.ORIGIN, description + " stays stock");
    check(result.source() == source, description + " preserves source identity");
  }

  private static void testEgressArguments() {
    Object receiver = new Object();
    Object registration = new Object();
    Object vpnSource = new Object();
    Object notificationType = new Object();
    Object notificationArgument = new Object();
    Object[] origin = {receiver, registration, vpnSource, notificationType, notificationArgument};
    Object donor = new Object();
    Object[] replacement = EgressArguments.replaceSource(origin, 2, donor);
    check(replacement != origin, "egress argument array is detached");
    check(origin[2] == vpnSource, "shared egress source is unchanged");
    check(replacement[2] == donor, "donor occupies only the source slot");
    for (int index = 0; index < origin.length; index++) {
      if (index != 2) {
        check(replacement[index] == origin[index], "egress lifecycle slot " + index + " is exact");
      }
    }
    check(
        EgressArguments.replaceSource(origin, 0, donor) == origin,
        "egress receiver replacement fails open");
    check(
        EgressArguments.replaceSource(origin, origin.length, donor) == origin,
        "out-of-range egress replacement fails open");
    check(
        EgressArguments.replaceSource(origin, 2, null) == origin,
        "null donor replacement fails open");

    List<Object> concurrentDonors =
        IntStream.range(0, 64).mapToObj(ignored -> new Object()).toList();
    List<Object[]> concurrentReplacements =
        concurrentDonors.parallelStream()
            .map(value -> EgressArguments.replaceSource(origin, 2, value))
            .toList();
    for (int index = 0; index < concurrentReplacements.size(); index++) {
      Object[] concurrent = concurrentReplacements.get(index);
      check(concurrent != origin, "concurrent egress array is detached " + index);
      check(
          concurrent[2] == concurrentDonors.get(index),
          "concurrent donor identity is isolated " + index);
      check(
          concurrent[1] == registration
              && concurrent[3] == notificationType
              && concurrent[4] == notificationArgument,
          "concurrent egress lifecycle identities are exact " + index);
    }
    check(origin[2] == vpnSource, "concurrent egress leaves shared source unchanged");
  }

  private static void testCatalog() {
    check(ServerHookCatalog.HOOKS.size() == 14, "exact hook count is 14");
    Set<String> identifiers = new HashSet<>();
    int synchronous = 0;
    int ingress = 0;
    int egress = 0;
    for (ServerHookCatalog.Hook hook : ServerHookCatalog.HOOKS) {
      check(identifiers.add(hook.id()), "hook IDs are unique");
      switch (hook.boundary()) {
        case SYNCHRONOUS -> {
          synchronous++;
          check(hook.phase() == ServerHookCatalog.Phase.AFTER, "sync hooks run after origin");
        }
        case INGRESS -> {
          ingress++;
          check(hook.phase() == ServerHookCatalog.Phase.BEFORE, "ingress hooks run before origin");
        }
        case EGRESS -> {
          egress++;
          check(hook.phase() == ServerHookCatalog.Phase.BEFORE, "egress hooks run before origin");
        }
      }
    }
    check(synchronous == 7, "seven synchronous hooks");
    check(ingress == 5, "five ingress hooks");
    check(egress == 2, "two egress hooks");
    check(identifiers.contains("sync.default_proxy"), "default proxy is covered");
    check(
        identifiers.contains("ingress.connectivity_diagnostics"),
        "connectivity diagnostics is covered");
    check(identifiers.contains("egress.pending_intent"), "PendingIntent egress is covered");
  }

  private static TargetAuthorization.ResolvedIdentity identity(
      int uid, List<String> packages, String resolvedPackage) {
    return new TargetAuthorization.ResolvedIdentity(
        uid, packages, resolvedPackage, false, false, false);
  }

  private static void check(boolean condition, String description) {
    tests++;
    if (!condition) {
      throw new AssertionError(description);
    }
  }

  private record LegacyValue(String token, boolean vpn, boolean connected) {}
}
