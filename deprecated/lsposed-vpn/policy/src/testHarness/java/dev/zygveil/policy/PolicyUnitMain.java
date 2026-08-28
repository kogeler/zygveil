// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.policy;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

public final class PolicyUnitMain {
  private static int tests;

  private PolicyUnitMain() {}

  public static void main(String[] arguments) throws Exception {
    testCapabilityPolicy();
    testStringPolicy();
    testObservationContext();
    testMatcherPolicy();
    testLegacyPolicy();
    testDonorPolicy();
    testHookCatalog();
    System.out.println("schema_version=1");
    System.out.println("status=PASS");
    System.out.println("tests=" + tests);
    System.out.println("categories=capability,string,context,matcher,legacy,donor,catalog");
  }

  private static void testCapabilityPolicy() {
    check(!CapabilityPolicy.hasTransport(true, 4, 4, true), "VPN transport is hidden for raw VPN");
    check(CapabilityPolicy.hasTransport(true, 1, 4, true), "other transport preserves origin");
    check(CapabilityPolicy.hasTransport(false, 4, 4, true), "non-VPN transport preserves origin");
    check(CapabilityPolicy.hasCapability(true, 15, 15, false), "NOT_VPN is present for raw VPN");
    check(
        !CapabilityPolicy.hasCapability(true, 12, 15, false), "other capability preserves origin");

    int[] origin = {12, 14, 16};
    int[] normalized = CapabilityPolicy.capabilities(true, origin, 15);
    check(Arrays.equals(normalized, new int[] {12, 14, 15, 16}), "capability insertion order");
    check(Arrays.equals(origin, new int[] {12, 14, 16}), "capability origin is unchanged");
    check(normalized != origin, "changed capability array is detached");
    check(
        CapabilityPolicy.capabilities(false, origin, 15) == origin,
        "non-VPN array is origin identity");
    int[] alreadyNormalized = {12, 15, 16};
    check(
        CapabilityPolicy.capabilities(true, alreadyNormalized, 15) != alreadyNormalized,
        "raw VPN array is detached when NOT_VPN already exists");
    check(
        Arrays.equals(
            CapabilityPolicy.capabilities(true, alreadyNormalized, 15), alreadyNormalized),
        "existing NOT_VPN values remain exact");

    Object ordinaryInfo = new Object();
    check(
        CapabilityPolicy.transportInfo(true, ordinaryInfo, "android.net.VpnTransportInfo")
            == ordinaryInfo,
        "non-VPN transport info is preserved");
    VpnTransportInfo fixture = new VpnTransportInfo();
    check(
        CapabilityPolicy.transportInfo(true, fixture, fixture.getClass().getName()) == null,
        "exact VPN transport info is hidden");
    check(
        CapabilityPolicy.transportInfo(false, fixture, fixture.getClass().getName()) == fixture,
        "VPN info on non-VPN object is preserved");
  }

  private static void testStringPolicy() {
    String info = "VpnTransportInfo{type=1}";
    String origin =
        "<[ Transports: WIFI|VPN Capabilities: INTERNET&VALIDATED LinkUpBandwidth>=100"
            + " TransportInfo: <"
            + info
            + "> ]>";
    CapabilityStringPolicy.Result result =
        CapabilityStringPolicy.sanitize(origin, new int[] {12, 16}, 15, info, true);
    check(result.sanitized(), "well-formed capability string is sanitized");
    check(
        result
            .value()
            .equals(
                "<[ Transports: WIFI Capabilities: INTERNET&NOT_VPN&VALIDATED"
                    + " LinkUpBandwidth>=100 ]>"),
        "structured fields are rewritten exactly");

    String exactTokens =
        "<[ Transports: NOT_VPN|VPNISH|VPN Capabilities: INTERNET LinkUpBandwidth>=1 ]>";
    CapabilityStringPolicy.Result exactResult =
        CapabilityStringPolicy.sanitize(exactTokens, new int[] {12}, 15, null, false);
    check(exactResult.sanitized(), "exact VPN transport token is accepted");
    check(
        exactResult.value().contains("Transports: NOT_VPN|VPNISH Capabilities:"),
        "VPN substrings are preserved");
    check(
        exactResult.value().contains("Capabilities: INTERNET&NOT_VPN "),
        "NOT_VPN is inserted once");

    assertFailOpen(
        origin.replace("WIFI|VPN", "VPN|VPN"), new int[] {12, 16}, info, "duplicate VPN");
    assertFailOpen(origin + " Transports: VPN", new int[] {12, 16}, info, "duplicate field");
    assertFailOpen(origin, new int[] {16, 12}, info, "unsorted capability values");
    assertFailOpen(
        origin.replace("INTERNET&VALIDATED", "INTERNET&NOT_VPN"),
        new int[] {12, 16},
        info,
        "capability name/value disagreement");
  }

  private static void assertFailOpen(
      String origin, int[] capabilities, String info, String description) {
    CapabilityStringPolicy.Result result =
        CapabilityStringPolicy.sanitize(origin, capabilities, 15, info, true);
    check(!result.sanitized() && result.value() == origin, description + " fails open");
  }

  private static void testObservationContext() throws Exception {
    check(!RequestObservationContext.isActive(), "context starts inactive");
    RequestObservationContext.Scope outerScope = RequestObservationContext.enter();
    try {
      check(RequestObservationContext.depth() == 1, "outer context depth");
      RequestObservationContext.Scope innerScope = RequestObservationContext.enter();
      try {
        check(RequestObservationContext.depth() == 2, "nested context depth");
      } finally {
        innerScope.close();
      }
      check(RequestObservationContext.depth() == 1, "nested context cleanup");
    } finally {
      outerScope.close();
    }
    check(!RequestObservationContext.isActive(), "outer context cleanup");

    try {
      RequestObservationContext.Scope scope = RequestObservationContext.enter();
      try {
        throw new ExpectedException();
      } finally {
        scope.close();
      }
    } catch (ExpectedException expected) {
      check(!RequestObservationContext.isActive(), "exception context cleanup");
    }

    AtomicBoolean otherThreadInactive = new AtomicBoolean();
    RequestObservationContext.Scope threadScope = RequestObservationContext.enter();
    try {
      Thread thread =
          new Thread(
              () -> otherThreadInactive.set(!RequestObservationContext.isActive()),
              "policy-context-test");
      thread.start();
      thread.join();
    } finally {
      threadScope.close();
    }
    check(otherThreadInactive.get(), "context is thread isolated");

    RequestObservationContext.Scope outer = RequestObservationContext.enter();
    RequestObservationContext.Scope inner = RequestObservationContext.enter();
    boolean rejected = false;
    try {
      outer.close();
    } catch (IllegalStateException expected) {
      rejected = true;
    }
    check(rejected && RequestObservationContext.depth() == 2, "out-of-order close is rejected");
    inner.close();
    outer.close();
    check(!RequestObservationContext.isActive(), "context recovers after rejected close");
  }

  private static void testMatcherPolicy() {
    check(
        MatcherPolicy.plan(false, true, true, true, 1).action() == MatcherPolicy.Action.ORIGIN,
        "null capabilities use origin");
    check(
        MatcherPolicy.plan(true, false, true, true, 1).action() == MatcherPolicy.Action.ORIGIN,
        "non-VPN capabilities use origin");
    check(
        MatcherPolicy.plan(true, true, false, true, 1).action() == MatcherPolicy.Action.NO_MATCH,
        "VPN-only request does not match");
    MatcherPolicy.Plan defaultPlan = MatcherPolicy.plan(true, true, true, false, 0);
    check(
        defaultPlan.action() == MatcherPolicy.Action.TRANSFORM
            && defaultPlan.removeNotVpn()
            && !defaultPlan.removeVpn(),
        "NOT_VPN request uses dual transform");
    MatcherPolicy.Plan mixedPlan = MatcherPolicy.plan(true, true, false, true, 2);
    check(
        mixedPlan.action() == MatcherPolicy.Action.TRANSFORM
            && !mixedPlan.removeNotVpn()
            && mixedPlan.removeVpn(),
        "mixed transport request removes only VPN constraint");
  }

  private static void testLegacyPolicy() {
    LegacyEntry disconnectedVpn = new LegacyEntry("vpn-off", true, false);
    LegacyEntry connectedVpn = new LegacyEntry("vpn-on", true, true);
    LegacyEntry wifi = new LegacyEntry("wifi", false, true);
    LegacyPolicy.ConnectedVpnClassifier<LegacyEntry> classifier =
        entry -> entry.vpn && entry.connected;
    check(
        LegacyPolicy.maskSingle(connectedVpn, classifier) == null,
        "connected VPN single result is hidden");
    check(
        LegacyPolicy.maskSingle(disconnectedVpn, classifier) == disconnectedVpn,
        "disconnected VPN single result is preserved");
    LegacyEntry[] origin = {null, disconnectedVpn, connectedVpn, wifi};
    LegacyEntry[] filtered = LegacyPolicy.filter(origin, classifier);
    check(
        Arrays.equals(filtered, new LegacyEntry[] {null, disconnectedVpn, wifi}),
        "legacy filter preserves null, placeholder and order");
    check(origin.length == 4 && origin[2] == connectedVpn, "legacy origin array is unchanged");
    LegacyEntry[] unchanged = {disconnectedVpn, wifi};
    check(LegacyPolicy.filter(unchanged, classifier) == unchanged, "unchanged legacy identity");
    check(LegacyPolicy.filter(null, classifier) == null, "null legacy array is preserved");
  }

  private static void testDonorPolicy() {
    check(
        DonorPolicy.select(null).outcome() == DonorPolicy.Selection.Outcome.NONE,
        "null donor list has no selection");
    check(
        DonorPolicy.select(List.of()).outcome() == DonorPolicy.Selection.Outcome.NONE,
        "empty donor list has no selection");

    Object donor = new Object();
    DonorPolicy.Selection<Object> unique =
        DonorPolicy.select(List.of(donorCandidate(donor, false, false, true, true, true)));
    check(unique.outcome() == DonorPolicy.Selection.Outcome.UNIQUE, "one donor is unique");
    check(unique.value() == donor, "unique donor identity is preserved");

    check(
        DonorPolicy.select(
                    Arrays.asList(null, donorCandidate(donor, false, false, true, true, true)))
                .outcome()
            == DonorPolicy.Selection.Outcome.UNIQUE,
        "null candidate is ignored");
    check(
        DonorPolicy.select(
                    List.of(
                        donorCandidate(null, false, false, true, true, true),
                        donorCandidate(donor, true, false, true, true, true),
                        donorCandidate(donor, false, true, true, true, true),
                        donorCandidate(donor, false, false, false, true, true),
                        donorCandidate(donor, false, false, true, false, true),
                        donorCandidate(donor, false, false, true, true, false)))
                .outcome()
            == DonorPolicy.Selection.Outcome.NONE,
        "every eligibility condition is required");

    DonorPolicy.Selection<Object> ambiguous =
        DonorPolicy.select(
            List.of(
                donorCandidate(donor, false, false, true, true, true),
                donorCandidate(new Object(), false, false, true, true, true)));
    check(
        ambiguous.outcome() == DonorPolicy.Selection.Outcome.AMBIGUOUS,
        "multiple donors are ambiguous");
    check(ambiguous.value() == null, "ambiguous selection exposes no donor");
  }

  private static DonorPolicy.Candidate<Object> donorCandidate(
      Object value,
      boolean sameNetwork,
      boolean vpn,
      boolean notVpn,
      boolean internet,
      boolean validated) {
    return new DonorPolicy.Candidate<>(value, sameNetwork, vpn, notVpn, internet, validated);
  }

  private static void testHookCatalog() {
    HookCatalog.validate();
    List<HookCatalog.MethodSpec> methods = HookCatalog.methods();
    check(methods.size() == 24, "hook catalog exact count");
    Set<String> keys = new HashSet<>();
    Map<String, Integer> policyCounts = new HashMap<>();
    for (HookCatalog.MethodSpec method : methods) {
      keys.add(method.key());
      policyCounts.merge(method.policy(), 1, Integer::sum);
    }
    check(keys.size() == 24, "hook catalog signatures are unique");
    check(policyCounts.get("capability") == 5, "capability catalog count");
    check(policyCounts.get("request-observation") == 4, "request observation catalog count");
    check(policyCounts.get("request-matcher") == 1, "matcher catalog count");
    check(policyCounts.get("request-boundary") == 10, "request boundary catalog count");
    check(policyCounts.get("manager-snapshot") == 2, "manager snapshot catalog count");
    check(policyCounts.get("legacy") == 2, "legacy catalog count");
    List<HookCatalog.MethodSpec> support = HookCatalog.supportMethods();
    check(support.size() == 1, "support catalog exact count");
    check(
        support.get(0).key().equals("android.net.ConnectivityManager#getAllNetworks()"),
        "support catalog contains only getAllNetworks");
    check(!keys.contains(support.get(0).key()), "support method is not hooked");
  }

  private static void check(boolean condition, String description) {
    tests++;
    if (!condition) {
      throw new AssertionError(description);
    }
  }

  private static final class ExpectedException extends Exception {
    private static final long serialVersionUID = 1L;
  }

  private static final class VpnTransportInfo {}

  private static final class LegacyEntry {
    private final String name;
    private final boolean vpn;
    private final boolean connected;

    private LegacyEntry(String name, boolean vpn, boolean connected) {
      this.name = name;
      this.vpn = vpn;
      this.connected = connected;
    }

    @Override
    public boolean equals(Object other) {
      return other instanceof LegacyEntry entry && name.equals(entry.name);
    }

    @Override
    public int hashCode() {
      return name.hashCode();
    }
  }
}
