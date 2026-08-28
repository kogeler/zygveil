// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.servervpn.policy;

import java.util.List;
import java.util.Objects;
import java.util.Set;

public final class TargetAuthorization {
  private static final int PER_USER_RANGE = 100_000;
  private static final int FIRST_APPLICATION_ID = 10_000;
  private static final int LAST_APPLICATION_ID = 19_999;
  private static final Set<String> EXCLUDED_PACKAGES =
      Set.of(
          "com.wireguard.android",
          "dev.zygveil.location.controller",
          "dev.zygveil.probe.canary",
          "com.topjohnwu.magisk");

  private TargetAuthorization() {}

  public static Decision authorize(
      ResolvedIdentity resolved, String claimedPackage, boolean claimRequired) {
    if (resolved == null) {
      return Decision.reject(Reason.UNRESOLVED_IDENTITY);
    }
    int applicationId = Math.floorMod(resolved.uid(), PER_USER_RANGE);
    int userId = Math.floorDiv(resolved.uid(), PER_USER_RANGE);
    if (userId != 0
        || applicationId < FIRST_APPLICATION_ID
        || applicationId > LAST_APPLICATION_ID) {
      return Decision.reject(Reason.UNSUPPORTED_UID);
    }
    if (resolved.system() || resolved.updatedSystem() || resolved.privileged()) {
      return Decision.reject(Reason.PRIVILEGED_IDENTITY);
    }
    if (resolved.packagesForUid() == null || resolved.packagesForUid().size() != 1) {
      return Decision.reject(Reason.SHARED_OR_DIFFERENT_UID);
    }
    String packageName = resolved.packagesForUid().get(0);
    if (packageName.isEmpty() || !packageName.equals(resolved.resolvedPackage())) {
      return Decision.reject(Reason.PACKAGE_MISMATCH);
    }
    if (EXCLUDED_PACKAGES.contains(packageName)) {
      return Decision.reject(Reason.EXCLUDED_PACKAGE);
    }
    if (claimRequired && !packageName.equals(claimedPackage)) {
      return Decision.reject(Reason.CLAIM_MISMATCH);
    }
    return Decision.authorized(resolved.uid(), packageName);
  }

  public record ResolvedIdentity(
      int uid,
      List<String> packagesForUid,
      String resolvedPackage,
      boolean system,
      boolean updatedSystem,
      boolean privileged) {
    public ResolvedIdentity {
      packagesForUid = packagesForUid == null ? null : List.copyOf(packagesForUid);
      resolvedPackage = Objects.requireNonNullElse(resolvedPackage, "");
    }
  }

  public enum Reason {
    AUTHORIZED,
    UNRESOLVED_IDENTITY,
    UNSUPPORTED_UID,
    PRIVILEGED_IDENTITY,
    SHARED_OR_DIFFERENT_UID,
    PACKAGE_MISMATCH,
    CLAIM_MISMATCH,
    EXCLUDED_PACKAGE
  }

  public record Decision(boolean authorized, Reason reason, int uid, String packageName) {
    private static Decision authorized(int uid, String packageName) {
      return new Decision(true, Reason.AUTHORIZED, uid, packageName);
    }

    private static Decision reject(Reason reason) {
      return new Decision(false, reason, -1, "");
    }
  }
}
