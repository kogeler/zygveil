// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class ControllerUnitMain {
  private static int tests;

  private ControllerUnitMain() {}

  public static void main(String[] arguments) throws Exception {
    testCoordinateParsing();
    testCoordinateFailures();
    testHelperStatus();
    testStateReduction();
    testFixedCommands();
    testOperationGuard();
    testRootStatusPrivacy();
    testPresets();
    System.out.println("schema_version=1");
    System.out.println("status=PASS");
    System.out.println("tests=" + tests);
    System.out.println(
        "categories=input,locale,precision,range,protocol,state,commands,lifecycle,presets,privacy");
  }

  private static void testCoordinateParsing() throws Exception {
    CoordinateInput.Values canonical = CoordinateInput.parse("60.17", "24.941", "35", "5", '.');
    check("60.17".equals(canonical.latitude()), "latitude canonical");
    check("24.941".equals(canonical.longitude()), "longitude canonical");
    check("35".equals(canonical.altitudeEllipsoid()), "ellipsoid canonical");
    check("5".equals(canonical.altitudeMsl()), "msl canonical");
    CoordinateInput.Values comma = CoordinateInput.parse("-12,5", "179,25", "-10,125", "0,5", ',');
    check("-12.5".equals(comma.latitude()), "locale latitude");
    check("179.25".equals(comma.longitude()), "locale longitude");
    check("-10.125".equals(comma.altitudeEllipsoid()), "locale altitude");
    CoordinateInput.Values boundary =
        CoordinateInput.parse("90.00000000", "-180.00000000", "-12000.000", "100000.000", '.');
    check("90".equals(boundary.latitude()), "latitude boundary");
    check("-180".equals(boundary.longitude()), "longitude boundary");
    check("-12000".equals(boundary.altitudeEllipsoid()), "altitude minimum");
    check("100000".equals(boundary.altitudeMsl()), "altitude maximum");
    CoordinateInput.Values zero = CoordinateInput.parse("-0.00000000", "0.0", "-0.000", "0", '.');
    check("0".equals(zero.latitude()), "negative zero latitude");
    check("0".equals(zero.altitudeEllipsoid()), "negative zero altitude");
    String payload = canonical.toHelperInput();
    check(payload.startsWith("schema_version=1\n"), "payload schema");
    check(payload.endsWith("altitude_msl_m=5\n"), "payload complete");
    check(
        payload.getBytes(java.nio.charset.StandardCharsets.UTF_8).length < 1024, "payload bounded");
  }

  private static void testCoordinateFailures() {
    expectInputFailure(
        "", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.REQUIRED);
    expectInputFailure(
        "+1", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.DECIMAL);
    expectInputFailure(
        ".5", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.DECIMAL);
    expectInputFailure(
        "-.5", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.DECIMAL);
    expectInputFailure(
        "1.", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.DECIMAL);
    expectInputFailure(
        "1e2", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.DECIMAL);
    expectInputFailure(
        "NaN", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.DECIMAL);
    expectInputFailure(
        "Infinity",
        "0",
        "0",
        "0",
        '.',
        CoordinateInput.Field.LATITUDE,
        CoordinateInput.Error.DECIMAL);
    expectInputFailure(
        "1,2", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.DECIMAL);
    expectInputFailure(
        "1.2,3", "0", "0", "0", ',', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.DECIMAL);
    expectInputFailure(
        "1.123456789",
        "0",
        "0",
        "0",
        '.',
        CoordinateInput.Field.LATITUDE,
        CoordinateInput.Error.PRECISION);
    expectInputFailure(
        "1.000000000",
        "0",
        "0",
        "0",
        '.',
        CoordinateInput.Field.LATITUDE,
        CoordinateInput.Error.PRECISION);
    expectInputFailure(
        "91", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.RANGE);
    expectInputFailure(
        "-91", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.RANGE);
    expectInputFailure(
        "0", "181", "0", "0", '.', CoordinateInput.Field.LONGITUDE, CoordinateInput.Error.RANGE);
    expectInputFailure(
        "0", "-181", "0", "0", '.', CoordinateInput.Field.LONGITUDE, CoordinateInput.Error.RANGE);
    expectInputFailure(
        "0",
        "0",
        "1.0000",
        "0",
        '.',
        CoordinateInput.Field.ALTITUDE_ELLIPSOID,
        CoordinateInput.Error.PRECISION);
    expectInputFailure(
        "0",
        "0",
        "-12000.001",
        "0",
        '.',
        CoordinateInput.Field.ALTITUDE_ELLIPSOID,
        CoordinateInput.Error.RANGE);
    expectInputFailure(
        "0",
        "0",
        "0",
        "100000.001",
        '.',
        CoordinateInput.Field.ALTITUDE_MSL,
        CoordinateInput.Error.RANGE);
    expectInputFailure(
        "０", "0", "0", "0", '.', CoordinateInput.Field.LATITUDE, CoordinateInput.Error.DECIMAL);
  }

  private static void testHelperStatus() throws Exception {
    HelperStatus redacted = HelperStatus.parse(status("applied", "none", false));
    check("active".equals(redacted.moduleState()), "status module");
    check("active".equals(redacted.runtimeState()), "status runtime");
    check("8".equals(redacted.appliedGeneration()), "status applied generation");
    check(redacted.coordinates() == null, "redacted coordinates absent");
    HelperStatus waiting = HelperStatus.parse(waitingStatus());
    check("waiting".equals(waiting.moduleState()), "waiting module state parses");
    check(waiting.coordinates() == null, "waiting placeholder coordinates are hidden");
    HelperStatus full = HelperStatus.parse(status("saved_pending_upstream", "none", true));
    check(full.coordinates() != null, "full coordinates present");
    check("-33.125".equals(full.coordinates().latitude()), "full latitude parsed");
    check("151.25".equals(full.coordinates().longitude()), "full longitude parsed");
    HelperStatus.parse(
        status("recovery_required", "rollback_persistence_uncertain", false)
            .replace("persisted_generation=8", "persisted_generation=7"));
    HelperStatus.parse(
        status("recovery_required", "persistence_uncertain", false)
            .replace("published_generation=8", "published_generation=7"));
    expectStatusFailure(status("applied", "none", false) + "unknown=value\n");
    expectStatusFailure(status("applied", "none", false) + "reason=duplicate\n");
    expectStatusFailure(status("applied", "none", true).replace("altitude_msl_m=5\n", ""));
    expectStatusFailure(
        status("applied", "none", false).replace("schema_version=1", "schema_version=2"));
    expectStatusFailure(
        status("applied", "none", false)
            .replace("published_generation=8", "published_generation=-1"));
    expectStatusFailure(
        status("applied", "none", false).replace("raw_gnss_mode=blocked", "raw_gnss_mode=raw"));
    expectStatusFailure(
        status("applied", "none", false).replace("module_state=active", "module_state=unknown"));
    expectStatusFailure(
        status("applied", "none", false).replace("system_server_pid=1234", "system_server_pid=0"));
    expectStatusFailure(
        status("applied", "none", false)
            .replace("system_server_start_ticks=424242", "system_server_start_ticks=0"));
    expectStatusFailure(
        status("applied", "none", false)
            .replace("boot_id=12345678-1234-1234-1234-123456789abc", "boot_id=unavailable"));
    expectStatusFailure(
        status("applied", "none", false)
            .replace("boot_config_generation=6", "boot_config_generation=4611686018427387904")
            .replace("persisted_generation=8", "persisted_generation=4611686018427387904")
            .replace("published_generation=8", "published_generation=4611686018427387904")
            .replace("applied_generation=8", "applied_generation=4611686018427387904"));
    expectStatusFailure(
        status("applied", "none", false).replace("applied_generation=8", "applied_generation=7"));
    expectStatusFailure(status("applied", "checksum_mismatch", false));
    expectStatusFailure(status("saved_pending_upstream", "checksum_mismatch", false));
    expectStatusFailure(status("rejected", "none", false));
    expectStatusFailure(status("unavailable", "runtime_inactive", false));
    expectStatusFailure(
        status("unavailable", "center_latitude_deg", false)
            .replace("module_state=active", "module_state=inactive")
            .replace("runtime_state=active", "runtime_state=inactive"));
    expectStatusFailure(
        status("applied", "none", false)
            .replace("boot_id=12345678-1234-1234-1234-123456789abc", "boot_id=secret"));
    expectStatusFailure(
        status("applied", "none", false)
            .replace(
                "boot_id=12345678-1234-1234-1234-123456789abc",
                "boot_id=-23456781234-1234-1234-123456789abc"));
    String secret = "66.12345678";
    try {
      HelperStatus.parse(secret);
      throw new AssertionError("secret output accepted");
    } catch (HelperStatus.ProtocolException error) {
      check(!error.getMessage().contains(secret), "protocol error redacted");
    }
  }

  private static void testStateReduction() throws Exception {
    check(
        ControllerState.fromStatus(HelperStatus.parse(status("applied", "none", false))).tone()
            == ControllerState.Tone.APPLIED,
        "state applied");
    check(
        ControllerState.fromStatus(HelperStatus.parse(waitingStatus())).tone()
            == ControllerState.Tone.WAITING,
        "state waiting for first coordinates");
    check(
        ControllerState.fromStatus(
                    HelperStatus.parse(status("saved_pending_upstream", "none", false)))
                .tone()
            == ControllerState.Tone.PENDING_UPSTREAM,
        "state pending upstream");
    check(
        ControllerState.fromStatus(
                    HelperStatus.parse(
                        status("saved_pending_reboot", "publish_unavailable", false)))
                .tone()
            == ControllerState.Tone.PENDING_REBOOT,
        "state pending reboot");
    check(
        ControllerState.fromStatus(
                    HelperStatus.parse(
                        status("recovery_required", "persisted_runtime_rejection", false)))
                .tone()
            == ControllerState.Tone.RECOVERY_REQUIRED,
        "state recovery required");
    check(
        ControllerState.fromStatus(
                    HelperStatus.parse(status("rejected", "checksum_mismatch", false)))
                .tone()
            == ControllerState.Tone.REJECTED,
        "state rejected");
    check(
        ControllerState.fromStatus(HelperStatus.parse(errorStatus("invalid_input"))).tone()
            == ControllerState.Tone.REJECTED,
        "error envelope rejected");
    String inactive =
        status("unavailable", "runtime_inactive", false)
            .replace("module_state=active", "module_state=inactive")
            .replace("runtime_state=active", "runtime_state=inactive");
    check(
        ControllerState.fromStatus(HelperStatus.parse(inactive)).tone()
            == ControllerState.Tone.INACTIVE,
        "state inactive");
    for (RootHelper.Failure failure : RootHelper.Failure.values()) {
      ControllerState state = ControllerState.fromFailure(failure);
      check(state.tone() != null, "failure state " + failure.name());
      check(!state.reason().isEmpty(), "failure reason " + failure.name());
    }
  }

  private static void testFixedCommands() {
    check(
        RootHelper.STATUS_COMMAND.equals(RootHelper.commandFor(RootHelper.Flow.STATUS)),
        "status command fixed");
    check(
        RootHelper.STATUS_UI_COMMAND.equals(RootHelper.commandFor(RootHelper.Flow.STATUS_UI)),
        "status ui command fixed");
    check(
        RootHelper.APPLY_COMMAND.equals(RootHelper.commandFor(RootHelper.Flow.APPLY)),
        "apply command fixed");
    for (RootHelper.Flow flow : RootHelper.Flow.values()) {
      String command = RootHelper.commandFor(flow);
      check(command.startsWith(RootHelper.HELPER_PATH + " "), "helper path fixed");
      check(command.indexOf('\n') < 0 && command.indexOf('=') < 0, "command has no input");
    }
    String privateValue = "66.12345678";
    check(!RootHelper.STATUS_COMMAND.contains(privateValue), "status command privacy");
    check(!RootHelper.STATUS_UI_COMMAND.contains(privateValue), "status ui command privacy");
    check(!RootHelper.APPLY_COMMAND.contains(privateValue), "apply command privacy");
    check(RootHelper.MAXIMUM_INPUT_BYTES == 1024, "input bound exact");
    check(RootHelper.MAXIMUM_OUTPUT_BYTES == 16 * 1024, "output bound exact");
    try {
      HelperStatus redacted = HelperStatus.parse(status("applied", "none", false));
      HelperStatus full = HelperStatus.parse(status("applied", "none", true));
      check(
          RootHelper.responseMatchesFlow(RootHelper.Flow.STATUS, redacted, 0),
          "redacted status response accepted");
      check(
          !RootHelper.responseMatchesFlow(RootHelper.Flow.STATUS, redacted, 3),
          "status response rejects failure exit");
      check(
          !RootHelper.responseMatchesFlow(RootHelper.Flow.STATUS, full, 0),
          "coordinate status response rejected");
      check(
          !RootHelper.responseMatchesFlow(RootHelper.Flow.APPLY, full, 0),
          "coordinate apply response rejected");
      check(
          RootHelper.responseMatchesFlow(RootHelper.Flow.STATUS_UI, full, 0),
          "coordinate UI response accepted");
      HelperStatus pending = HelperStatus.parse(status("saved_pending_upstream", "none", false));
      HelperStatus rejected = HelperStatus.parse(status("rejected", "checksum_mismatch", false));
      check(
          RootHelper.responseMatchesFlow(RootHelper.Flow.APPLY, pending, 0),
          "successful apply transition accepted");
      check(
          !RootHelper.responseMatchesFlow(RootHelper.Flow.APPLY, pending, 4),
          "successful apply state rejects failure exit");
      check(
          RootHelper.responseMatchesFlow(RootHelper.Flow.APPLY, rejected, 2),
          "rejected apply transition accepts failure exit");
      check(
          !RootHelper.responseMatchesFlow(RootHelper.Flow.APPLY, rejected, 0),
          "rejected apply state rejects success exit");
      check(
          !RootHelper.responseMatchesFlow(RootHelper.Flow.APPLY, rejected, 42),
          "rejected apply state rejects unknown exit");
      HelperStatus unauthorized = HelperStatus.parse(errorStatus("unauthorized_invocation"));
      check(
          RootHelper.responseMatchesFlow(RootHelper.Flow.STATUS, unauthorized, 5),
          "unauthorized status exit accepted");
      check(
          !RootHelper.responseMatchesFlow(RootHelper.Flow.STATUS, unauthorized, 0),
          "unauthorized status success rejected");
    } catch (HelperStatus.ProtocolException error) {
      throw new AssertionError("fixed response fixture invalid", error);
    }
  }

  private static void testOperationGuard() {
    OperationGuard guard = new OperationGuard();
    long first = guard.begin();
    check(guard.isCurrent(first), "first operation current");
    long second = guard.begin();
    check(!guard.isCurrent(first), "superseded operation stale");
    check(guard.isCurrent(second), "second operation current");
    guard.invalidate();
    check(!guard.isCurrent(second), "destroyed operation stale");
  }

  private static void testPresets() throws Exception {
    CoordinateInput.Values point = CoordinateInput.parse("10.25", "-20.5", "35", "5", '.');
    PresetCodec.Preset first = PresetCodec.create("Primary", point);
    PresetCodec.Preset second =
        PresetCodec.create("Edge point", CoordinateInput.parse("-90", "180", "0", "-10", '.'));
    byte[] encoded = PresetCodec.encode(List.of(first, second));
    List<PresetCodec.Preset> decoded = PresetCodec.decode(encoded);
    check(decoded.equals(List.of(first, second)), "preset round trip");
    check(encoded.length < PresetCodec.MAXIMUM_BYTES, "preset encoding bounded");
    byte[] corrupt = encoded.clone();
    corrupt[0] ^= 1;
    expectPresetDecodeFailure(corrupt);
    expectPresetDecodeFailure(Arrays.copyOf(encoded, encoded.length - 1));
    byte[] trailing = Arrays.copyOf(encoded, encoded.length + 1);
    expectPresetDecodeFailure(trailing);
    expectPresetNameFailure("");
    expectPresetNameFailure(" leading");
    expectPresetNameFailure("trailing ");
    expectPresetNameFailure("line\nbreak");
    expectPresetNameFailure("x".repeat(33));
    List<PresetCodec.Preset> maximum = new ArrayList<>();
    for (int index = 0; index < PresetCodec.MAXIMUM_PRESETS; index++) {
      maximum.add(PresetCodec.create("P" + index, point));
    }
    check(PresetCodec.decode(PresetCodec.encode(maximum)).size() == 20, "preset maximum");
    maximum.add(first);
    try {
      PresetCodec.encode(maximum);
      throw new AssertionError("preset overflow accepted");
    } catch (PresetCodec.CodecException error) {
      check("preset_limit".equals(error.getMessage()), "preset overflow rejected");
    }
  }

  private static void testRootStatusPrivacy() throws Exception {
    HelperStatus full = HelperStatus.parse(status("applied", "none", true));
    RootHelper.Result result = new RootHelper.Result(full, RootHelper.Failure.NONE, 0);
    String rendered =
        RootStatusStore.render("12345678-1234-1234-1234-123456789abc", 1_777_000_000_000L, result);
    check(rendered.contains("schema_version=1\n"), "root status schema");
    check(rendered.contains("transport_status=none\n"), "root status transport");
    check(rendered.contains("helper_status_present=true\n"), "root status helper present");
    check(rendered.contains("coordinates=absent\n"), "root status redaction marker");
    check(!rendered.contains("-33.125"), "root status latitude absent");
    check(!rendered.contains("151.25"), "root status longitude absent");
    check(!rendered.contains("altitude_ellipsoid_m"), "root status altitude key absent");
    String failed =
        RootStatusStore.render(
            "abcdef12-1234-1234-1234-123456789abc",
            1_777_000_000_001L,
            RootHelper.Result.failed(RootHelper.Failure.DENIED));
    check(failed.contains("transport_status=denied"), "root status denial");
    check(failed.contains("helper_status_present=false"), "root status missing helper");
  }

  private static String status(String control, String reason, boolean coordinates) {
    String persisted = "8";
    String published = "8";
    String applied = "7";
    if ("applied".equals(control)) {
      applied = "8";
    } else if ("saved_pending_reboot".equals(control)) {
      persisted = "9";
      applied = "8";
    } else if ("rejected".equals(control)) {
      persisted = "7";
    }
    String result =
        "schema_version=1\n"
            + "module_state=active\n"
            + "runtime_state=active\n"
            + "control_state="
            + control
            + "\nreason="
            + reason
            + "\nraw_gnss_mode=blocked\n"
            + "boot_config_generation=6\n"
            + "persisted_generation="
            + persisted
            + "\npublished_generation="
            + published
            + "\napplied_generation="
            + applied
            + "\n"
            + "system_server_pid=1234\n"
            + "system_server_start_ticks=424242\n"
            + "boot_id=12345678-1234-1234-1234-123456789abc\n";
    if (coordinates) {
      result +=
          "center_latitude_deg=-33.125\n"
              + "center_longitude_deg=151.25\n"
              + "altitude_ellipsoid_m=35\n"
              + "altitude_msl_m=5\n";
    }
    return result;
  }

  private static String errorStatus(String reason) {
    return "schema_version=1\n"
        + "module_state=inactive\n"
        + "runtime_state=unavailable\n"
        + "control_state=rejected\n"
        + "reason="
        + reason
        + "\nraw_gnss_mode=blocked\n"
        + "boot_config_generation=0\n"
        + "persisted_generation=0\n"
        + "published_generation=0\n"
        + "applied_generation=0\n"
        + "system_server_pid=0\n"
        + "system_server_start_ticks=0\n"
        + "boot_id=unavailable\n";
  }

  private static String waitingStatus() {
    return "schema_version=1\n"
        + "module_state=waiting\n"
        + "runtime_state=waiting\n"
        + "control_state=awaiting_first_coordinates\n"
        + "reason=none\n"
        + "raw_gnss_mode=blocked\n"
        + "boot_config_generation=1\n"
        + "persisted_generation=1\n"
        + "published_generation=1\n"
        + "applied_generation=1\n"
        + "system_server_pid=1234\n"
        + "system_server_start_ticks=424242\n"
        + "boot_id=12345678-1234-1234-1234-123456789abc\n";
  }

  private static void expectInputFailure(
      String latitude,
      String longitude,
      String ellipsoid,
      String msl,
      char separator,
      CoordinateInput.Field expectedField,
      CoordinateInput.Error expectedError) {
    try {
      CoordinateInput.parse(latitude, longitude, ellipsoid, msl, separator);
      throw new AssertionError("invalid coordinate accepted");
    } catch (CoordinateInput.InvalidInput error) {
      check(error.field() == expectedField, "input field");
      check(error.error() == expectedError, "input error");
      check(latitude.isEmpty() || !error.getMessage().contains(latitude), "input error privacy");
    }
  }

  private static void expectStatusFailure(String text) {
    try {
      HelperStatus.parse(text);
      throw new AssertionError("invalid status accepted");
    } catch (HelperStatus.ProtocolException error) {
      check(!error.getMessage().isEmpty(), "status failure code");
    }
  }

  private static void expectPresetDecodeFailure(byte[] bytes) {
    try {
      PresetCodec.decode(bytes);
      throw new AssertionError("invalid preset accepted");
    } catch (PresetCodec.CodecException error) {
      check(!error.getMessage().isEmpty(), "preset failure code");
    }
  }

  private static void expectPresetNameFailure(String name) throws Exception {
    CoordinateInput.Values point = CoordinateInput.parse("0", "0", "0", "0", '.');
    try {
      PresetCodec.create(name, point);
      throw new AssertionError("invalid preset name accepted");
    } catch (PresetCodec.CodecException error) {
      check("preset_name".equals(error.getMessage()), "preset name rejected");
      check(name.isEmpty() || !error.getMessage().contains(name), "preset name privacy");
    }
  }

  private static void check(boolean condition, String message) {
    tests++;
    if (!condition) {
      throw new AssertionError(message);
    }
  }
}
