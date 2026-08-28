# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

PYTHON ?= python3
REPORT_ROOT ?= .artifacts/reports
ADB_SERIAL ?=
FINAL_ARTIFACT_BUILD ?= 0

.PHONY: help

help:
	@printf '%s\n' \
		'make help            Print the complete supported interface and variables' \
		'make doctor          Verify baseline host tools, rootless Podman, and toolchain inventory' \
		'make docs-check      Validate contracts, links, catalogs, and Make inventory' \
		'make privacy-check   Reject device identity and host-private paths in repository inputs' \
		'make topology-check  Validate supported component and deprecated-source boundaries' \
		'make attestation-keys Validate current builder/dependency keys and bootstrap inputs' \
		'make attestation-check Run the documentation-independent technical gate set' \
		'make final-preflight Run every technical attestation gate and record the private receipt' \
		'make final-preflight-verify Verify the existing receipt without rerunning any gate' \
		'make device-ui-ready Wake the display, dismiss a noncredential keyguard, and prove UI readiness' \
		'make adb-root        Explicitly restart rooted-debugging adbd as root' \
		'make adb-unroot      Explicitly return adbd to the shell identity' \
		'make vpn-status      Capture sanitized provider and active VPN-agent evidence' \
		'make syntax          Parse Python automation and dry-parse the Make target graph' \
		'make image-key       Print content-addressed builder and dependency keys' \
		'make image           Build the pinned rootless Android builder image (online)' \
		'make deps            Resolve and verify the offline Gradle cache (online)' \
		'make bootstrap       Prepare image, dependencies, and stable debug signing' \
		'make image-save      Export the current builder as an OCI archive' \
		'make image-load      Load the expected OCI builder archive' \
		'make confinement-test Prove container isolation and tar-stream boundaries' \
		'make test-network-block Prove the ordinary build container has no network' \
		'make signing-init    Create the ignored stable debug keystore in-container' \
		'make signing-info    Report the stable signing certificate fingerprint' \
		'make shellcheck      Run the standalone shell check inside the builder' \
		'make test-server-vpn-model Run hook-free server authorization/projection model tests' \
		'make test-server-vpn-config Run strict immutable server config/guard parser tests' \
		'make server-vpn-poc-build Build one non-attestable combined-host runtime set' \
		'make server-vpn-poc-install Install the built combined-host POC enabled' \
		'make server-vpn-poc-reboot Reboot and validate the focused combined-host POC' \
		'make server-vpn-poc-status Inspect the current focused server-VPN POC without mutation' \
		'make server-vpn-poc-isolation Check VPN runtime absence in controlled app processes' \
		'make server-vpn-poc-stock-probe Capture one state-paired stock universal-probe phase' \
		'make server-vpn-poc-probe Capture overlapping active primary/canary probe phase' \
		'make server-vpn-poc-differential Evaluate stock/active/rollback POC phases locally' \
		'make server-vpn-poc-recover Explicitly disable the disposable combined host and reboot once' \
		'make server-vpn-final-build Verify preflight, then build and freeze one combined generation' \
		'make server-vpn-final-verify Verify the receipt-bound frozen generation without mutation' \
		'make server-vpn-final-install Install the frozen combined host production-enabled' \
		'make server-vpn-final-enable Explicitly enable the combined host for development evidence' \
		'make server-vpn-final-disable Explicitly disable the combined host for development evidence' \
		'make server-vpn-final-reboot Reboot and validate one frozen evidence state' \
		'make server-vpn-final-status Read and validate the frozen current runtime state' \
		'make server-vpn-final-isolation Prove final server-VPN application-process isolation' \
		'make server-vpn-final-stock-suite Run all stock groups in main and secondary roles' \
		'make server-vpn-final-active-suite Run all active target/canary groups and stress' \
		'make server-vpn-final-recover Disable and reboot the frozen host for rollback evidence' \
		'make server-vpn-final-acceptance Validate the three immutable final phase suites' \
		'make server-vpn-final-attest Aggregate existing final evidence without host gates' \
		'make location-build  Build and inspect the combined Magisk/Zygisk module' \
		'make location-poc-build Build only the non-attestable global application native POC' \
		'make location-candidate-build Build only the non-attestable production-semantics native candidate' \
		'make location-poc-stage Atomically stage the existing POC native in the active module' \
		'make location-poc-reboot Reboot and wait for the staged global application POC' \
		'make location-poc-smoke Inspect only canary process POC mappings without hashes' \
		'make location-poc-run Fast build, stage, reboot, and focused canary POC cycle' \
		'make location-candidate-run Fast production-semantics build, stage, reboot, and canary cycle' \
		'make location-poc-live-reuse Prove a live update in one PID and restore the original point' \
		'make location-final-build Verify preflight, then build the combined location artifact set' \
		'make location-input-check Validate all private location fixtures before preflight' \
		'make location-final-input-check Validate all formal private fixtures before device mutation' \
		'make location-final-input-verify Verify the frozen private-fixture receipt without replacing it' \
		'make location-final-attest Aggregate existing final location evidence without host gates' \
		'make test-location-unit Run deterministic stationary/GNSS model tests' \
		'make location-controller-build Build and inspect the standalone location controller APK' \
		'make test-location-controller-unit Run controller parser/protocol/state tests offline' \
		'make location-controller-install Install the exact standalone controller as a new package' \
		'make location-controller-install-existing Install the already-built frozen controller APK' \
		'make location-controller-ensure-existing Idempotently ensure the frozen controller APK' \
		'make location-controller-reinstall Replace the exact installed standalone controller' \
		'make location-controller-reinstall-existing Replace it with the frozen controller APK' \
		'make location-controller-open Open only the exact controller launcher activity' \
		'make location-controller-status Verify a fresh redacted fixed-helper root request' \
		'make location-controller-root-request Trigger only the fixed redacted Magisk root flow' \
		'make location-live-set Apply a private live coordinate file through fixed helper stdin' \
		'make location-live-status Read validated redacted live-control status' \
		'make location-poc-live-set Apply a private live point through the disposable helper flow' \
		'make location-poc-live-status Read disposable helper status without hash attestation' \
		'make location-install Install the exact combined module production-enabled' \
		'make location-install-existing Install the already-built frozen location ZIP' \
		'make location-update Replace a fully disabled location module artifact' \
		'make location-update-existing Stage the already-built frozen ZIP as an update' \
		'make location-uninstall Stage exact disabled location module removal' \
		'make location-set    Atomically configure a disabled location module' \
		'make location-status Validate and report location module/runtime state' \
		'make location-enable Arm the module for the next reboot' \
		'make location-disable Create its disable marker before the next reboot' \
		'make location-reboot Explicitly reboot and validate the requested module state' \
		'make location-logs   Capture bounded sanitized location/runtime diagnostics' \
		'make location-recover Disable, reboot, validate stability, and collect diagnostics' \
		'make test-location-baseline Capture the no-module public location/GNSS reference' \
		'make test-location-disabled Validate stock behavior after a disabled-module boot' \
		'make test-location-passthrough Validate synthetic outputs with diagnostic Raw passthrough' \
		'make test-location-blocked Validate synthetic outputs and zero Raw GNSS delivery' \
		'make test-location-live Validate one live generation across four probe roles' \
		'make test-location-live-edge Validate a newer edge generation on the same runtime' \
		'make test-location-isolation Prove no persistent location code remains in the probe' \
		'make test-location-stability Exercise provider, screen, and app restart cycles' \
		'make test-location-failures Reject invalid/non-root updates without state change' \
		'make test-location-stress Run repeated updates and concurrent probe roles' \
		'make test-location-persistence Prove the latest live generation survives reboot' \
		'make test-location-restored Validate fresh stock outputs after module disable/reboot' \
		'make test-location-acceptance Validate the complete current-artifact location matrix' \
		'make test-location-final-baseline Capture a freeze-verified reusable no-module baseline' \
		'make test-location-final-disabled Capture the freeze-bound disabled phase' \
		'make test-location-final-passthrough Capture the freeze-bound Raw-passthrough phase' \
		'make test-location-final-blocked Capture the freeze-bound Raw-blocked phase' \
		'make test-location-final-live Capture the first freeze-bound live generation' \
		'make test-location-final-live-edge Capture the freeze-bound edge generation' \
		'make test-location-final-isolation Capture freeze-bound process-isolation evidence' \
		'make test-location-final-stability Capture freeze-bound stability evidence' \
		'make test-location-final-failures Capture freeze-bound failure-containment evidence' \
		'make test-location-final-stress Capture freeze-bound repeated/concurrent evidence' \
		'make test-location-final-persistence Capture freeze-bound reboot persistence' \
		'make test-location-final-restored Capture freeze-bound stock restoration' \
		'make build-probe     Build and inspect both independent public probe variants' \
		'make probe-apk       Build and verify the primary public probe APK' \
		'make probe-canary-apk Build and verify the canary public probe APK' \
		'make probe-canary-poc-build Build only the non-attestable canary POC APK' \
		'make probe-server-vpn-poc-build Build the non-attestable universal POC APK pair' \
		'make probe-primary-poc-install Install the existing non-attestable primary POC APK' \
		'make probe-server-vpn-poc-run Run one active group in a selected universal POC APK' \
		'make probe-server-vpn-poc-concurrent Run overlapping target/canary server-VPN POC sessions' \
		'make probe-canary-poc-server-vpn Run one server-VPN group in the canary POC APK' \
		'make probe-canary-poc-install Install the existing canary POC APK' \
		'make probe-canary-poc-location Run one focused canary POC location session' \
		'make probe-canary-poc-location-reuse Run focused POC in the unchanged canary PID' \
		'make probe-canary-poc-location-trigger Run an oracle-free POC upstream trigger' \
		'make probe-install  Install the primary public probe APK' \
		'make probe-install-canary Install the canary public probe APK' \
		'make probe-install-existing Install the already-built frozen primary probe APK' \
		'make probe-install-canary-existing Install the already-built frozen canary probe APK' \
		'make probe-run      Run one labelled public detector group' \
		'make probe-location Run the public location/GNSS observation session' \
		'make probe-results  Recollect and validate one probe JSONL result' \
		'make probe-cleanup  Stop only the selected probe process' \
		'make check           Run documentation plus technical repository quality gates' \
		'make format          Apply project formatters inside the confined builder' \
		'make format-check    Check formatting inside the offline confined builder' \
		'make attestation-format-check Check code formatting without reading documentation' \
		'make lint            Run Android, Python, shell, and Containerfile linters' \
		'make static-analysis Run compiler and Python semantic analysis' \
		'make quality         Run the complete offline source quality gate' \
		'make clean           Remove generated state while preserving stable signing' \
		'make clean-containers Remove only project-labelled containers and images' \
		'make clean-signing   Delete stable signing only with the exact CONFIRM token' \
		'' \
		'Optional variables:' \
		'  ADB_SERIAL=<selector>            required only when multiple ADB transports are present; never persisted' \
		'  VARIANT=primary|canary           select a probe application ID' \
		'  VPN_EXPECTED=on|off              label the externally controlled VPN state' \
		'  MODULE_EXPECTED=on|off           label the externally controlled module state' \
		'  EXPECTED_STATE=any|absent|disabled|pending_reboot_disabled|pending_reboot_enabled|waiting|active|active_control_failure' \
		'  EXPECTED_CONTROL_STATE=any|accepted|awaiting_first_coordinates|applied|saved_pending_upstream|saved_pending_reboot|recovery_required|rejected|unavailable' \
		'  LOCATION_CONFIG=.state/file.properties select a private mode-0600 boot config' \
		'  LOCATION_LIVE_FILE=.state/location-live.properties select a private mode-0600 live input' \
		'  LOCATION_ORACLE=.state/location-live.properties select a private probe oracle input' \
		'  RAW_GNSS_MODE=blocked|passthrough select expected mode for probe-location' \
		'  SERVER_VPN_FINAL_EXPECTED=active|inactive select the final reboot/status state' \
		'  SERVER_VPN_FINAL_PHASE_KIND=baseline|rollback label a final stock suite' \
		'  OBSERVATION_WINDOW_MS=5000..120000 select the location/GNSS session window' \
		'  MOVEMENT_CONFIRMATION=physical-device-moved label the deliberate movement phase' \
		'  GROUP=sync|async|active|link|schema|location|secondary-sync|secondary-async|secondary-active|secondary-link|secondary-location' \
		'  RUN_ID=<id>                      select persisted probe evidence' \
		'  REPEAT=2..10                     select native baseline repetitions' \
		'  REPORT_ROOT=<path>               override the ignored report root' \
		'  CONFIRM=delete-stable-signing-identity authorize destructive signing cleanup'
