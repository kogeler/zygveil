# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

LOCATION_REPORT_DIR := $(REPORT_ROOT)/location
LOCATION_MODULE := dist/zygveil.zip
LOCATION_POC_NATIVE := .artifacts/poc/location/libzygveil.so
LOCATION_POC_HELPER := .artifacts/poc/location/locationctl
LOCATION_POC_BRIDGE := .artifacts/poc/location/bridge.dex
LOCATION_POC_SHADOWHOOK_HELPER := .artifacts/poc/location/libshadowhook_nothing.so
LOCATION_POC_REPORT_DIR := .artifacts/poc/reports/location
LOCATION_CONTROLLER_APK := dist/zygveil-location-controller-debug.apk
LOCATION_DEVICE_AUTOMATION := tools/automation/location_device.py
LOCATION_DEVICE_RUN = $(PYTHON) $(LOCATION_DEVICE_AUTOMATION) \
	--report-dir '$(LOCATION_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'
LOCATION_POC_DEVICE_RUN = $(PYTHON) $(LOCATION_DEVICE_AUTOMATION) \
	--report-dir '$(LOCATION_POC_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'
LOCATION_CONTROLLER_AUTOMATION := tools/automation/location_controller_device.py
LOCATION_CONTROLLER_RUN = $(PYTHON) $(LOCATION_CONTROLLER_AUTOMATION) \
	--report-dir '$(LOCATION_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'
LOCATION_LIVE_AUTOMATION := tools/automation/location_live_control.py
LOCATION_LIVE_RUN = $(PYTHON) $(LOCATION_LIVE_AUTOMATION) \
	--report-dir '$(LOCATION_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'
LOCATION_POC_LIVE_RUN = $(PYTHON) $(LOCATION_LIVE_AUTOMATION) \
	--report-dir '$(LOCATION_POC_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)' --poc
LOCATION_POC_LIVE_REUSE_AUTOMATION := tools/automation/location_poc_live.py
LOCATION_POC_LIVE_REUSE_RUN = $(PYTHON) $(LOCATION_POC_LIVE_REUSE_AUTOMATION) \
	--report-dir '$(LOCATION_POC_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'
LOCATION_ACCEPTANCE_AUTOMATION := tools/automation/location_acceptance.py
LOCATION_ACCEPTANCE_RUN = $(PYTHON) $(LOCATION_ACCEPTANCE_AUTOMATION) \
	--report-dir '$(LOCATION_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)' \
	--observation-window-ms '$(OBSERVATION_WINDOW_MS)' \
	--location-oracle '$(LOCATION_ORACLE)'
LOCATION_FINAL_ACCEPTANCE_RUN = $(LOCATION_ACCEPTANCE_RUN) \
	--builder-tag '$(BUILDER_TAG)' --dependency-key '$(DEPENDENCY_KEY)' --final-context \
	$(LOCATION_INPUT_ARGUMENTS)
LOCATION_FINAL_INPUT_AUTOMATION := tools/automation/location_final_inputs.py
LOCATION_INPUT_RUN = $(PYTHON) $(LOCATION_FINAL_INPUT_AUTOMATION) \
	--report-dir '$(LOCATION_REPORT_DIR)'
LOCATION_INPUT_ARGUMENTS = --boot-blocked '$(LOCATION_BOOT_BLOCKED)' \
	--boot-passthrough '$(LOCATION_BOOT_PASSTHROUGH)' \
	--oracle-blocked '$(LOCATION_ORACLE_BLOCKED)' \
	--oracle-passthrough '$(LOCATION_ORACLE_PASSTHROUGH)' \
	--live '$(LOCATION_LIVE_FIRST)' --edge '$(LOCATION_LIVE_EDGE)'
EXPECTED_STATE ?= any
LOCATION_LIVE_FILE ?= .state/location-live.properties
LOCATION_ORACLE ?=
LOCATION_CONFIG ?=
LOCATION_BOOT_BLOCKED ?= .state/location-boot-blocked.properties
LOCATION_BOOT_PASSTHROUGH ?= .state/location-boot-passthrough.properties
LOCATION_ORACLE_BLOCKED ?= .state/location-oracle-blocked.properties
LOCATION_ORACLE_PASSTHROUGH ?= .state/location-oracle-passthrough.properties
LOCATION_LIVE_FIRST ?= .state/location-live-second.properties
LOCATION_LIVE_EDGE ?= .state/location-live-edge.properties
EXPECTED_CONTROL_STATE ?=

.PHONY: location-build location-poc-build location-candidate-build \
	location-poc-stage location-poc-reboot \
	location-poc-smoke \
	location-poc-run location-candidate-run location-final-build location-final-attest \
	location-input-check location-final-input-check location-final-input-verify \
	location-controller-build test-location-unit test-location-controller-unit \
	location-install location-install-existing location-update location-update-existing \
	location-uninstall location-set \
	location-status location-enable location-disable location-reboot location-logs location-recover \
	location-controller-install location-controller-install-existing \
	location-controller-ensure-existing \
	location-controller-reinstall location-controller-reinstall-existing location-controller-open \
	location-controller-status location-controller-root-request \
	location-live-set location-live-status \
	location-poc-live-set location-poc-live-status location-poc-live-reuse \
	test-location-baseline test-location-disabled test-location-passthrough test-location-blocked \
	test-location-live test-location-live-edge \
	test-location-isolation test-location-restored \
	test-location-stability test-location-failures test-location-stress \
	test-location-persistence test-location-acceptance \
	test-location-final-baseline test-location-final-disabled \
	test-location-final-passthrough test-location-final-blocked \
	test-location-final-live test-location-final-live-edge \
	test-location-final-isolation test-location-final-stability \
	test-location-final-failures test-location-final-stress \
	test-location-final-persistence test-location-final-restored

location-build: $(if $(filter 1,$(FINAL_ARTIFACT_BUILD)),,image)
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/zygveil.zip .container-output/build-location.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py build-location \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/zygveil.zip=$(LOCATION_MODULE)' \
		--map '.container-output/build-location.txt=$(LOCATION_REPORT_DIR)/build-location.txt'
	@cat '$(LOCATION_REPORT_DIR)/build-location.txt'


location-poc-build:
	@$(call require_builder_image)
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
			--env 'BUILDER_EXPORT=.container-output/libzygveil_app_poc.so .container-output/locationctl-app-poc .container-output/bridge-app-poc.dex .container-output/libshadowhook_nothing-app-poc.so .container-output/build-location-app-poc.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py build-location-app-poc \
	| $(CONTAINER_TOOL) extract \
			--map '.container-output/libzygveil_app_poc.so=$(LOCATION_POC_NATIVE)' \
			--map '.container-output/locationctl-app-poc=$(LOCATION_POC_HELPER)' \
			--map '.container-output/bridge-app-poc.dex=$(LOCATION_POC_BRIDGE)' \
			--map '.container-output/libshadowhook_nothing-app-poc.so=$(LOCATION_POC_SHADOWHOOK_HELPER)' \
			--map '.container-output/build-location-app-poc.txt=$(LOCATION_POC_REPORT_DIR)/build-location-app-poc.txt'
	@printf '%s\n' 'Global application location POC runtime set: native, helper, bridge, linker helper (non-attestable)'

location-candidate-build:
	@$(call require_builder_image)
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
			--env 'BUILDER_EXPORT=.container-output/libzygveil_candidate.so .container-output/locationctl-candidate .container-output/bridge-candidate.dex .container-output/libshadowhook_nothing-candidate.so .container-output/build-location-candidate.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py build-location-candidate \
	| $(CONTAINER_TOOL) extract \
			--map '.container-output/libzygveil_candidate.so=$(LOCATION_POC_NATIVE)' \
			--map '.container-output/locationctl-candidate=$(LOCATION_POC_HELPER)' \
			--map '.container-output/bridge-candidate.dex=$(LOCATION_POC_BRIDGE)' \
			--map '.container-output/libshadowhook_nothing-candidate.so=$(LOCATION_POC_SHADOWHOOK_HELPER)' \
			--map '.container-output/build-location-candidate.txt=$(LOCATION_POC_REPORT_DIR)/build-location-candidate.txt'
	@printf '%s\n' 'Global application production candidate runtime set: native, helper, bridge, linker helper (non-attestable)'

test-location-unit:
	@$(call require_builder_image)
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/test-location-unit.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py test-location-unit \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/test-location-unit.txt=$(LOCATION_REPORT_DIR)/test-location-unit.txt'
	@cat '$(LOCATION_REPORT_DIR)/test-location-unit.txt'

test-location-controller-unit:
	@$(call require_builder_image)
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/test-location-controller-unit.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py test-location-controller-unit \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/test-location-controller-unit.txt=$(LOCATION_REPORT_DIR)/test-location-controller-unit.txt'
	@cat '$(LOCATION_REPORT_DIR)/test-location-controller-unit.txt'

location-controller-build: $(if $(filter 1,$(FINAL_ARTIFACT_BUILD)),,image deps signing-init)
	@$(SOURCE_WITH_BUILD_INPUTS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/zygveil-location-controller-debug.apk .container-output/build-location-controller.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py build-controller \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/zygveil-location-controller-debug.apk=$(LOCATION_CONTROLLER_APK)' \
		--map '.container-output/build-location-controller.txt=$(LOCATION_REPORT_DIR)/build-location-controller.txt'
	@$(CONTAINER_TOOL) apk-status --path '$(LOCATION_CONTROLLER_APK)'
	@cat '$(LOCATION_REPORT_DIR)/build-location-controller.txt'

location-controller-install: location-controller-build
	@$(LOCATION_CONTROLLER_RUN) location-controller-install

location-controller-install-existing:
	@$(LOCATION_CONTROLLER_RUN) location-controller-install

location-controller-ensure-existing:
	@$(LOCATION_CONTROLLER_RUN) location-controller-ensure-existing

location-controller-reinstall: location-controller-build
	@$(LOCATION_CONTROLLER_RUN) location-controller-reinstall

location-controller-reinstall-existing:
	@$(LOCATION_CONTROLLER_RUN) location-controller-reinstall

location-controller-open:
	@$(LOCATION_CONTROLLER_RUN) location-controller-open

location-controller-status:
	@$(LOCATION_CONTROLLER_RUN) location-controller-status

location-controller-root-request:
	@$(LOCATION_CONTROLLER_RUN) location-controller-root-request

location-live-set:
	@$(LOCATION_LIVE_RUN) --input-file '$(LOCATION_LIVE_FILE)' \
		--expected-control-state '$(EXPECTED_CONTROL_STATE)' location-live-set

location-live-status:
	@$(LOCATION_LIVE_RUN) --expected-control-state '$(EXPECTED_CONTROL_STATE)' \
		location-live-status

location-poc-live-set:
	@$(LOCATION_POC_LIVE_RUN) --input-file '$(LOCATION_LIVE_FILE)' \
		--expected-control-state '$(EXPECTED_CONTROL_STATE)' location-live-set

location-poc-live-status:
	@$(LOCATION_POC_LIVE_RUN) --expected-control-state '$(EXPECTED_CONTROL_STATE)' \
		location-live-status

location-poc-live-reuse:
	@$(LOCATION_POC_LIVE_REUSE_RUN) --input-file '$(LOCATION_LIVE_FILE)' \
		--raw-gnss-mode '$(RAW_GNSS_MODE)' \
		--observation-window-ms '$(OBSERVATION_WINDOW_MS)' location-poc-live-reuse

location-install: location-build
	@$(LOCATION_DEVICE_RUN) location-install

location-install-existing:
	@$(LOCATION_DEVICE_RUN) location-install

location-update: location-build
	@$(LOCATION_DEVICE_RUN) location-update

location-update-existing:
	@$(LOCATION_DEVICE_RUN) location-update

location-poc-stage:
	@$(LOCATION_POC_DEVICE_RUN) location-poc-stage

location-poc-reboot:
	@$(LOCATION_POC_DEVICE_RUN) location-poc-reboot

location-poc-smoke:
	@$(LOCATION_POC_DEVICE_RUN) location-poc-smoke

location-poc-run: location-poc-build location-poc-stage location-poc-reboot
	@$(PROBE_POC_RUN) --variant canary --group location \
		--raw-gnss-mode '$(RAW_GNSS_MODE)' \
		--observation-window-ms '$(OBSERVATION_WINDOW_MS)' \
		--location-oracle '$(LOCATION_ORACLE)' probe-run

location-candidate-run: location-candidate-build location-poc-stage location-poc-reboot
	@$(PROBE_POC_RUN) --variant canary --group location \
		--raw-gnss-mode '$(RAW_GNSS_MODE)' \
		--observation-window-ms '$(OBSERVATION_WINDOW_MS)' \
		--location-oracle '$(LOCATION_ORACLE)' probe-run

location-final-build:
	@$(MAKE) --no-print-directory final-preflight-verify
	@$(MAKE) --no-print-directory FINAL_ARTIFACT_BUILD=1 \
		location-controller-build build-probe location-build

location-input-check:
	@$(LOCATION_INPUT_RUN) $(LOCATION_INPUT_ARGUMENTS)

location-final-input-check:
	@$(MAKE) --no-print-directory server-vpn-final-verify
	@$(LOCATION_INPUT_RUN) --builder-tag '$(BUILDER_TAG)' \
		--dependency-key '$(DEPENDENCY_KEY)' --final-context $(LOCATION_INPUT_ARGUMENTS)

location-final-input-verify:
	@$(MAKE) --no-print-directory server-vpn-final-verify
	@$(LOCATION_INPUT_RUN) --builder-tag '$(BUILDER_TAG)' \
		--dependency-key '$(DEPENDENCY_KEY)' --final-context --verify \
		$(LOCATION_INPUT_ARGUMENTS)

location-final-attest:
	@$(MAKE) --no-print-directory server-vpn-final-verify
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-acceptance
	@printf '%s\n' 'Final location candidate and evidence: PASS'

location-uninstall:
	@$(LOCATION_DEVICE_RUN) location-uninstall

location-set:
	@$(LOCATION_DEVICE_RUN) --config-file '$(LOCATION_CONFIG)' location-set

location-status:
	@$(LOCATION_DEVICE_RUN) --expected-state '$(EXPECTED_STATE)' location-status

location-enable:
	@$(LOCATION_DEVICE_RUN) location-enable

location-disable:
	@$(LOCATION_DEVICE_RUN) location-disable

location-reboot:
	@$(LOCATION_DEVICE_RUN) --expected-state '$(EXPECTED_STATE)' location-reboot

location-logs:
	@$(LOCATION_DEVICE_RUN) location-logs

location-recover:
	@$(LOCATION_DEVICE_RUN) location-recover

test-location-baseline:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-baseline

test-location-disabled:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-disabled

test-location-passthrough:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-passthrough

test-location-blocked:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-blocked

test-location-live:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-live

test-location-live-edge:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-live-edge

test-location-isolation:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-isolation

test-location-stability:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-stability

test-location-failures:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-failures

test-location-stress:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-stress

test-location-persistence:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-persistence

test-location-restored:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-restored

test-location-acceptance:
	@$(LOCATION_ACCEPTANCE_RUN) test-location-acceptance

test-location-final-baseline:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-baseline

test-location-final-disabled:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-disabled

test-location-final-passthrough:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-passthrough

test-location-final-blocked:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-blocked

test-location-final-live:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-live

test-location-final-live-edge:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-live-edge

test-location-final-isolation:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-isolation

test-location-final-stability:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-stability

test-location-final-failures:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-failures

test-location-final-stress:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-stress

test-location-final-persistence:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-persistence

test-location-final-restored:
	@$(LOCATION_FINAL_ACCEPTANCE_RUN) test-location-restored
