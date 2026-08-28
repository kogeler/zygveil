# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

PROBE_REPORT_DIR := $(REPORT_ROOT)/probe
PROBE_PRIMARY_APK := dist/zygveil-probe-primary-debug.apk
PROBE_CANARY_APK := dist/zygveil-probe-canary-debug.apk
PROBE_SOURCE_HASH := dist/probe-detector-source.sha256
PROBE_CANARY_POC_APK := .artifacts/poc/probe/zygveil-probe-canary-poc.apk
PROBE_PRIMARY_POC_APK := .artifacts/poc/probe/zygveil-probe-primary-poc.apk
PROBE_POC_REPORT_DIR := .artifacts/poc/reports/probe
PROBE_AUTOMATION := tools/automation/probe.py
PROBE_RUN = $(PYTHON) $(PROBE_AUTOMATION) \
	--report-dir '$(PROBE_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'
PROBE_POC_RUN = $(PYTHON) $(PROBE_AUTOMATION) \
	--report-dir '$(PROBE_POC_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)' --poc
VARIANT ?= primary
VPN_EXPECTED ?=
MODULE_EXPECTED ?=
GROUP ?=
RUN_ID ?=
RAW_GNSS_MODE ?=
OBSERVATION_WINDOW_MS ?= 20000
LOCATION_ORACLE ?=
SERVER_VPN_GROUP ?= server-vpn-sync
SERVER_VPN_CONCURRENT_GROUP ?= server-vpn-async

.PHONY: build-probe probe-apk probe-canary-apk probe-install probe-install-canary \
	probe-install-existing probe-install-canary-existing \
	probe-canary-poc-build probe-canary-poc-install probe-canary-poc-location \
	probe-canary-poc-server-vpn \
	probe-server-vpn-poc-build probe-primary-poc-install \
	probe-server-vpn-poc-run probe-server-vpn-poc-concurrent \
	probe-canary-poc-location-reuse probe-canary-poc-location-trigger \
	probe-run probe-location probe-results probe-cleanup

build-probe: $(if $(filter 1,$(FINAL_ARTIFACT_BUILD)),,image deps signing-init)
	@$(SOURCE_WITH_BUILD_INPUTS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/zygveil-probe-primary-debug.apk .container-output/zygveil-probe-canary-debug.apk .container-output/probe-detector-source.sha256 .container-output/build-probe.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py build-probe \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/zygveil-probe-primary-debug.apk=$(PROBE_PRIMARY_APK)' \
		--map '.container-output/zygveil-probe-canary-debug.apk=$(PROBE_CANARY_APK)' \
		--map '.container-output/probe-detector-source.sha256=$(PROBE_SOURCE_HASH)' \
		--map '.container-output/build-probe.txt=$(PROBE_REPORT_DIR)/build-probe.txt'
	@$(CONTAINER_TOOL) apk-status --path '$(PROBE_PRIMARY_APK)'
	@$(CONTAINER_TOOL) apk-status --path '$(PROBE_CANARY_APK)'
	@cat '$(PROBE_SOURCE_HASH)'

probe-apk: build-probe
	@$(CONTAINER_TOOL) apk-status --path '$(PROBE_PRIMARY_APK)'

probe-canary-apk: build-probe
	@$(CONTAINER_TOOL) apk-status --path '$(PROBE_CANARY_APK)'

probe-canary-poc-build:
	@$(call require_builder_image)
	@test -d '$(DEPENDENCY_DIR)' && test -s '$(SIGNING_KEYSTORE)' || { \
		printf '%s\n' 'POC Android cache/signing input is missing; run make bootstrap once.' >&2; \
		exit 1; \
	}
	@$(SOURCE_WITH_BUILD_INPUTS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/zygveil-probe-canary-poc.apk .container-output/build-probe-canary-poc.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py build-probe-canary-poc \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/zygveil-probe-canary-poc.apk=$(PROBE_CANARY_POC_APK)' \
		--map '.container-output/build-probe-canary-poc.txt=$(PROBE_POC_REPORT_DIR)/build-probe-canary-poc.txt'
	@printf '%s\n' 'POC canary: $(PROBE_CANARY_POC_APK) (non-attestable)'

probe-server-vpn-poc-build:
	@$(call require_builder_image)
	@test -d '$(DEPENDENCY_DIR)' && test -s '$(SIGNING_KEYSTORE)' || { \
		printf '%s\n' 'POC Android cache/signing input is missing; run make bootstrap once.' >&2; \
		exit 1; \
	}
	@$(SOURCE_WITH_BUILD_INPUTS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/zygveil-probe-primary-poc.apk .container-output/zygveil-probe-canary-poc.apk .container-output/build-probe-server-vpn-poc.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py build-probe-server-vpn-poc \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/zygveil-probe-primary-poc.apk=$(PROBE_PRIMARY_POC_APK)' \
		--map '.container-output/zygveil-probe-canary-poc.apk=$(PROBE_CANARY_POC_APK)' \
		--map '.container-output/build-probe-server-vpn-poc.txt=$(PROBE_POC_REPORT_DIR)/build-probe-server-vpn-poc.txt'
	@printf '%s\n' 'POC probe pair: $(PROBE_PRIMARY_POC_APK) $(PROBE_CANARY_POC_APK) (non-attestable)'

probe-install: probe-apk
	@$(PROBE_RUN) probe-install

probe-install-canary: probe-canary-apk
	@$(PROBE_RUN) probe-install-canary

probe-install-existing:
	@$(PROBE_RUN) probe-install

probe-install-canary-existing:
	@$(PROBE_RUN) probe-install-canary

probe-canary-poc-install:
	@$(PROBE_POC_RUN) probe-install-canary-poc

probe-primary-poc-install:
	@$(PROBE_POC_RUN) probe-install-primary-poc

probe-canary-poc-location:
	@$(PROBE_POC_RUN) --variant canary --group location \
		--raw-gnss-mode '$(RAW_GNSS_MODE)' \
		--observation-window-ms '$(OBSERVATION_WINDOW_MS)' \
		--location-oracle '$(LOCATION_ORACLE)' probe-run

probe-canary-poc-location-reuse:
	@$(PROBE_POC_RUN) --reuse-process --variant canary --group location \
		--raw-gnss-mode '$(RAW_GNSS_MODE)' \
		--observation-window-ms '$(OBSERVATION_WINDOW_MS)' \
		--location-oracle '$(LOCATION_ORACLE)' probe-run

probe-canary-poc-location-trigger:
	@$(PROBE_POC_RUN) --poc-no-oracle --variant canary --group location \
		--raw-gnss-mode '$(RAW_GNSS_MODE)' \
		--observation-window-ms '$(OBSERVATION_WINDOW_MS)' probe-run

probe-canary-poc-server-vpn:
	@$(PROBE_POC_RUN) --variant canary --group '$(SERVER_VPN_GROUP)' \
		--vpn-expected on --module-expected off probe-run

probe-server-vpn-poc-run:
	@$(PROBE_POC_RUN) --variant '$(VARIANT)' --group '$(SERVER_VPN_GROUP)' \
		--vpn-expected on --module-expected on probe-run

probe-server-vpn-poc-concurrent:
	@$(PROBE_POC_RUN) --group '$(SERVER_VPN_CONCURRENT_GROUP)' \
		probe-server-vpn-concurrent

probe-run:
	@$(PROBE_RUN) --variant '$(VARIANT)' --vpn-expected '$(VPN_EXPECTED)' \
		--module-expected '$(MODULE_EXPECTED)' --group '$(GROUP)' \
		--raw-gnss-mode '$(RAW_GNSS_MODE)' \
		--observation-window-ms '$(OBSERVATION_WINDOW_MS)' \
		--location-oracle '$(LOCATION_ORACLE)' probe-run

probe-location:
	@$(PROBE_RUN) --variant '$(VARIANT)' --group location \
		--raw-gnss-mode '$(RAW_GNSS_MODE)' \
		--observation-window-ms '$(OBSERVATION_WINDOW_MS)' \
		--location-oracle '$(LOCATION_ORACLE)' probe-run

probe-results:
	@$(PROBE_RUN) --run-id '$(RUN_ID)' probe-results

probe-cleanup:
	@$(PROBE_RUN) --run-id '$(RUN_ID)' probe-cleanup
