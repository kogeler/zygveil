# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

SERVER_VPN_POC_DIR := .artifacts/poc/server-vpn
SERVER_VPN_POC_REPORT_DIR := .artifacts/poc/reports/server-vpn
SERVER_VPN_REPORT_DIR := $(REPORT_ROOT)/server-vpn
SERVER_VPN_COMBINED_HOST_ZIP := $(SERVER_VPN_POC_DIR)/zygveil-poc.zip
SERVER_VPN_POC_NATIVE := $(SERVER_VPN_POC_DIR)/combined-host/libzygveil.so
SERVER_VPN_POC_LOCATION_HELPER := $(SERVER_VPN_POC_DIR)/combined-host/locationctl
SERVER_VPN_POC_LOCATION_BRIDGE := $(SERVER_VPN_POC_DIR)/combined-host/bridge.dex
SERVER_VPN_POC_BRIDGE := $(SERVER_VPN_POC_DIR)/combined-host/server-vpn-bridge.dex
SERVER_VPN_POC_SHADOWHOOK := $(SERVER_VPN_POC_DIR)/combined-host/libshadowhook_nothing.so
SERVER_VPN_DEVICE_AUTOMATION := tools/automation/server_vpn_device.py
SERVER_VPN_DEVICE_RUN = $(PYTHON) $(SERVER_VPN_DEVICE_AUTOMATION) \
	--report-dir '$(SERVER_VPN_POC_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'
SERVER_VPN_POC_EXPECTED ?= active
SERVER_VPN_PROBE_GROUP ?= server-vpn-async
SERVER_VPN_BASELINE_PHASE ?=
SERVER_VPN_ACTIVE_PHASE ?=
SERVER_VPN_ROLLBACK_PHASE ?=
SERVER_VPN_FINAL_REPORT_DIR := $(REPORT_ROOT)/server-vpn-final
SERVER_VPN_FINAL_AUTOMATION := tools/automation/server_vpn_final.py
SERVER_VPN_FINAL_RUN = $(PYTHON) $(SERVER_VPN_FINAL_AUTOMATION) \
	--report-dir '$(SERVER_VPN_FINAL_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)' \
	--builder-tag '$(BUILDER_TAG)' --dependency-key '$(DEPENDENCY_KEY)'
SERVER_VPN_FINAL_EXPECTED ?= active
SERVER_VPN_FINAL_PHASE_KIND ?= baseline
SERVER_VPN_FINAL_BASELINE_PHASE ?=
SERVER_VPN_FINAL_ACTIVE_PHASE ?=
SERVER_VPN_FINAL_ROLLBACK_PHASE ?=

.PHONY: test-server-vpn-model test-server-vpn-config server-vpn-poc-build \
	server-vpn-poc-install server-vpn-poc-reboot server-vpn-poc-status \
	server-vpn-poc-isolation server-vpn-poc-stock-probe server-vpn-poc-probe \
	server-vpn-poc-differential server-vpn-poc-recover \
	server-vpn-final-build server-vpn-final-verify server-vpn-final-install \
	server-vpn-final-enable server-vpn-final-disable \
	server-vpn-final-reboot server-vpn-final-status server-vpn-final-isolation \
	server-vpn-final-stock-suite server-vpn-final-active-suite \
	server-vpn-final-recover server-vpn-final-acceptance server-vpn-final-attest

test-server-vpn-model:
	@$(call require_builder_image)
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/test-server-vpn-model.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py \
			test-server-vpn-model \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/test-server-vpn-model.txt=$(SERVER_VPN_REPORT_DIR)/test-server-vpn-model.txt'
	@cat '$(SERVER_VPN_REPORT_DIR)/test-server-vpn-model.txt'

test-server-vpn-config:
	@$(call require_builder_image)
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/test-server-vpn-config.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py \
			test-server-vpn-config \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/test-server-vpn-config.txt=$(SERVER_VPN_REPORT_DIR)/test-server-vpn-config.txt'
	@cat '$(SERVER_VPN_REPORT_DIR)/test-server-vpn-config.txt'

server-vpn-poc-build:
	@$(call require_builder_image)
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/zygveil-poc.zip .container-output/libzygveil_server_vpn_poc.so .container-output/locationctl-server-vpn-poc .container-output/bridge-server-vpn-poc.dex .container-output/server-vpn-bridge-poc.dex .container-output/libshadowhook_nothing-server-vpn-poc.so .container-output/build-server-vpn-poc.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py build-server-vpn-poc \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/zygveil-poc.zip=$(SERVER_VPN_COMBINED_HOST_ZIP)' \
		--map '.container-output/libzygveil_server_vpn_poc.so=$(SERVER_VPN_POC_NATIVE)' \
		--map '.container-output/locationctl-server-vpn-poc=$(SERVER_VPN_POC_LOCATION_HELPER)' \
		--map '.container-output/bridge-server-vpn-poc.dex=$(SERVER_VPN_POC_LOCATION_BRIDGE)' \
		--map '.container-output/server-vpn-bridge-poc.dex=$(SERVER_VPN_POC_BRIDGE)' \
		--map '.container-output/libshadowhook_nothing-server-vpn-poc.so=$(SERVER_VPN_POC_SHADOWHOOK)' \
		--map '.container-output/build-server-vpn-poc.txt=$(SERVER_VPN_POC_REPORT_DIR)/build-server-vpn-poc.txt'
	@cat '$(SERVER_VPN_POC_REPORT_DIR)/build-server-vpn-poc.txt'

server-vpn-poc-install:
	@$(SERVER_VPN_DEVICE_RUN) poc-install

server-vpn-poc-reboot:
	@$(SERVER_VPN_DEVICE_RUN) --expected '$(SERVER_VPN_POC_EXPECTED)' poc-reboot

server-vpn-poc-status:
	@$(SERVER_VPN_DEVICE_RUN) --expected '$(SERVER_VPN_POC_EXPECTED)' poc-status

server-vpn-poc-isolation:
	@$(SERVER_VPN_DEVICE_RUN) --expected '$(SERVER_VPN_POC_EXPECTED)' poc-isolation

server-vpn-poc-stock-probe:
	@$(SERVER_VPN_DEVICE_RUN) --group '$(SERVER_VPN_PROBE_GROUP)' poc-stock-probe

server-vpn-poc-probe:
	@$(SERVER_VPN_DEVICE_RUN) --group '$(SERVER_VPN_PROBE_GROUP)' poc-active-probe

server-vpn-poc-differential:
	@$(SERVER_VPN_DEVICE_RUN) \
		--baseline-phase '$(SERVER_VPN_BASELINE_PHASE)' \
		--active-phase '$(SERVER_VPN_ACTIVE_PHASE)' \
		--rollback-phase '$(SERVER_VPN_ROLLBACK_PHASE)' \
		poc-differential

server-vpn-poc-recover:
	@$(SERVER_VPN_DEVICE_RUN) poc-recover

server-vpn-final-build:
	@$(MAKE) --no-print-directory location-final-build
	@$(SERVER_VPN_FINAL_RUN) final-freeze

server-vpn-final-verify:
	@$(SERVER_VPN_FINAL_RUN) final-verify

server-vpn-final-install:
	@$(SERVER_VPN_FINAL_RUN) final-install

server-vpn-final-enable:
	@$(SERVER_VPN_FINAL_RUN) final-enable

server-vpn-final-disable:
	@$(SERVER_VPN_FINAL_RUN) final-disable

server-vpn-final-reboot:
	@$(SERVER_VPN_FINAL_RUN) --expected '$(SERVER_VPN_FINAL_EXPECTED)' final-reboot

server-vpn-final-status:
	@$(SERVER_VPN_FINAL_RUN) --expected '$(SERVER_VPN_FINAL_EXPECTED)' final-status

server-vpn-final-isolation:
	@$(SERVER_VPN_FINAL_RUN) final-isolation

server-vpn-final-stock-suite:
	@$(SERVER_VPN_FINAL_RUN) --phase-kind '$(SERVER_VPN_FINAL_PHASE_KIND)' final-stock-suite

server-vpn-final-active-suite:
	@$(SERVER_VPN_FINAL_RUN) final-active-suite

server-vpn-final-recover:
	@$(SERVER_VPN_FINAL_RUN) final-recover

server-vpn-final-acceptance:
	@$(SERVER_VPN_FINAL_RUN) \
		--baseline-phase '$(SERVER_VPN_FINAL_BASELINE_PHASE)' \
		--active-phase '$(SERVER_VPN_FINAL_ACTIVE_PHASE)' \
		--rollback-phase '$(SERVER_VPN_FINAL_ROLLBACK_PHASE)' \
		final-acceptance

server-vpn-final-attest:
	@$(MAKE) --no-print-directory server-vpn-final-verify
	@$(MAKE) --no-print-directory server-vpn-final-acceptance
	@$(MAKE) --no-print-directory location-final-attest
	@printf '%s\n' 'Frozen combined-host server-VPN and location evidence: PASS'
