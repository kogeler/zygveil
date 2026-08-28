# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

BUILD_REPORT_DIR := $(REPORT_ROOT)/build
BUILD_ARTIFACT_DIR := .artifacts/build
BUILT_MODULE_APK := $(BUILD_ARTIFACT_DIR)/zygveil-legacy-vpn-debug.apk
MODULE_APK := dist/zygveil-legacy-vpn-debug.apk
ARTIFACT_AUTOMATION := tools/automation/artifacts.py

.PHONY: build export apk

build:
	@$(call require_quality_inputs)
	@test -f '$(SIGNING_KEYSTORE)' || { \
		printf 'stable signing input is missing; run make bootstrap\n' >&2; exit 1; \
	}
	@$(SOURCE_WITH_BUILD_INPUTS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/zygveil-legacy-vpn-debug.apk .container-output/build.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py build-production \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/zygveil-legacy-vpn-debug.apk=$(BUILT_MODULE_APK)' \
		--map '.container-output/build.txt=$(BUILD_REPORT_DIR)/build.txt'
	@$(CONTAINER_TOOL) apk-status --module --path '$(BUILT_MODULE_APK)'

export: build
	@$(PYTHON) $(ARTIFACT_AUTOMATION) --report-dir '$(BUILD_REPORT_DIR)' export
	@$(CONTAINER_TOOL) apk-status --module --path '$(MODULE_APK)'
	@cat '$(MODULE_APK).sha256'

apk: quality test-unit export
