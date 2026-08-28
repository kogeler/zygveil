# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

FINAL_PREFLIGHT_REPORT_DIR := $(REPORT_ROOT)/acceptance
FINAL_PREFLIGHT_AUTOMATION := tools/automation/final_preflight.py
FINAL_PREFLIGHT_RUN = $(PYTHON) $(FINAL_PREFLIGHT_AUTOMATION) \
	--report-dir '$(FINAL_PREFLIGHT_REPORT_DIR)' \
	--builder-tag '$(BUILDER_TAG)' --dependency-key '$(DEPENDENCY_KEY)'

.PHONY: check attestation-check final-preflight final-preflight-verify

attestation-check: privacy-check topology-check attestation-keys attestation-format-check \
		lint static-analysis syntax \
		test-location-unit test-location-controller-unit \
		test-server-vpn-model test-server-vpn-config \
		signing-info test-network-block confinement-test
	@$(FINAL_PREFLIGHT_RUN) attestation-check

check: docs-check privacy-check topology-check attestation-keys quality \
		test-location-unit test-location-controller-unit \
		test-server-vpn-model test-server-vpn-config \
		signing-info test-network-block confinement-test

final-preflight:
	@$(MAKE) --no-print-directory location-input-check
	@$(FINAL_PREFLIGHT_RUN) prepare
	@$(MAKE) --no-print-directory attestation-check
	@$(FINAL_PREFLIGHT_RUN) record

final-preflight-verify:
	@$(FINAL_PREFLIGHT_RUN) verify
