# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

ACCEPTANCE_REPORT_DIR := $(REPORT_ROOT)/acceptance
ACCEPTANCE_AUTOMATION := tools/automation/acceptance.py
ACCEPTANCE_RUN = $(PYTHON) $(ACCEPTANCE_AUTOMATION) \
	--report-dir '$(ACCEPTANCE_REPORT_DIR)' --native-report-dir '$(NATIVE_REPORT_DIR)' \
	--module-report-dir '$(MODULE_TEST_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'

.PHONY: test-data-plane test-rollback test-baseline test-device test-matrix \
	check cycle rollback

test-data-plane:
	@$(ACCEPTANCE_RUN) --vpn-expected '$(VPN_EXPECTED)' \
		--module-expected '$(MODULE_EXPECTED)' test-data-plane

test-rollback:
	@$(ACCEPTANCE_RUN) --vpn-expected '$(VPN_EXPECTED)' \
		--module-expected '$(MODULE_EXPECTED)' --repeat '$(REPEAT)' test-rollback

test-baseline:
	@$(ACCEPTANCE_RUN) test-baseline

test-device:
	@$(ACCEPTANCE_RUN) test-device

test-matrix:
	@$(ACCEPTANCE_RUN) test-matrix

check: docs-check attestation-keys quality test-unit signing-info confinement-test
	@$(ACCEPTANCE_RUN) check

cycle: apk reinstall target-restart logs

rollback: framework-manager-open
	@printf '%s\n' \
		'Disable ZygVeil Legacy VPN in the supported manager UI; keep VPN ON and exact probe scope.' \
		'Then run: make test-data-plane VPN_EXPECTED=on MODULE_EXPECTED=off' \
		'Finally run: make test-rollback VPN_EXPECTED=on MODULE_EXPECTED=off'
