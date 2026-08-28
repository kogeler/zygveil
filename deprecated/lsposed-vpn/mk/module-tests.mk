# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

MODULE_TEST_REPORT_DIR := $(REPORT_ROOT)/module
MODULE_TEST_AUTOMATION := tools/automation/module_tests.py

.PHONY: test-module-sync test-module-async test-module-link

test-module-sync:
	@$(PYTHON) $(MODULE_TEST_AUTOMATION) --report-dir '$(MODULE_TEST_REPORT_DIR)' \
		--native-report-dir '$(NATIVE_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)' \
		--vpn-expected '$(VPN_EXPECTED)' --module-expected '$(MODULE_EXPECTED)' \
		--repeat '$(REPEAT)' test-module-sync

test-module-async:
	@$(PYTHON) $(MODULE_TEST_AUTOMATION) --report-dir '$(MODULE_TEST_REPORT_DIR)' \
		--native-report-dir '$(NATIVE_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)' \
		--vpn-expected '$(VPN_EXPECTED)' --module-expected '$(MODULE_EXPECTED)' \
		--repeat '$(REPEAT)' test-module-async

test-module-link:
	@$(PYTHON) $(MODULE_TEST_AUTOMATION) --report-dir '$(MODULE_TEST_REPORT_DIR)' \
		--native-report-dir '$(NATIVE_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)' \
		--vpn-expected '$(VPN_EXPECTED)' --module-expected '$(MODULE_EXPECTED)' \
		--repeat '$(REPEAT)' test-module-link
