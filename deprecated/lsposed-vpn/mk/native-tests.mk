# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

NATIVE_REPORT_DIR := $(REPORT_ROOT)/native
NATIVE_AUTOMATION := tools/automation/native_tests.py
REPEAT ?= 3

.PHONY: test-native-sync test-native-async test-native-link

test-native-sync:
	@$(PYTHON) $(NATIVE_AUTOMATION) --report-dir '$(NATIVE_REPORT_DIR)' \
		--adb-serial '$(ADB_SERIAL)' --vpn-expected '$(VPN_EXPECTED)' \
		--repeat '$(REPEAT)' test-native-sync

test-native-async:
	@$(PYTHON) $(NATIVE_AUTOMATION) --report-dir '$(NATIVE_REPORT_DIR)' \
		--adb-serial '$(ADB_SERIAL)' --vpn-expected '$(VPN_EXPECTED)' \
		--repeat '$(REPEAT)' test-native-async

test-native-link:
	@$(PYTHON) $(NATIVE_AUTOMATION) --report-dir '$(NATIVE_REPORT_DIR)' \
		--adb-serial '$(ADB_SERIAL)' --vpn-expected '$(VPN_EXPECTED)' \
		--repeat '$(REPEAT)' test-native-link
