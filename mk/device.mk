# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

ADB_DEVICE_REPORT_DIR := $(REPORT_ROOT)/device
ADB_DEVICE_AUTOMATION := tools/automation/adb_device.py
ADB_DEVICE_RUN = $(PYTHON) $(ADB_DEVICE_AUTOMATION) \
	--report-dir '$(ADB_DEVICE_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'

.PHONY: adb-root adb-unroot device-ui-ready

device-ui-ready:
	@$(ADB_DEVICE_RUN) device-ui-ready

adb-root:
	@$(ADB_DEVICE_RUN) adb-root

adb-unroot:
	@$(ADB_DEVICE_RUN) adb-unroot
