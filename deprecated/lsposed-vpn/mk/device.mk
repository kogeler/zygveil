# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

DEVICE_REPORT_DIR := $(REPORT_ROOT)/device
DEVICE_AUTOMATION := tools/automation/device.py
DEVICE_RUN = $(PYTHON) $(DEVICE_AUTOMATION) \
	--report-dir '$(DEVICE_REPORT_DIR)' --adb-serial '$(ADB_SERIAL)'
.PHONY: adb-root adb-unroot install reinstall scope-status target-restart logs logs-clear

adb-root:
	@$(DEVICE_RUN) adb-root

adb-unroot:
	@$(DEVICE_RUN) adb-unroot

install:
	@$(DEVICE_RUN) install

reinstall:
	@$(DEVICE_RUN) reinstall

scope-status:
	@$(DEVICE_RUN) scope-status

target-restart:
	@$(DEVICE_RUN) target-restart

logs:
	@$(DEVICE_RUN) logs

logs-clear:
	@$(DEVICE_RUN) logs-clear
