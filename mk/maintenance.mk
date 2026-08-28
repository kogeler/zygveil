# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

MAINTENANCE_REPORT_DIR := $(REPORT_ROOT)/maintenance
MAINTENANCE_AUTOMATION := tools/automation/maintenance.py

.PHONY: clean clean-signing

clean:
	@$(PYTHON) $(MAINTENANCE_AUTOMATION) --report-dir '$(MAINTENANCE_REPORT_DIR)' clean

clean-signing:
	@$(PYTHON) $(MAINTENANCE_AUTOMATION) --report-dir '$(MAINTENANCE_REPORT_DIR)' \
		--confirm '$(CONFIRM)' clean-signing
