# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

BASELINE_REPORT_DIR := $(REPORT_ROOT)/baseline
BASELINE_AUTOMATION := tools/automation/baseline.py
BASELINE_RUN = $(PYTHON) $(BASELINE_AUTOMATION) --report-dir '$(BASELINE_REPORT_DIR)'

.PHONY: doctor docs-check privacy-check topology-check attestation-keys vpn-status syntax

doctor:
	@$(BASELINE_RUN) doctor

docs-check:
	@$(BASELINE_RUN) docs-check

privacy-check:
	@$(BASELINE_RUN) privacy-check

topology-check:
	@$(BASELINE_RUN) topology-check

attestation-keys:
	@$(BASELINE_RUN) attestation-keys

vpn-status:
	@$(BASELINE_RUN) --adb-serial '$(ADB_SERIAL)' vpn-status

syntax:
	@$(BASELINE_RUN) syntax
