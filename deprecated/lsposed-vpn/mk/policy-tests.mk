# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

POLICY_REPORT_DIR := $(REPORT_ROOT)/policy

.PHONY: test-unit

test-unit:
	@$(call require_quality_inputs)
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/test-unit.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py test-unit \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/test-unit.txt=$(POLICY_REPORT_DIR)/test-unit.txt'
	@cat '$(POLICY_REPORT_DIR)/test-unit.txt'
