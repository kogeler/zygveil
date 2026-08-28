# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

QUALITY_REPORT_DIR := $(REPORT_ROOT)/quality
FORMATTED_ARCHIVE := .artifacts/quality/formatted-source.tar

define require_quality_inputs
	$(PODMAN) image exists '$(BUILDER_TAG)' || { \
		printf 'builder image is missing; run make bootstrap\n' >&2; exit 1; \
	}; \
	$(CONTAINER_TOOL) dependency-status \
		--directory '$(DEPENDENCY_DIR)' --dependency-key '$(DEPENDENCY_KEY)' >/dev/null || { \
		printf 'dependency cache is missing; run make bootstrap\n' >&2; exit 1; \
	}
endef

.PHONY: format format-check attestation-format-check lint static-analysis quality

format:
	@$(call require_quality_inputs)
	@$(SOURCE_WITH_DEPS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/formatted-source.tar .container-output/format.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py format-source \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/formatted-source.tar=$(FORMATTED_ARCHIVE)' \
		--map '.container-output/format.txt=$(QUALITY_REPORT_DIR)/format.txt'
	@$(CONTAINER_TOOL) apply-formatted --archive '$(FORMATTED_ARCHIVE)'
	@rm -f '$(FORMATTED_ARCHIVE)'

format-check:
	@$(call require_quality_inputs)
	@$(SOURCE_WITH_DEPS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/format-check.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py format-check \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/format-check.txt=$(QUALITY_REPORT_DIR)/format-check.txt'

attestation-format-check:
	@$(call require_quality_inputs)
	@$(SOURCE_WITH_DEPS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/attestation-format-check.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py attestation-format-check \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/attestation-format-check.txt=$(QUALITY_REPORT_DIR)/attestation-format-check.txt'

lint:
	@$(call require_quality_inputs)
	@$(SOURCE_WITH_DEPS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/lint.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py lint \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/lint.txt=$(QUALITY_REPORT_DIR)/lint.txt'

static-analysis:
	@$(call require_quality_inputs)
	@$(SOURCE_WITH_DEPS) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/static-analysis.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py static-analysis \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/static-analysis.txt=$(QUALITY_REPORT_DIR)/static-analysis.txt'

quality: format-check lint static-analysis syntax
