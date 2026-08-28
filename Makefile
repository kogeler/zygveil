# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help
.NOTPARALLEL:
.DELETE_ON_ERROR:

include mk/common.mk
include mk/baseline.mk
include mk/container.mk
include mk/quality.mk
include mk/location.mk
include mk/server-vpn.mk
include mk/device.mk
include mk/probe.mk
include mk/acceptance.mk
include mk/maintenance.mk
