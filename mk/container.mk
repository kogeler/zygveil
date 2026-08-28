# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

PODMAN ?= podman
CONTAINER_TOOL := $(PYTHON) tools/automation/container.py
IMAGE_KEY := $(shell $(CONTAINER_TOOL) key image)
DEPENDENCY_KEY := $(shell $(CONTAINER_TOOL) key dependencies)
BUILDER_TAG := localhost/zygveil-builder:$(IMAGE_KEY)
BUILDER_CONTEXT := containers/builder/Containerfile containers/builder/entrypoint.sh
CONTAINER_REPORT_DIR := $(REPORT_ROOT)/container
DEPENDENCY_DIR := .artifacts/dependencies/$(DEPENDENCY_KEY)
IMAGE_ARCHIVE := .artifacts/images/android-builder-$(IMAGE_KEY).oci.tar
SIGNING_KEYSTORE := .state/debug.keystore

BUILDER_CONFINE = \
	--rm \
	--interactive \
	--network=none \
	--userns=auto:size=2048 \
	--security-opt=no-new-privileges \
	--cap-drop=ALL \
	--read-only \
	--read-only-tmpfs=false \
	--ipc=private \
	--pid=private \
	--uts=private \
	--cgroupns=private \
	--systemd=false \
	--no-hosts \
	--unsetenv-all \
	--umask=077 \
	--pids-limit=1024 \
	--memory=8g \
	--memory-swap=8g \
	--ulimit=nofile=4096:4096 \
	--log-driver=none \
	--timeout=1800 \
	--pull=never \
	--label=zygveil.owner \
	--tmpfs=/tmp:rw,nosuid,nodev,size=4g,mode=1777 \
	--tmpfs=/work:rw,exec,nosuid,nodev,size=4g,mode=1777 \
	--env HOME=/tmp/home \
	--env LANG=C.UTF-8 \
	--env LC_ALL=C.UTF-8 \
	--env TZ=UTC \
	--env JAVA_HOME=/opt/java \
	--env ANDROID_HOME=/opt/android-sdk \
	--env ANDROID_SDK_ROOT=/opt/android-sdk \
	--env ANDROID_USER_HOME=/tmp/home/.android \
	--env GRADLE_USER_HOME=/tmp/home/.gradle \
	--env 'GRADLE_OPTS=-Duser.home=/tmp/home' \
	--env PATH=/opt/java/bin:/opt/android-sdk/platform-tools:/usr/local/bin:/usr/bin:/bin

BUILDER_ONLINE = $(subst --network=none,--network=slirp4netns,$(BUILDER_CONFINE))
DEPENDENCY_ONLINE = $(filter-out --tmpfs=/tmp:% --tmpfs=/work:%,$(BUILDER_ONLINE)) \
	--tmpfs=/tmp:rw,nosuid,nodev,size=16g,mode=1777 \
	--tmpfs=/work:rw,exec,nosuid,nodev,size=4g,mode=1777

SOURCE_ARCHIVE = $(CONTAINER_TOOL) source-archive
SOURCE_WITH_DEPS = $(SOURCE_ARCHIVE) \
	--dependency-dir '$(DEPENDENCY_DIR)' --dependency-key '$(DEPENDENCY_KEY)'
SOURCE_WITH_BUILD_INPUTS = $(SOURCE_WITH_DEPS) --keystore '$(SIGNING_KEYSTORE)'

define require_builder_image
	$(PODMAN) image exists '$(BUILDER_TAG)' || { \
		printf '%s\n' 'builder is missing; run make bootstrap once.' >&2; exit 1; \
	}
endef

.PHONY: image-key image deps bootstrap image-save image-load confinement-test \
	test-network-block signing-init signing-info shellcheck clean-containers

image-key:
	@printf 'builder=%s\ndependencies=%s\n' '$(IMAGE_KEY)' '$(DEPENDENCY_KEY)'

image:
	@$(PODMAN) image exists '$(BUILDER_TAG)' || { \
		printf 'building %s\n' '$(BUILDER_TAG)' >&2; \
		$(PODMAN) build --quiet --pull=missing --tag '$(BUILDER_TAG)' \
			--label=zygveil.owner \
			--file containers/builder/Containerfile . >/dev/null; \
	}
	@$(PODMAN) image inspect '$(BUILDER_TAG)' \
		--format 'builder={{.RepoTags}} image_id={{.Id}} digest={{.Digest}}'
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/image.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py toolchain-info \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/image.txt=$(CONTAINER_REPORT_DIR)/image.txt'
	@cat '$(CONTAINER_REPORT_DIR)/image.txt'

deps: image
	@if $(CONTAINER_TOOL) dependency-status \
		--directory '$(DEPENDENCY_DIR)' --dependency-key '$(DEPENDENCY_KEY)' >/dev/null 2>&1; then \
		$(CONTAINER_TOOL) dependency-status \
			--directory '$(DEPENDENCY_DIR)' --dependency-key '$(DEPENDENCY_KEY)'; \
	else \
		$(SOURCE_ARCHIVE) \
		| $(PODMAN) run $(DEPENDENCY_ONLINE) \
			--env DEPENDENCY_KEY='$(DEPENDENCY_KEY)' \
			--env 'BUILDER_EXPORT=.container-output/gradle-home.tar .container-output/manifest.json .container-output/verification-metadata.xml' \
			--env BUILDER_EXPORT_ON_SUCCESS=1 \
			'$(BUILDER_TAG)' python3 tools/automation/container_job.py dependencies \
		| $(CONTAINER_TOOL) extract \
			--map '.container-output/gradle-home.tar=$(DEPENDENCY_DIR)/gradle-home.tar' \
			--map '.container-output/manifest.json=$(DEPENDENCY_DIR)/manifest.json' \
			--map '.container-output/verification-metadata.xml=gradle/verification-metadata.xml'; \
		$(CONTAINER_TOOL) dependency-status \
			--directory '$(DEPENDENCY_DIR)' --dependency-key '$(DEPENDENCY_KEY)'; \
	fi

bootstrap: doctor image deps signing-init

image-save: image
	@mkdir -p '$(dir $(IMAGE_ARCHIVE))'
	@temporary='$(IMAGE_ARCHIVE).tmp.'$$$$; \
		trap 'rm -f "$$temporary"' EXIT; \
		$(PODMAN) save --quiet --format oci-archive \
			--output "$$temporary" '$(BUILDER_TAG)'; \
		mv -f "$$temporary" '$(IMAGE_ARCHIVE)'

image-load:
	@test -r '$(IMAGE_ARCHIVE)' || { \
		printf 'builder archive is missing: %s\n' '$(IMAGE_ARCHIVE)' >&2; exit 1; \
	}
	@$(PODMAN) load --quiet --input '$(IMAGE_ARCHIVE)' >/dev/null
	@$(PODMAN) image exists '$(BUILDER_TAG)'

test-network-block: image
	@$(SOURCE_ARCHIVE) \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/network-block.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py network-block \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/network-block.txt=$(CONTAINER_REPORT_DIR)/network-block.txt'

confinement-test: test-network-block
	@before=$$($(CONTAINER_TOOL) digest Makefile); \
		$(SOURCE_ARCHIVE) \
		| $(PODMAN) run $(BUILDER_CONFINE) \
			--env 'BUILDER_EXPORT=.container-output/confinement.txt' \
			--env BUILDER_EXPORT_ON_SUCCESS=1 \
			'$(BUILDER_TAG)' python3 tools/automation/container_job.py confinement \
		| $(CONTAINER_TOOL) extract \
			--map '.container-output/confinement.txt=$(CONTAINER_REPORT_DIR)/confinement.txt'; \
		after=$$($(CONTAINER_TOOL) digest Makefile); \
		test "$$before" = "$$after" || { \
			printf 'host checkout changed during confinement test\n' >&2; exit 1; \
		}; \
		printf 'host_source_unchanged=true\n' >> '$(CONTAINER_REPORT_DIR)/confinement.txt'

signing-init: image
	@if [[ -f '$(SIGNING_KEYSTORE)' ]]; then \
		printf 'stable keystore exists: %s\n' '$(SIGNING_KEYSTORE)'; \
	else \
		$(SOURCE_ARCHIVE) \
		| $(PODMAN) run $(BUILDER_CONFINE) \
			--env 'BUILDER_EXPORT=.container-output/debug.keystore .container-output/signing-init.txt' \
			--env BUILDER_EXPORT_ON_SUCCESS=1 \
			'$(BUILDER_TAG)' python3 tools/automation/container_job.py signing-init \
		| $(CONTAINER_TOOL) extract \
			--map '.container-output/debug.keystore=$(SIGNING_KEYSTORE)' \
			--map '.container-output/signing-init.txt=$(CONTAINER_REPORT_DIR)/signing-init.txt'; \
		chmod 0600 '$(SIGNING_KEYSTORE)'; \
	fi

signing-info: image signing-init
	@$(SOURCE_ARCHIVE) --keystore '$(SIGNING_KEYSTORE)' \
	| $(PODMAN) run $(BUILDER_CONFINE) \
		--env 'BUILDER_EXPORT=.container-output/signing-info.txt' \
		--env BUILDER_EXPORT_ON_SUCCESS=1 \
		'$(BUILDER_TAG)' python3 tools/automation/container_job.py signing-info \
	| $(CONTAINER_TOOL) extract \
		--map '.container-output/signing-info.txt=$(CONTAINER_REPORT_DIR)/signing-info.txt'
	@cat '$(CONTAINER_REPORT_DIR)/signing-info.txt'

shellcheck: image
	@$(SOURCE_ARCHIVE) | $(PODMAN) run $(BUILDER_CONFINE) \
		'$(BUILDER_TAG)' shellcheck containers/builder/entrypoint.sh gradlew \
			components/zygisk-host/module/customize.sh \
			components/zygisk-host/module/guard.sh \
			components/zygisk-host/module/post-fs-data.sh

clean-containers:
	@stale=$$($(PODMAN) ps --all --quiet \
		--filter 'label=zygveil.owner' 2>/dev/null); \
	if [[ -n "$$stale" ]]; then \
		$(PODMAN) rm --force --time 5 $$stale >/dev/null; \
	fi
	@images=$$($(PODMAN) images --quiet \
		--filter 'reference=localhost/zygveil-builder:*' 2>/dev/null); \
	if [[ -n "$$images" ]]; then \
		$(PODMAN) rmi --force $$images >/dev/null; \
	fi
