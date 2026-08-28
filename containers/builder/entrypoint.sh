#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

set -euo pipefail

if [[ "$(id -u)" -eq 0 ]]; then
    printf 'android-builder: refusing root uid\n' >&2
    exit 1
fi
if ! grep -Eq '^CapEff:[[:space:]]+0+$' /proc/self/status; then
    printf 'android-builder: effective capabilities are not empty\n' >&2
    exit 1
fi
if ! grep -Eq '^NoNewPrivs:[[:space:]]+1$' /proc/self/status; then
    printf 'android-builder: NoNewPrivs is not set\n' >&2
    exit 1
fi
if ! grep -Eq '^Seccomp:[[:space:]]+2$' /proc/self/status; then
    printf 'android-builder: seccomp filtering is not active\n' >&2
    exit 1
fi
(($#)) || {
    printf 'android-builder: no command given\n' >&2
    exit 2
}

mkdir -p "$HOME" "$ANDROID_USER_HOME" "$GRADLE_USER_HOME"
chmod 0700 "$HOME"
[[ ! -e /work/src ]] || {
    printf 'android-builder: unexpected pre-existing work tree\n' >&2
    exit 1
}
mkdir -p /work/src /work/out
chmod 0700 /work/src /work/out
tar --extract --file=- --directory=/work/src
mkdir -p /work/src/gradle/wrapper
cp /opt/gradle-wrapper/gradle-wrapper.jar /work/src/gradle/wrapper/gradle-wrapper.jar
cd /work/src

if [[ -z "${BUILDER_EXPORT:-}" ]]; then
    exec "$@"
fi

status=0
"$@" >&2 || status=$?
if ((status != 0)) && [[ "${BUILDER_EXPORT_ON_SUCCESS:-0}" == 1 ]]; then
    tar --create --file=- --files-from=/dev/null
    exit "$status"
fi

exported=()
for path in ${BUILDER_EXPORT}; do
    if [[ -e "$path" ]]; then
        exported+=("$path")
    fi
done
if ((${#exported[@]})); then
    tar --create --file=- --directory=/work/src -- "${exported[@]}"
else
    tar --create --file=- --files-from=/dev/null
fi
exit "$status"
