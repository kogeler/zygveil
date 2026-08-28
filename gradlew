#!/bin/sh

# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: MIT

set -eu
unset CDPATH
root=$(cd -- "$(dirname -- "$0")" && pwd)
exec java -classpath "$root/gradle/wrapper/gradle-wrapper.jar" \
    org.gradle.wrapper.GradleWrapperMain "$@"
