#!/system/bin/sh

# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: LGPL-3.0-or-later

MODDIR="${0%/*}"
rm -f "$MODDIR/.guard"
rm -f "$MODDIR/early-lifecycle.log"

# shellcheck source=/dev/null
. "$MODDIR/guard.sh"
if validate_runtime; then
    temporary="$MODDIR/.guard.tmp.$$"
    printf 'zygveil-runtime-ready-v1\n' > "$temporary"
    chmod 0644 "$temporary"
    mv -f "$temporary" "$MODDIR/.guard"
else
    touch "$MODDIR/disable"
    rm -f "$MODDIR/server-vpn-runtime-status.properties" \
        "$MODDIR/.server-vpn-runtime-status.tmp"
    temporary="$MODDIR/.runtime-status.tmp.$$"
    {
        printf 'schema_version=4\n'
        printf 'state=inactive\n'
        printf 'reason=runtime_prerequisite_missing\n'
        printf 'raw_gnss_mode=unknown\n'
        printf 'hook_count=0\n'
        printf 'system_server_pid=0\n'
        printf 'system_server_start_ticks=0\n'
        printf 'config_generation=0\n'
        printf 'boot_id='
        cat /proc/sys/kernel/random/boot_id
        printf 'control_fd=0\n'
        printf 'control_owner_pid=0\n'
        printf 'control_owner_start_ticks=0\n'
    } > "$temporary"
    chmod 0644 "$temporary"
    mv -f "$temporary" "$MODDIR/runtime-status.properties"
fi
