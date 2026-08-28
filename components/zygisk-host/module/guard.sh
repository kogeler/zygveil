#!/system/bin/sh

# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: LGPL-3.0-or-later

append_mismatch() {
    if [ -n "${MISMATCHES:-}" ]; then
        MISMATCHES="$MISMATCHES,$1"
    else
        MISMATCHES="$1"
    fi
}

check_runtime_file() {
    [ -f "$MODDIR/$1" ] && [ ! -L "$MODDIR/$1" ] || append_mismatch runtime_file
}

write_guard_status() {
    temporary="$MODDIR/.guard-status.tmp.$$"
    {
        printf 'schema_version=1\n'
        printf 'state=%s\n' "$1"
        printf 'mismatches=%s\n' "${MISMATCHES:-none}"
    } > "$temporary"
    chmod 0644 "$temporary"
    mv -f "$temporary" "$MODDIR/guard-status.properties"
}

validate_runtime() {
    MISMATCHES=''
    check_runtime_file config.properties
    check_runtime_file bridge.dex
    check_runtime_file server-vpn-config.properties
    check_runtime_file server-vpn-bridge.dex
    check_runtime_file libshadowhook_nothing.so
    check_runtime_file locationctl
    check_runtime_file zygisk/arm64-v8a.so
    zygisk_value="$(magisk --sqlite "SELECT value FROM settings WHERE key='zygisk';" 2> /dev/null)"
    printf '%s\n' "$zygisk_value" | grep -qx 'value=1' || append_mismatch zygisk
    if [ -n "$MISMATCHES" ]; then
        write_guard_status mismatch
        return 1
    fi
    write_guard_status valid
    return 0
}
