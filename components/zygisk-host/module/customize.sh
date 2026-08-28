#!/system/bin/sh

# SPDX-FileCopyrightText: 2026 kogeler
# SPDX-License-Identifier: LGPL-3.0-or-later

# Consumed by Magisk and the dynamically sourced runtime guard.
# shellcheck disable=SC2034
SKIPUNZIP=0
# shellcheck disable=SC2034
MODDIR="$MODPATH"

ui_print '- ZygVeil installer'
rm -f "$MODPATH/.guard" "$MODPATH/runtime-status.properties" \
    "$MODPATH/server-vpn-runtime-status.properties" \
    "$MODPATH/.server-vpn-runtime-status.tmp"

# shellcheck source=/dev/null
. "$MODPATH/guard.sh"
if ! validate_runtime; then
    abort "Runtime prerequisites failed: $MISMATCHES"
fi
rm -f "$MODPATH/disable" || abort 'Could not retain production module enablement'

LIVE_MODULE=/data/adb/modules/zygveil
LIVE_CONFIG="$LIVE_MODULE/config.properties"
if [ "$MODPATH/config.properties" != "$LIVE_CONFIG" ] && [ -d "$LIVE_MODULE" ]; then
    [ -f "$LIVE_CONFIG" ] && [ ! -L "$LIVE_CONFIG" ] ||
        abort 'Existing location configuration is unavailable or unsafe'
    cp -p "$LIVE_CONFIG" "$MODPATH/config.properties" ||
        abort 'Could not preserve the existing location configuration'
    ui_print '- Preserved existing location coordinates and activation state'
fi

set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/customize.sh" 0 0 0755
set_perm "$MODPATH/guard.sh" 0 0 0755
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/config.properties" 0 0 0600
[ ! -f "$MODPATH/server-vpn-config.properties" ] ||
    set_perm "$MODPATH/server-vpn-config.properties" 0 0 0644
set_perm "$MODPATH/libshadowhook_nothing.so" 0 0 0644
set_perm "$MODPATH/locationctl" 0 0 0755
set_perm "$MODPATH/zygisk/arm64-v8a.so" 0 0 0755
ui_print '- Installed enabled; reboot starts VPN masking and location control'
