// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <stdbool.h>
#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

void* zygveil_shadowhook_dlopen(const char* filename, int flags);
int zygveil_shadowhook_dlclose(void* handle);
void* zygveil_shadowhook_xdl_open(const char* filename, int flags);
bool zygveil_shadowhook_ends_with(const char* value, const char* suffix);

#ifdef __cplusplus
}
#endif

#define dlopen zygveil_shadowhook_dlopen
#define dlclose zygveil_shadowhook_dlclose
#define xdl_open zygveil_shadowhook_xdl_open
#define sh_util_ends_with zygveil_shadowhook_ends_with
