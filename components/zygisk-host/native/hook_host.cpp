// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "hook_host.hpp"

#include <shadowhook.h>

#include <mutex>
#include <string_view>
#include <unordered_map>

#include <lsplant.hpp>

namespace zygveil::hook_host {
namespace {

std::mutex g_inline_mutex;
std::unordered_map<void*, void*> g_inline_stubs;
void* g_art_handle = nullptr;

void ClearException(JNIEnv* env) noexcept {
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
  }
}

void* InlineHook(void* target, void* replacement) {
  void* original = nullptr;
  void* stub = shadowhook_hook_func_addr(target, replacement, &original);
  if (stub == nullptr || original == nullptr) {
    return nullptr;
  }
  std::lock_guard lock(g_inline_mutex);
  g_inline_stubs[target] = stub;
  return original;
}

bool InlineUnhook(void* target) {
  std::lock_guard lock(g_inline_mutex);
  const auto found = g_inline_stubs.find(target);
  if (found == g_inline_stubs.end()) {
    return false;
  }
  const bool success = shadowhook_unhook(found->second) == 0;
  if (success) {
    g_inline_stubs.erase(found);
  }
  return success;
}

void* ResolveArt(std::string_view symbol) {
  if (g_art_handle == nullptr) {
    return nullptr;
  }
  const std::string owned(symbol);
  void* result = shadowhook_dlsym_symtab(g_art_handle, owned.c_str());
  return result != nullptr ? result : shadowhook_dlsym_dynsym(g_art_handle, owned.c_str());
}

}  // namespace

bool ArtHookHost::Prepare(JNIEnv* env, std::string* error) {
  if (art_ready_) {
    *error = "hook_host_already_prepared";
    return false;
  }
  const int shadow_result = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
  if (shadow_result != 0) {
    *error = "shadowhook_init:" + std::to_string(shadow_result);
    return false;
  }
  g_art_handle = shadowhook_dlopen("libart.so");
  if (g_art_handle == nullptr) {
    *error = "libart_symbol_table_unavailable";
    return false;
  }
  lsplant::InitInfo info{
      .inline_hooker = InlineHook,
      .inline_unhooker = InlineUnhook,
      .art_symbol_resolver = ResolveArt,
      .art_symbol_prefix_resolver = [](std::string_view) -> void* { return nullptr; },
      .generated_class_name = "ZygVeilSystemServerHook_",
      .generated_source_name = "ZygVeilSystemServerHookHost",
      .generated_field_name = "featureBridge",
      .generated_method_name = "{target}",
      .executable_memory_allocator = {},
      .executable_memory_recycler = {},
  };
  if (!lsplant::Init(env, info)) {
    ClearException(env);
    *error = "lsplant_init_failed";
    return false;
  }
  art_ready_ = true;
  return true;
}

bool ArtHookHost::Ready() const noexcept {
  return art_ready_;
}

ArtHookHost::Checkpoint ArtHookHost::CreateCheckpoint() const noexcept {
  return hooks_.size();
}

std::size_t ArtHookHost::HookCount() const noexcept {
  return hooks_.size();
}

std::size_t ArtHookHost::HookCountSince(Checkpoint checkpoint) const noexcept {
  return checkpoint <= hooks_.size() ? hooks_.size() - checkpoint : 0;
}

jobject ArtHookHost::BridgeAt(std::size_t index) const noexcept {
  return index < hooks_.size() ? hooks_[index].bridge : nullptr;
}

FeatureOwner ArtHookHost::OwnerAt(std::size_t index) const noexcept {
  return index < hooks_.size() ? hooks_[index].owner : FeatureOwner::kLocation;
}

bool ArtHookHost::Install(JNIEnv* env, FeatureOwner owner, int hook_id, bool static_target,
                          jobject target, const BridgeContract& bridge,
                          std::string* error) {
  if (!art_ready_ || target == nullptr || bridge.bridge_class == nullptr ||
      bridge.constructor == nullptr || bridge.callback == nullptr ||
      bridge.set_backup == nullptr) {
    *error = "hook_host_contract_invalid";
    return false;
  }
  jobject bridge_object = env->NewObject(
      bridge.bridge_class, bridge.constructor, hook_id,
      static_target ? JNI_TRUE : JNI_FALSE);
  jobject callback = bridge_object == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->ToReflectedMethod(bridge.bridge_class, bridge.callback, JNI_FALSE);
  jobject target_global = callback == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->NewGlobalRef(target);
  jobject bridge_global = target_global == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->NewGlobalRef(bridge_object);
  if (callback == nullptr || target_global == nullptr || bridge_global == nullptr ||
      env->ExceptionCheck()) {
    ClearException(env);
    if (target_global != nullptr) {
      env->DeleteGlobalRef(target_global);
    }
    if (bridge_global != nullptr) {
      env->DeleteGlobalRef(bridge_global);
    }
    env->DeleteLocalRef(callback);
    env->DeleteLocalRef(bridge_object);
    *error = "hook_host_reference_failed";
    return false;
  }
  if (env->MonitorEnter(bridge_object) != JNI_OK || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteGlobalRef(target_global);
    env->DeleteGlobalRef(bridge_global);
    env->DeleteLocalRef(callback);
    env->DeleteLocalRef(bridge_object);
    *error = "hook_host_publication_monitor_failed";
    return false;
  }
  const auto release_monitor = [&]() noexcept {
    const bool released = env->MonitorExit(bridge_object) == JNI_OK && !env->ExceptionCheck();
    ClearException(env);
    return released;
  };
  jobject backup = lsplant::Hook(env, target, bridge_object, callback);
  if (backup == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    const bool monitor_released = release_monitor();
    env->DeleteGlobalRef(target_global);
    env->DeleteGlobalRef(bridge_global);
    env->DeleteLocalRef(callback);
    env->DeleteLocalRef(bridge_object);
    *error = monitor_released ? "hook_host_install_failed"
                              : "hook_host_publication_monitor_release_failed";
    rollback_incomplete_ = !monitor_released;
    return false;
  }
  env->CallVoidMethod(bridge_object, bridge.set_backup, backup);
  if (env->ExceptionCheck()) {
    ClearException(env);
    const bool unhooked = lsplant::UnHook(env, target);
    ClearException(env);
    const bool monitor_released = release_monitor();
    if (!unhooked || !monitor_released) {
      rollback_incomplete_ = true;
      *error = "hook_host_backup_rollback_retained";
      if (!unhooked) {
        hooks_.push_back({.owner = owner, .target = target_global, .bridge = bridge_global});
      } else {
        env->DeleteGlobalRef(target_global);
        env->DeleteGlobalRef(bridge_global);
      }
    } else {
      *error = "hook_host_backup_assignment_failed";
      env->DeleteGlobalRef(target_global);
      env->DeleteGlobalRef(bridge_global);
    }
    env->DeleteLocalRef(callback);
    env->DeleteLocalRef(bridge_object);
    return false;
  }
  hooks_.push_back({.owner = owner, .target = target_global, .bridge = bridge_global});
  if (!release_monitor()) {
    rollback_incomplete_ = true;
    *error = "hook_host_publication_monitor_release_failed";
    env->DeleteLocalRef(callback);
    env->DeleteLocalRef(bridge_object);
    return false;
  }
  // LSPlant owns the returned global backup reference until UnHook.
  env->DeleteLocalRef(callback);
  env->DeleteLocalRef(bridge_object);
  return true;
}

bool ArtHookHost::RollbackTo(JNIEnv* env, Checkpoint checkpoint) noexcept {
  if (checkpoint > hooks_.size() || rollback_incomplete_) {
    rollback_incomplete_ = true;
    return false;
  }
  for (std::size_t index = hooks_.size(); index > checkpoint; --index) {
    HookRecord& hook = hooks_[index - 1];
    if (hook.target == nullptr || !lsplant::UnHook(env, hook.target)) {
      ClearException(env);
      rollback_incomplete_ = true;
      return false;
    }
    ClearException(env);
  }
  for (std::size_t index = hooks_.size(); index > checkpoint; --index) {
    HookRecord& hook = hooks_[index - 1];
    env->DeleteGlobalRef(hook.target);
    env->DeleteGlobalRef(hook.bridge);
  }
  hooks_.resize(checkpoint);
  return true;
}

bool ArtHookHost::RollbackIncomplete() const noexcept {
  return rollback_incomplete_;
}

}  // namespace zygveil::hook_host
