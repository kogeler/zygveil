// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "runtime.hpp"

#include <chrono>
#include <string_view>
#include <thread>
#include <utility>

#include "hook_host.hpp"
#include "status.hpp"

namespace zygveil::server_vpn {
namespace {

constexpr auto kCatalogDeadline = std::chrono::seconds(8);
constexpr auto kCatalogPollInterval = std::chrono::milliseconds(100);
constexpr std::uint32_t kActivationPending = 0;
constexpr std::uint32_t kActivationCommitted = 1;

std::string JavaString(JNIEnv* env, jstring value) {
  if (value == nullptr || env->ExceptionCheck()) {
    return {};
  }
  const char* text = env->GetStringUTFChars(value, nullptr);
  if (text == nullptr || env->ExceptionCheck()) {
    return {};
  }
  std::string result(text);
  env->ReleaseStringUTFChars(value, text);
  return result;
}

}  // namespace

Runtime::Runtime(Config config, hook_host::ArtHookHost* hook_host)
    : config_(std::move(config)), hook_host_(hook_host) {}

const Config& Runtime::config() const noexcept {
  return config_;
}

void Runtime::ClearException(JNIEnv* env) const noexcept {
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
  }
}

void Runtime::Cleanup(JNIEnv* env) noexcept {
  if (bridge_class_ != nullptr && bridge_reset_runtime_ != nullptr) {
    env->CallStaticVoidMethod(bridge_class_, bridge_reset_runtime_);
    ClearException(env);
  }
  if (bridge_class_ != nullptr) {
    env->DeleteGlobalRef(bridge_class_);
    bridge_class_ = nullptr;
  }
  if (bridge_loader_ != nullptr) {
    env->DeleteGlobalRef(bridge_loader_);
    bridge_loader_ = nullptr;
  }
  if (system_class_loader_ != nullptr) {
    env->DeleteGlobalRef(system_class_loader_);
    system_class_loader_ = nullptr;
  }
  bridge_constructor_ = nullptr;
  bridge_callback_ = nullptr;
  bridge_set_backup_ = nullptr;
  bridge_activate_ = nullptr;
  bridge_deactivate_ = nullptr;
  bridge_prepare_runtime_ = nullptr;
  bridge_configure_runtime_ = nullptr;
  bridge_resolved_hooks_ = nullptr;
  bridge_runtime_ready_ = nullptr;
  bridge_reset_runtime_ = nullptr;
}

jobject Runtime::LoadClass(JNIEnv* env, jobject loader, const char* class_name) noexcept {
  jclass loader_class = env->FindClass("java/lang/ClassLoader");
  const jmethodID load_class = loader_class == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->GetMethodID(
            loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
  jstring name = load_class == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->NewStringUTF(class_name);
  jobject result = name == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->CallObjectMethod(loader, load_class, name);
  if (env->ExceptionCheck()) {
    ClearException(env);
    result = nullptr;
  }
  env->DeleteLocalRef(name);
  env->DeleteLocalRef(loader_class);
  return result;
}

bool Runtime::LoadBridge(JNIEnv* env, const std::vector<std::uint8_t>& bridge_dex,
                         std::string* error) {
  if (bridge_dex.empty() || bridge_dex.size() > 1024 * 1024) {
    *error = "server_vpn_bridge_size_invalid";
    return false;
  }
  jclass class_loader = env->FindClass("java/lang/ClassLoader");
  jclass byte_buffer = env->FindClass("java/nio/ByteBuffer");
  jclass memory_loader = env->FindClass("dalvik/system/InMemoryDexClassLoader");
  const jmethodID get_system_loader = class_loader == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->GetStaticMethodID(
            class_loader, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
  const jmethodID wrap = byte_buffer == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->GetStaticMethodID(byte_buffer, "wrap", "([B)Ljava/nio/ByteBuffer;");
  const jmethodID loader_constructor = memory_loader == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->GetMethodID(
            memory_loader, "<init>", "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
  if (get_system_loader == nullptr || wrap == nullptr || loader_constructor == nullptr ||
      env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(memory_loader);
    env->DeleteLocalRef(byte_buffer);
    env->DeleteLocalRef(class_loader);
    *error = "server_vpn_bridge_loader_contract_missing";
    return false;
  }
  jbyteArray bytes = env->NewByteArray(static_cast<jsize>(bridge_dex.size()));
  if (bytes != nullptr && !env->ExceptionCheck()) {
    env->SetByteArrayRegion(bytes, 0, static_cast<jsize>(bridge_dex.size()),
                            reinterpret_cast<const jbyte*>(bridge_dex.data()));
  }
  jobject buffer = bytes == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->CallStaticObjectMethod(byte_buffer, wrap, bytes);
  jobject parent = buffer == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->CallStaticObjectMethod(class_loader, get_system_loader);
  jobject loader = parent == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->NewObject(memory_loader, loader_constructor, buffer, parent);
  if (loader == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(loader);
    env->DeleteLocalRef(parent);
    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(bytes);
    env->DeleteLocalRef(memory_loader);
    env->DeleteLocalRef(byte_buffer);
    env->DeleteLocalRef(class_loader);
    *error = "server_vpn_bridge_loader_failed";
    return false;
  }
  system_class_loader_ = env->NewGlobalRef(parent);
  bridge_loader_ = env->NewGlobalRef(loader);
  jobject local_bridge = bridge_loader_ == nullptr || system_class_loader_ == nullptr ||
          env->ExceptionCheck()
      ? nullptr
      : LoadClass(env, bridge_loader_, "dev.zygveil.servervpn.bridge.ServerVpnBridge");
  env->DeleteLocalRef(loader);
  env->DeleteLocalRef(parent);
  env->DeleteLocalRef(buffer);
  env->DeleteLocalRef(bytes);
  env->DeleteLocalRef(memory_loader);
  env->DeleteLocalRef(byte_buffer);
  env->DeleteLocalRef(class_loader);
  if (local_bridge == nullptr) {
    ClearException(env);
    *error = "server_vpn_bridge_class_missing";
    return false;
  }
  bridge_class_ = static_cast<jclass>(env->NewGlobalRef(local_bridge));
  env->DeleteLocalRef(local_bridge);
  if (bridge_class_ == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    *error = "server_vpn_bridge_reference_failed";
    return false;
  }
  bridge_constructor_ = env->GetMethodID(bridge_class_, "<init>", "(IZ)V");
  bridge_callback_ = env->ExceptionCheck()
      ? nullptr
      : env->GetMethodID(
            bridge_class_, "callback", "([Ljava/lang/Object;)Ljava/lang/Object;");
  bridge_set_backup_ = env->ExceptionCheck()
      ? nullptr
      : env->GetMethodID(
            bridge_class_, "setBackup", "(Ljava/lang/reflect/Method;)V");
  bridge_activate_ = env->ExceptionCheck()
      ? nullptr
      : env->GetMethodID(bridge_class_, "activate", "()V");
  bridge_deactivate_ = env->ExceptionCheck()
      ? nullptr
      : env->GetMethodID(bridge_class_, "deactivate", "()V");
  bridge_prepare_runtime_ = env->ExceptionCheck()
      ? nullptr
      : env->GetStaticMethodID(
            bridge_class_, "prepareRuntime", "()Ljava/lang/String;");
  bridge_configure_runtime_ = env->ExceptionCheck()
      ? nullptr
      : env->GetStaticMethodID(
            bridge_class_, "configureRuntime", "()Z");
  bridge_resolved_hooks_ = env->ExceptionCheck()
      ? nullptr
      : env->GetStaticMethodID(
            bridge_class_, "resolvedHookMethods", "()[Ljava/lang/reflect/Method;");
  bridge_runtime_ready_ = env->ExceptionCheck()
      ? nullptr
      : env->GetStaticMethodID(
            bridge_class_, "runtimeReadyForActivation", "()Z");
  bridge_reset_runtime_ = env->ExceptionCheck()
      ? nullptr
      : env->GetStaticMethodID(bridge_class_, "resetRuntime", "()V");
  const jfieldID catalog_version = env->ExceptionCheck()
      ? nullptr
      : env->GetStaticFieldID(bridge_class_, "CATALOG_VERSION", "I");
  const jfieldID hook_count = env->ExceptionCheck()
      ? nullptr
      : env->GetStaticFieldID(bridge_class_, "HOOK_COUNT", "I");
  if (bridge_constructor_ == nullptr || bridge_callback_ == nullptr ||
      bridge_set_backup_ == nullptr || bridge_activate_ == nullptr ||
      bridge_deactivate_ == nullptr || bridge_prepare_runtime_ == nullptr ||
      bridge_configure_runtime_ == nullptr || bridge_resolved_hooks_ == nullptr ||
      bridge_runtime_ready_ == nullptr || bridge_reset_runtime_ == nullptr ||
      catalog_version == nullptr || hook_count == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    *error = "server_vpn_bridge_contract_missing";
    return false;
  }
  const jint observed_catalog = env->GetStaticIntField(bridge_class_, catalog_version);
  const jint observed_hooks = env->GetStaticIntField(bridge_class_, hook_count);
  if (env->ExceptionCheck() || observed_catalog != 1 ||
      observed_hooks != static_cast<jint>(kCatalogHookCount)) {
    ClearException(env);
    *error = "server_vpn_bridge_catalog_mismatch";
    return false;
  }
  return true;
}

bool Runtime::PrepareCatalog(JNIEnv* env, std::string* error) {
  const auto deadline = std::chrono::steady_clock::now() + kCatalogDeadline;
  while (std::chrono::steady_clock::now() < deadline) {
    jstring value = static_cast<jstring>(
        env->CallStaticObjectMethod(bridge_class_, bridge_prepare_runtime_));
    const std::string state = JavaString(env, value);
    env->DeleteLocalRef(value);
    if (env->ExceptionCheck()) {
      ClearException(env);
      *error = "connectivity_catalog_prepare_failed";
      return false;
    }
    if (state == "ready") {
      return true;
    }
    if (state.starts_with("error_")) {
      const std::string detailed = "connectivity_" + state.substr(6);
      *error = ValidStatusReason(detailed) ? detailed : "connectivity_catalog_resolution_failed";
      return false;
    }
    if (!state.starts_with("pending_")) {
      *error = "connectivity_catalog_state_invalid";
      return false;
    }
    std::this_thread::sleep_for(kCatalogPollInterval);
  }
  *error = "connectivity_catalog_timeout";
  return false;
}

bool Runtime::ConfigureBridge(JNIEnv* env, std::string* error) {
  const jboolean configured =
      env->CallStaticBooleanMethod(bridge_class_, bridge_configure_runtime_);
  if (configured != JNI_TRUE || env->ExceptionCheck()) {
    ClearException(env);
    *error = "server_vpn_bridge_configuration_failed";
    return false;
  }
  return true;
}

void Runtime::DeactivateInstalled(JNIEnv* env, std::size_t checkpoint) noexcept {
  if (hook_host_ == nullptr || bridge_deactivate_ == nullptr) {
    return;
  }
  const std::size_t count = hook_host_->HookCountSince(checkpoint);
  for (std::size_t index = 0; index < count; ++index) {
    jobject bridge = hook_host_->BridgeAt(checkpoint + index);
    if (bridge != nullptr) {
      env->CallVoidMethod(bridge, bridge_deactivate_);
      ClearException(env);
    }
  }
}

RuntimeResult Runtime::Initialize(
    JNIEnv* env, const std::vector<std::uint8_t>& bridge_dex,
    std::uint32_t* activation_claim) {
  RuntimeResult result;
  result.reason = "catalog_initialization_failed";
  if (env == nullptr || hook_host_ == nullptr || !hook_host_->Ready() ||
      activation_claim == nullptr ||
      __atomic_load_n(activation_claim, __ATOMIC_ACQUIRE) != kActivationPending) {
    result.reason = "shared_hook_host_unavailable";
    return result;
  }
  const hook_host::ArtHookHost::Checkpoint checkpoint = hook_host_->CreateCheckpoint();
  const auto rollback = [&](std::string reason) -> RuntimeResult {
    DeactivateInstalled(env, checkpoint);
    const bool complete = hook_host_->RollbackTo(env, checkpoint);
    RuntimeResult failure;
    failure.reason = complete ? std::move(reason) : "catalog_rollback_retained";
    failure.retention_required = !complete;
    if (complete) {
      Cleanup(env);
    }
    return failure;
  };

  std::string error;
  if (!LoadBridge(env, bridge_dex, &error) || !PrepareCatalog(env, &error) ||
      !ConfigureBridge(env, &error)) {
    Cleanup(env);
    result.reason = error;
    return result;
  }
  jobjectArray hooks = static_cast<jobjectArray>(
      env->CallStaticObjectMethod(bridge_class_, bridge_resolved_hooks_));
  const jsize hook_count = hooks == nullptr || env->ExceptionCheck()
      ? -1
      : env->GetArrayLength(hooks);
  if (hook_count != static_cast<jsize>(kCatalogHookCount) || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(hooks);
    Cleanup(env);
    result.reason = "connectivity_hook_catalog_invalid";
    return result;
  }
  const hook_host::BridgeContract bridge_contract{
      .bridge_class = bridge_class_,
      .constructor = bridge_constructor_,
      .callback = bridge_callback_,
      .set_backup = bridge_set_backup_,
  };
  for (jsize index = 0; index < hook_count; ++index) {
    jobject target = env->GetObjectArrayElement(hooks, index);
    if (target == nullptr || env->ExceptionCheck()) {
      ClearException(env);
      env->DeleteLocalRef(target);
      env->DeleteLocalRef(hooks);
      return rollback("connectivity_hook_reference_failed");
    }
    const bool installed = hook_host_->Install(
        env, hook_host::FeatureOwner::kServerVpn, index, false, target,
        bridge_contract, &error);
    env->DeleteLocalRef(target);
    if (!installed) {
      env->DeleteLocalRef(hooks);
      return rollback(error.empty() ? "connectivity_hook_install_failed" : error);
    }
  }
  env->DeleteLocalRef(hooks);
  if (hook_host_->HookCountSince(checkpoint) != kCatalogHookCount) {
    return rollback("connectivity_hook_count_mismatch");
  }
  for (std::size_t index = 0; index < kCatalogHookCount; ++index) {
    if (hook_host_->OwnerAt(checkpoint + index) !=
        hook_host::FeatureOwner::kServerVpn) {
      return rollback("connectivity_hook_owner_mismatch");
    }
  }
  const jboolean runtime_ready =
      env->CallStaticBooleanMethod(bridge_class_, bridge_runtime_ready_);
  if (runtime_ready != JNI_TRUE || env->ExceptionCheck()) {
    ClearException(env);
    return rollback("connectivity_backup_catalog_invalid");
  }
  if (__atomic_load_n(activation_claim, __ATOMIC_ACQUIRE) != kActivationPending) {
    return rollback("post_server_timeout");
  }
  std::uint32_t expected_claim = kActivationPending;
  if (!__atomic_compare_exchange_n(
          activation_claim, &expected_claim, kActivationCommitted, false,
          __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
    return rollback("post_server_timeout");
  }
  jobject activation_bridge = hook_host_->BridgeAt(checkpoint);
  if (activation_bridge == nullptr) {
    return rollback("connectivity_bridge_activation_failed");
  }
  env->CallVoidMethod(activation_bridge, bridge_activate_);
  if (env->ExceptionCheck()) {
    ClearException(env);
    return rollback("connectivity_bridge_activation_failed");
  }
  result.active = true;
  result.retention_required = true;
  result.hook_count = kCatalogHookCount;
  result.reason = "active";
  return result;
}

}  // namespace zygveil::server_vpn
