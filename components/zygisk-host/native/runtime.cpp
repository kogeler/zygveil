// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "runtime.hpp"

#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <string_view>
#include <thread>
#include <utility>

#include "application_delivery_policy.hpp"

namespace zygveil::location {
namespace {

constexpr int kLocationHook = 0;
constexpr int kStatusHook = 1;
constexpr int kNmeaHook = 2;
constexpr int kMeasurementHook = 3;
constexpr int kNavigationHook = 4;
constexpr int kHookCount = 5;
constexpr int kAppParcelHook = 5;
constexpr int kAppHookCount = 1;
constexpr auto kClassLoaderDeadline = std::chrono::seconds(30);
constexpr auto kClassLoaderPollInterval = std::chrono::milliseconds(50);

std::atomic<Runtime*> g_runtime{nullptr};
std::atomic<bool> g_dispatch_accepting{false};
std::shared_mutex g_dispatch_gate;
alignas(64) thread_local bool g_in_callback = false;

bool ActivationTimedOut(const std::uint32_t* claim) {
  return claim == nullptr ||
      __atomic_load_n(claim, __ATOMIC_ACQUIRE) == kRuntimeActivationTimedOut;
}

void ThrowInactiveDispatch(JNIEnv* env) {
  jclass exception = env->FindClass("java/lang/IllegalStateException");
  if (exception != nullptr && !env->ExceptionCheck()) {
    env->ThrowNew(exception, "location runtime inactive");
  }
  env->DeleteLocalRef(exception);
}

jobject NativeDispatch(JNIEnv* env, jclass, jint hook_id, jobject backup, jobjectArray args) {
  if (g_in_callback) {
    Runtime* runtime = g_runtime.load(std::memory_order_acquire);
    return runtime == nullptr ? nullptr : runtime->Dispatch(env, hook_id, backup, args);
  }
  if (!g_dispatch_accepting.load(std::memory_order_acquire)) {
    ThrowInactiveDispatch(env);
    return nullptr;
  }
  std::shared_lock gate(g_dispatch_gate);
  Runtime* runtime = g_runtime.load(std::memory_order_acquire);
  if (!g_dispatch_accepting.load(std::memory_order_acquire) || runtime == nullptr ||
      backup == nullptr || args == nullptr) {
    ThrowInactiveDispatch(env);
    return nullptr;
  }
  return runtime->Dispatch(env, hook_id, backup, args);
}


std::int64_t WallTimeMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::int64_t ElapsedNs() {
  timespec value{};
  clock_gettime(CLOCK_BOOTTIME, &value);
  return static_cast<std::int64_t>(value.tv_sec) * 1'000'000'000LL + value.tv_nsec;
}

}  // namespace

struct Runtime::JniCache {
  jclass location = nullptr;
  jclass location_result = nullptr;
  jclass list = nullptr;
  jclass array_list = nullptr;
  jclass gnss_status = nullptr;
  jclass nmea_listener = nullptr;
  jclass method = nullptr;
  jclass long_class = nullptr;

  jmethodID location_copy = nullptr;
  jmethodID location_get_provider = nullptr;
  jmethodID location_get_time = nullptr;
  jmethodID location_get_elapsed = nullptr;
  jmethodID location_set_time = nullptr;
  jmethodID location_set_elapsed = nullptr;
  jmethodID location_set_latitude = nullptr;
  jmethodID location_set_longitude = nullptr;
  jmethodID location_set_accuracy = nullptr;
  jmethodID location_set_altitude = nullptr;
  jmethodID location_set_vertical_accuracy = nullptr;
  jmethodID location_set_msl_altitude = nullptr;
  jmethodID location_set_msl_accuracy = nullptr;
  jmethodID location_set_speed = nullptr;
  jmethodID location_set_speed_accuracy = nullptr;
  jmethodID location_set_bearing = nullptr;
  jmethodID location_set_bearing_accuracy = nullptr;
  jmethodID location_remove_bearing = nullptr;
  jmethodID location_remove_bearing_accuracy = nullptr;
  jmethodID location_is_complete = nullptr;

  jmethodID location_result_as_list = nullptr;
  jmethodID location_result_create = nullptr;
  jmethodID location_result_validate = nullptr;
  jmethodID list_size = nullptr;
  jmethodID list_get = nullptr;
  jmethodID array_list_constructor = nullptr;
  jmethodID array_list_add = nullptr;
  jmethodID gnss_status_wrap = nullptr;
  jmethodID nmea_received = nullptr;
  jmethodID method_invoke = nullptr;
  jmethodID long_value = nullptr;
};

Runtime::Runtime(Config config, ControlPage* control_page, int control_descriptor,
                 ControlPage* application_control_page, bool application_control_writable,
                 bool application_fail_closed, std::string boot_id)
    : config_(std::move(config)),
      model_(config_),
      control_page_(control_page),
      control_descriptor_(control_descriptor),
      application_control_page_(application_control_page),
      application_control_writable_(application_control_writable),
      application_fail_closed_(application_fail_closed),
      application_server_pid_(application_control_page == nullptr
                                  ? 0
                                  : application_control_page->header.server_pid),
      application_boot_generation_(application_control_page == nullptr
                                       ? 0
                                       : application_control_page->header.boot_config_generation),
      application_boot_fields_digest_(application_control_page == nullptr
                                          ? 0
                                          : application_control_page->header.boot_fields_digest),
      boot_id_(std::move(boot_id)),
      boot_fields_digest_(BootFieldsDigest(EncodeConfig(config_))),
      applied_generation_(config_.config_generation) {}

Runtime::~Runtime() {
  if (g_runtime.load(std::memory_order_acquire) == this) {
    g_dispatch_accepting.store(false, std::memory_order_release);
    std::unique_lock gate(g_dispatch_gate);
    g_runtime.store(nullptr, std::memory_order_release);
  }
  if (control_page_ != nullptr) {
    munmap(control_page_, sizeof(ControlPage));
    control_page_ = nullptr;
  }
  if (application_control_page_ != nullptr) {
    if (application_control_writable_) {
      StoreControlRuntimeState(application_control_page_, ControlRuntimeState::kInactive);
    }
    munmap(application_control_page_, sizeof(ControlPage));
    application_control_page_ = nullptr;
  }
  if (control_descriptor_ >= 0) {
    close(control_descriptor_);
    control_descriptor_ = -1;
  }
}

void Runtime::ClearException(JNIEnv* env) const noexcept {
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
  }
}

bool Runtime::PrepareArt(JNIEnv* env, std::string* error) {
  hook_host_ = std::make_unique<hook_host::ArtHookHost>();
  if (!hook_host_->Prepare(env, error)) {
    hook_host_.reset();
    return false;
  }
  art_ready_ = true;
  return true;
}

hook_host::ArtHookHost* Runtime::HookHost() const noexcept {
  return hook_host_.get();
}

jobject Runtime::LoadClass(JNIEnv* env, const char* name) noexcept {
  if (system_class_loader_ == nullptr) {
    return nullptr;
  }
  jclass loader_class = env->FindClass("java/lang/ClassLoader");
  if (loader_class == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    return nullptr;
  }
  const jmethodID load_class =
      env->GetMethodID(loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
  if (load_class == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(loader_class);
    return nullptr;
  }
  jstring class_name = env->NewStringUTF(name);
  if (class_name == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(loader_class);
    return nullptr;
  }
  jobject result = env->CallObjectMethod(system_class_loader_, load_class, class_name);
  const bool failed = result == nullptr || env->ExceptionCheck();
  if (failed) {
    ClearException(env);
  }
  env->DeleteLocalRef(class_name);
  env->DeleteLocalRef(loader_class);
  if (failed) {
    env->DeleteLocalRef(result);
    return nullptr;
  }
  return result;
}

bool Runtime::AcquireSystemServerClassLoader(JNIEnv* env, std::string* error) {
  jclass looper_class = env->FindClass("android/os/Looper");
  if (looper_class == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(looper_class);
    *error = "system_server_class_loader_contract_failed";
    return false;
  }
  jclass thread_class = env->FindClass("java/lang/Thread");
  if (thread_class == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(looper_class);
    env->DeleteLocalRef(thread_class);
    *error = "system_server_class_loader_contract_failed";
    return false;
  }
  const jmethodID get_main_looper =
      env->GetStaticMethodID(looper_class, "getMainLooper", "()Landroid/os/Looper;");
  const jmethodID get_thread = env->ExceptionCheck()
      ? nullptr
      : env->GetMethodID(looper_class, "getThread", "()Ljava/lang/Thread;");
  const jmethodID get_context_loader = env->ExceptionCheck()
      ? nullptr
      : env->GetMethodID(thread_class, "getContextClassLoader",
                         "()Ljava/lang/ClassLoader;");
  if (get_main_looper == nullptr || get_thread == nullptr || get_context_loader == nullptr ||
      env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(looper_class);
    env->DeleteLocalRef(thread_class);
    *error = "system_server_class_loader_contract_failed";
    return false;
  }

  const auto deadline = std::chrono::steady_clock::now() + kClassLoaderDeadline;
  while (std::chrono::steady_clock::now() < deadline) {
    jobject looper = env->CallStaticObjectMethod(looper_class, get_main_looper);
    jobject thread = nullptr;
    jobject loader = nullptr;
    if (looper != nullptr && !env->ExceptionCheck()) {
      thread = env->CallObjectMethod(looper, get_thread);
    }
    if (thread != nullptr && !env->ExceptionCheck()) {
      loader = env->CallObjectMethod(thread, get_context_loader);
    }
    if (loader != nullptr && !env->ExceptionCheck()) {
      system_class_loader_ = env->NewGlobalRef(loader);
      if (system_class_loader_ != nullptr && !env->ExceptionCheck()) {
        jobject target = LoadClass(
            env, "com.android.server.location.provider.LocationProviderManager");
        if (target != nullptr) {
          env->DeleteLocalRef(target);
          env->DeleteLocalRef(loader);
          env->DeleteLocalRef(thread);
          env->DeleteLocalRef(looper);
          env->DeleteLocalRef(thread_class);
          env->DeleteLocalRef(looper_class);
          return true;
        }
        env->DeleteGlobalRef(system_class_loader_);
        system_class_loader_ = nullptr;
      } else {
        ClearException(env);
        if (system_class_loader_ != nullptr) {
          env->DeleteGlobalRef(system_class_loader_);
        }
        system_class_loader_ = nullptr;
      }
    }
    ClearException(env);
    env->DeleteLocalRef(loader);
    env->DeleteLocalRef(thread);
    env->DeleteLocalRef(looper);
    std::this_thread::sleep_for(kClassLoaderPollInterval);
  }
  env->DeleteLocalRef(thread_class);
  env->DeleteLocalRef(looper_class);
  *error = "system_server_class_loader_timeout";
  return false;
}

bool Runtime::AcquireApplicationClassLoader(JNIEnv* env, std::string* error) {
  jclass loader_class = env->FindClass("java/lang/ClassLoader");
  if (loader_class == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(loader_class);
    *error = "application_class_loader_class_missing";
    return false;
  }
  const jmethodID get_system_loader = env->GetStaticMethodID(
      loader_class, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
  jobject loader = get_system_loader == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->CallStaticObjectMethod(loader_class, get_system_loader);
  if (loader == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(loader);
    env->DeleteLocalRef(loader_class);
    *error = "application_class_loader_unavailable";
    return false;
  }
  system_class_loader_ = env->NewGlobalRef(loader);
  const bool failed = system_class_loader_ == nullptr || env->ExceptionCheck();
  if (failed) {
    ClearException(env);
    if (system_class_loader_ != nullptr) {
      env->DeleteGlobalRef(system_class_loader_);
      system_class_loader_ = nullptr;
    }
  }
  env->DeleteLocalRef(loader);
  env->DeleteLocalRef(loader_class);
  if (failed) {
    *error = "application_class_loader_reference_failed";
    return false;
  }
  return true;
}

bool Runtime::LoadBridge(JNIEnv* env, const std::vector<std::uint8_t>& bridge_dex,
                         std::string* error) {
  if (system_class_loader_ == nullptr) {
    *error = "system_class_loader_unavailable";
    return false;
  }

  jbyteArray bytes = env->NewByteArray(static_cast<jsize>(bridge_dex.size()));
  if (bytes == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    *error = "bridge_byte_array_failed";
    return false;
  }
  env->SetByteArrayRegion(bytes, 0, static_cast<jsize>(bridge_dex.size()),
                          reinterpret_cast<const jbyte*>(bridge_dex.data()));
  if (env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(bytes);
    *error = "bridge_byte_array_copy_failed";
    return false;
  }
  jclass byte_buffer = env->FindClass("java/nio/ByteBuffer");
  if (byte_buffer == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(bytes);
    *error = "bridge_byte_buffer_class_failed";
    return false;
  }
  const jmethodID wrap =
      env->GetStaticMethodID(byte_buffer, "wrap", "([B)Ljava/nio/ByteBuffer;");
  if (wrap == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(bytes);
    env->DeleteLocalRef(byte_buffer);
    *error = "bridge_byte_buffer_method_failed";
    return false;
  }
  jobject buffer = env->CallStaticObjectMethod(byte_buffer, wrap, bytes);
  if (buffer == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(bytes);
    env->DeleteLocalRef(byte_buffer);
    *error = "bridge_byte_buffer_failed";
    return false;
  }
  jclass memory_loader = env->FindClass("dalvik/system/InMemoryDexClassLoader");
  if (memory_loader == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(bytes);
    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(byte_buffer);
    *error = "bridge_class_loader_class_failed";
    return false;
  }
  const jmethodID constructor =
      env->GetMethodID(memory_loader, "<init>",
                       "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
  if (constructor == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(bytes);
    env->DeleteLocalRef(buffer);
    env->DeleteLocalRef(byte_buffer);
    env->DeleteLocalRef(memory_loader);
    *error = "bridge_class_loader_constructor_failed";
    return false;
  }
  jobject loader = env->NewObject(memory_loader, constructor, buffer, system_class_loader_);
  const bool loader_failed = loader == nullptr || env->ExceptionCheck();
  if (loader_failed) {
    ClearException(env);
  }
  env->DeleteLocalRef(bytes);
  env->DeleteLocalRef(buffer);
  env->DeleteLocalRef(byte_buffer);
  env->DeleteLocalRef(memory_loader);
  if (loader_failed) {
    env->DeleteLocalRef(loader);
    *error = "bridge_class_loader_failed";
    return false;
  }

  bridge_loader_ = env->NewGlobalRef(loader);
  if (bridge_loader_ == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    if (bridge_loader_ != nullptr) {
      env->DeleteGlobalRef(bridge_loader_);
      bridge_loader_ = nullptr;
    }
    env->DeleteLocalRef(loader);
    *error = "bridge_loader_reference_failed";
    return false;
  }
  jobject previous_loader = system_class_loader_;
  system_class_loader_ = bridge_loader_;
  jobject local_bridge = LoadClass(env, "dev.zygveil.location.bridge.HookBridge");
  system_class_loader_ = previous_loader;
  env->DeleteLocalRef(loader);
  if (local_bridge == nullptr) {
    *error = "bridge_class_missing";
    return false;
  }
  bridge_class_ = static_cast<jclass>(env->NewGlobalRef(local_bridge));
  const bool bridge_reference_failed = bridge_class_ == nullptr || env->ExceptionCheck();
  if (bridge_reference_failed) {
    ClearException(env);
  }
  env->DeleteLocalRef(local_bridge);
  if (bridge_reference_failed) {
    if (bridge_class_ != nullptr) {
      env->DeleteGlobalRef(bridge_class_);
    }
    bridge_class_ = nullptr;
    *error = "bridge_class_reference_failed";
    return false;
  }
  const JNINativeMethod methods[] = {{
      const_cast<char*>("dispatch"),
      const_cast<char*>(
          "(ILjava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;"),
      reinterpret_cast<void*>(NativeDispatch),
  }};
  if (env->RegisterNatives(bridge_class_, methods, 1) != JNI_OK) {
    ClearException(env);
    *error = "bridge_native_registration_failed";
    return false;
  }
  const auto bridge_method = [&](const char* name, const char* signature) -> jmethodID {
    return env->ExceptionCheck() ? nullptr : env->GetMethodID(bridge_class_, name, signature);
  };
  bridge_constructor_ = bridge_method("<init>", "(IZ)V");
  bridge_callback_ = bridge_method("callback", "([Ljava/lang/Object;)Ljava/lang/Object;");
  bridge_set_backup_ = bridge_method("setBackup", "(Ljava/lang/reflect/Method;)V");
  bridge_activate_ = bridge_method("activateFailClosed", "()V");
  bridge_deactivate_ = bridge_method("deactivateFailClosed", "()V");
  if (bridge_constructor_ == nullptr || bridge_callback_ == nullptr ||
      bridge_set_backup_ == nullptr || bridge_activate_ == nullptr ||
      bridge_deactivate_ == nullptr) {
    ClearException(env);
    *error = "bridge_method_contract_failed";
    return false;
  }
  return true;
}


jobject Runtime::ResolveMethod(JNIEnv* env, const char* class_name, const char* method_name,
                               const std::vector<const char*>& parameter_types) noexcept {
  jobject target_class = LoadClass(env, class_name);
  if (target_class == nullptr) {
    return nullptr;
  }
  jclass class_class = env->FindClass("java/lang/Class");
  if (class_class == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(class_class);
    env->DeleteLocalRef(target_class);
    return nullptr;
  }
  const jmethodID declared = env->GetMethodID(
      class_class, "getDeclaredMethod",
      "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
  if (declared == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(class_class);
    env->DeleteLocalRef(target_class);
    return nullptr;
  }
  jobjectArray parameters = env->NewObjectArray(
      static_cast<jsize>(parameter_types.size()), class_class, nullptr);
  if (parameters == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(parameters);
    env->DeleteLocalRef(class_class);
    env->DeleteLocalRef(target_class);
    return nullptr;
  }
  for (std::size_t index = 0; index < parameter_types.size(); ++index) {
    jobject parameter = nullptr;
    if (std::string_view(parameter_types[index]) == "long") {
      jclass long_class = env->FindClass("java/lang/Long");
      if (long_class == nullptr || env->ExceptionCheck()) {
        ClearException(env);
        env->DeleteLocalRef(long_class);
        env->DeleteLocalRef(parameters);
        env->DeleteLocalRef(class_class);
        env->DeleteLocalRef(target_class);
        return nullptr;
      }
      const jfieldID type =
          env->GetStaticFieldID(long_class, "TYPE", "Ljava/lang/Class;");
      if (type == nullptr || env->ExceptionCheck()) {
        ClearException(env);
        env->DeleteLocalRef(long_class);
        env->DeleteLocalRef(parameters);
        env->DeleteLocalRef(class_class);
        env->DeleteLocalRef(target_class);
        return nullptr;
      }
      parameter = env->GetStaticObjectField(long_class, type);
      const bool parameter_failed = parameter == nullptr || env->ExceptionCheck();
      if (parameter_failed) {
        ClearException(env);
      }
      env->DeleteLocalRef(long_class);
      if (parameter_failed) {
        env->DeleteLocalRef(parameter);
        env->DeleteLocalRef(parameters);
        env->DeleteLocalRef(class_class);
        env->DeleteLocalRef(target_class);
        return nullptr;
      }
    } else {
      parameter = LoadClass(env, parameter_types[index]);
    }
    if (parameter == nullptr || env->ExceptionCheck()) {
      ClearException(env);
      env->DeleteLocalRef(parameter);
      env->DeleteLocalRef(parameters);
      env->DeleteLocalRef(class_class);
      env->DeleteLocalRef(target_class);
      return nullptr;
    }
    env->SetObjectArrayElement(parameters, static_cast<jsize>(index), parameter);
    const bool set_failed = env->ExceptionCheck();
    if (set_failed) {
      ClearException(env);
    }
    env->DeleteLocalRef(parameter);
    if (set_failed) {
      env->DeleteLocalRef(parameters);
      env->DeleteLocalRef(class_class);
      env->DeleteLocalRef(target_class);
      return nullptr;
    }
  }
  jstring name = env->NewStringUTF(method_name);
  if (name == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(name);
    env->DeleteLocalRef(parameters);
    env->DeleteLocalRef(class_class);
    env->DeleteLocalRef(target_class);
    return nullptr;
  }
  jobject method = env->CallObjectMethod(target_class, declared, name, parameters);
  const bool failed = method == nullptr || env->ExceptionCheck();
  if (failed) {
    ClearException(env);
  }
  env->DeleteLocalRef(name);
  env->DeleteLocalRef(parameters);
  env->DeleteLocalRef(class_class);
  env->DeleteLocalRef(target_class);
  if (failed) {
    env->DeleteLocalRef(method);
    return nullptr;
  }
  return method;
}

bool Runtime::InstallHook(JNIEnv* env, int hook_id, const char* class_name,
                          const char* method_name,
                          const std::vector<const char*>& parameter_types,
                          bool static_target, std::string* error) {
  if (hook_host_ == nullptr) {
    *error = "hook_host_unavailable";
    return false;
  }
  jobject target = ResolveMethod(env, class_name, method_name, parameter_types);
  if (target == nullptr) {
    *error = std::string("signature_missing:") + class_name + "." + method_name;
    return false;
  }
  const hook_host::BridgeContract bridge{
      .bridge_class = bridge_class_,
      .constructor = bridge_constructor_,
      .callback = bridge_callback_,
      .set_backup = bridge_set_backup_,
  };
  const bool installed = hook_host_->Install(
      env, hook_host::FeatureOwner::kLocation, hook_id, static_target, target, bridge, error);
  env->DeleteLocalRef(target);
  return installed;
}

bool Runtime::CacheFramework(JNIEnv* env, std::string* error) {
  cache_ = std::make_unique<JniCache>();
  const auto global_class = [&](const char* name) -> jclass {
    jobject local = LoadClass(env, name);
    if (local == nullptr) {
      return nullptr;
    }
    jclass global = static_cast<jclass>(env->NewGlobalRef(local));
    const bool failed = global == nullptr || env->ExceptionCheck();
    if (failed) {
      ClearException(env);
    }
    env->DeleteLocalRef(local);
    if (failed) {
      if (global != nullptr) {
        env->DeleteGlobalRef(global);
      }
      return nullptr;
    }
    return global;
  };
  cache_->location = global_class("android.location.Location");
  cache_->location_result = global_class("android.location.LocationResult");
  cache_->list = global_class("java.util.List");
  cache_->array_list = global_class("java.util.ArrayList");
  cache_->gnss_status = global_class("android.location.GnssStatus");
  cache_->nmea_listener = global_class("android.location.IGnssNmeaListener");
  cache_->method = global_class("java.lang.reflect.Method");
  cache_->long_class = global_class("java.lang.Long");
  if (cache_->location == nullptr || cache_->location_result == nullptr || cache_->list == nullptr ||
      cache_->array_list == nullptr || cache_->gnss_status == nullptr ||
      cache_->nmea_listener == nullptr || cache_->method == nullptr ||
      cache_->long_class == nullptr) {
    ClearException(env);
    *error = "framework_cache_class_missing";
    return false;
  }

  const auto instance_method = [&](jclass type, const char* name,
                                   const char* signature) -> jmethodID {
    return env->ExceptionCheck() ? nullptr : env->GetMethodID(type, name, signature);
  };
  const auto static_method = [&](jclass type, const char* name,
                                 const char* signature) -> jmethodID {
    return env->ExceptionCheck() ? nullptr : env->GetStaticMethodID(type, name, signature);
  };

  cache_->location_copy =
      instance_method(cache_->location, "<init>", "(Landroid/location/Location;)V");
  cache_->location_get_provider =
      instance_method(cache_->location, "getProvider", "()Ljava/lang/String;");
  cache_->location_get_time = instance_method(cache_->location, "getTime", "()J");
  cache_->location_get_elapsed =
      instance_method(cache_->location, "getElapsedRealtimeNanos", "()J");
  cache_->location_set_time = instance_method(cache_->location, "setTime", "(J)V");
  cache_->location_set_elapsed =
      instance_method(cache_->location, "setElapsedRealtimeNanos", "(J)V");
  cache_->location_set_latitude =
      instance_method(cache_->location, "setLatitude", "(D)V");
  cache_->location_set_longitude =
      instance_method(cache_->location, "setLongitude", "(D)V");
  cache_->location_set_accuracy =
      instance_method(cache_->location, "setAccuracy", "(F)V");
  cache_->location_set_altitude =
      instance_method(cache_->location, "setAltitude", "(D)V");
  cache_->location_set_vertical_accuracy =
      instance_method(cache_->location, "setVerticalAccuracyMeters", "(F)V");
  cache_->location_set_msl_altitude =
      instance_method(cache_->location, "setMslAltitudeMeters", "(D)V");
  cache_->location_set_msl_accuracy =
      instance_method(cache_->location, "setMslAltitudeAccuracyMeters", "(F)V");
  cache_->location_set_speed = instance_method(cache_->location, "setSpeed", "(F)V");
  cache_->location_set_speed_accuracy =
      instance_method(cache_->location, "setSpeedAccuracyMetersPerSecond", "(F)V");
  cache_->location_set_bearing = instance_method(cache_->location, "setBearing", "(F)V");
  cache_->location_set_bearing_accuracy =
      instance_method(cache_->location, "setBearingAccuracyDegrees", "(F)V");
  cache_->location_remove_bearing =
      instance_method(cache_->location, "removeBearing", "()V");
  cache_->location_remove_bearing_accuracy =
      instance_method(cache_->location, "removeBearingAccuracy", "()V");
  cache_->location_is_complete = instance_method(cache_->location, "isComplete", "()Z");
  cache_->location_result_as_list =
      instance_method(cache_->location_result, "asList", "()Ljava/util/List;");
  cache_->location_result_create =
      static_method(cache_->location_result, "create",
                    "(Ljava/util/List;)Landroid/location/LocationResult;");
  cache_->location_result_validate =
      instance_method(cache_->location_result, "validate",
                      "()Landroid/location/LocationResult;");
  cache_->list_size = instance_method(cache_->list, "size", "()I");
  cache_->list_get = instance_method(cache_->list, "get", "(I)Ljava/lang/Object;");
  cache_->array_list_constructor = instance_method(cache_->array_list, "<init>", "(I)V");
  cache_->array_list_add =
      instance_method(cache_->array_list, "add", "(Ljava/lang/Object;)Z");
  cache_->gnss_status_wrap = static_method(
      cache_->gnss_status, "wrap", "(I[I[F[F[F[F[F)Landroid/location/GnssStatus;");
  cache_->nmea_received = instance_method(
      cache_->nmea_listener, "onNmeaReceived", "(JLjava/lang/String;)V");
  cache_->method_invoke = instance_method(
      cache_->method, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
  cache_->long_value = instance_method(cache_->long_class, "longValue", "()J");
  if (env->ExceptionCheck()) {
    ClearException(env);
    *error = "framework_cache_method_missing";
    return false;
  }
  const std::array required = {
      cache_->location_copy,
      cache_->location_get_provider,
      cache_->location_get_time,
      cache_->location_get_elapsed,
      cache_->location_set_time,
      cache_->location_set_elapsed,
      cache_->location_set_latitude,
      cache_->location_set_longitude,
      cache_->location_set_accuracy,
      cache_->location_set_altitude,
      cache_->location_set_vertical_accuracy,
      cache_->location_set_msl_altitude,
      cache_->location_set_msl_accuracy,
      cache_->location_set_speed,
      cache_->location_set_speed_accuracy,
      cache_->location_set_bearing,
      cache_->location_set_bearing_accuracy,
      cache_->location_remove_bearing,
      cache_->location_remove_bearing_accuracy,
      cache_->location_is_complete,
      cache_->location_result_as_list,
      cache_->location_result_create,
      cache_->location_result_validate,
      cache_->list_size,
      cache_->list_get,
      cache_->array_list_constructor,
      cache_->array_list_add,
      cache_->gnss_status_wrap,
      cache_->nmea_received,
      cache_->method_invoke,
      cache_->long_value,
  };
  if (std::any_of(required.begin(), required.end(), [](jmethodID value) { return value == nullptr; })) {
    *error = "framework_cache_method_null";
    return false;
  }
  return true;
}

bool Runtime::CacheApplication(JNIEnv* env, std::string* error) {
  cache_ = std::make_unique<JniCache>();
  const auto global_class = [&](const char* name) -> jclass {
    jobject local = LoadClass(env, name);
    if (local == nullptr) {
      return nullptr;
    }
    jclass global = static_cast<jclass>(env->NewGlobalRef(local));
    const bool failed = global == nullptr || env->ExceptionCheck();
    if (failed) {
      ClearException(env);
    }
    env->DeleteLocalRef(local);
    if (failed) {
      if (global != nullptr) {
        env->DeleteGlobalRef(global);
      }
      return nullptr;
    }
    return global;
  };
  cache_->location = global_class("android.location.Location");
  cache_->method = global_class("java.lang.reflect.Method");
  if (cache_->location == nullptr || cache_->method == nullptr) {
    *error = "application_cache_class_missing";
    return false;
  }
  const auto instance_method = [&](jclass type, const char* name,
                                   const char* signature) -> jmethodID {
    return env->ExceptionCheck() ? nullptr : env->GetMethodID(type, name, signature);
  };
  cache_->location_copy =
      instance_method(cache_->location, "<init>", "(Landroid/location/Location;)V");
  cache_->location_get_provider =
      instance_method(cache_->location, "getProvider", "()Ljava/lang/String;");
  cache_->location_get_time = instance_method(cache_->location, "getTime", "()J");
  cache_->location_get_elapsed =
      instance_method(cache_->location, "getElapsedRealtimeNanos", "()J");
  cache_->location_set_time = instance_method(cache_->location, "setTime", "(J)V");
  cache_->location_set_elapsed =
      instance_method(cache_->location, "setElapsedRealtimeNanos", "(J)V");
  cache_->location_set_latitude =
      instance_method(cache_->location, "setLatitude", "(D)V");
  cache_->location_set_longitude =
      instance_method(cache_->location, "setLongitude", "(D)V");
  cache_->location_set_accuracy = instance_method(cache_->location, "setAccuracy", "(F)V");
  cache_->location_set_altitude = instance_method(cache_->location, "setAltitude", "(D)V");
  cache_->location_set_vertical_accuracy =
      instance_method(cache_->location, "setVerticalAccuracyMeters", "(F)V");
  cache_->location_set_msl_altitude =
      instance_method(cache_->location, "setMslAltitudeMeters", "(D)V");
  cache_->location_set_msl_accuracy =
      instance_method(cache_->location, "setMslAltitudeAccuracyMeters", "(F)V");
  cache_->location_set_speed = instance_method(cache_->location, "setSpeed", "(F)V");
  cache_->location_set_speed_accuracy =
      instance_method(cache_->location, "setSpeedAccuracyMetersPerSecond", "(F)V");
  cache_->location_set_bearing = instance_method(cache_->location, "setBearing", "(F)V");
  cache_->location_set_bearing_accuracy =
      instance_method(cache_->location, "setBearingAccuracyDegrees", "(F)V");
  cache_->location_remove_bearing = instance_method(cache_->location, "removeBearing", "()V");
  cache_->location_remove_bearing_accuracy =
      instance_method(cache_->location, "removeBearingAccuracy", "()V");
  cache_->location_is_complete = instance_method(cache_->location, "isComplete", "()Z");
  cache_->method_invoke = env->GetMethodID(
      cache_->method, "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
  const std::array required = {
      cache_->location_copy,
      cache_->location_get_provider,
      cache_->location_get_time,
      cache_->location_get_elapsed,
      cache_->location_set_time,
      cache_->location_set_elapsed,
      cache_->location_set_latitude,
      cache_->location_set_longitude,
      cache_->location_set_accuracy,
      cache_->location_set_altitude,
      cache_->location_set_vertical_accuracy,
      cache_->location_set_msl_altitude,
      cache_->location_set_msl_accuracy,
      cache_->location_set_speed,
      cache_->location_set_speed_accuracy,
      cache_->location_set_bearing,
      cache_->location_set_bearing_accuracy,
      cache_->location_remove_bearing,
      cache_->location_remove_bearing_accuracy,
      cache_->location_is_complete,
      cache_->method_invoke,
  };
  if (env->ExceptionCheck() ||
      std::any_of(required.begin(), required.end(), [](jmethodID value) { return value == nullptr; })) {
    ClearException(env);
    *error = "application_cache_method_missing";
    return false;
  }
  return true;
}

RuntimeResult Runtime::FailInitialization(JNIEnv* env, std::string reason) {
  RuntimeResult result;
  result.retention_required = !Rollback(env);
  result.reason = result.retention_required ? "hook_rollback_retained" : std::move(reason);
  return result;
}

bool Runtime::ActivateInstalledBridges(JNIEnv* env, std::string* error) noexcept {
  const std::size_t count = hook_host_ == nullptr ? 0 : hook_host_->HookCount();
  for (std::size_t index = 0; index < count; ++index) {
    if (hook_host_->OwnerAt(index) != hook_host::FeatureOwner::kLocation) {
      continue;
    }
    jobject bridge = hook_host_->BridgeAt(index);
    env->CallVoidMethod(bridge, bridge_activate_);
    if (env->ExceptionCheck()) {
      ClearException(env);
      DeactivateInstalledBridges(env);
      if (error != nullptr) {
        *error = "fail_closed_activation_failed";
      }
      return false;
    }
  }
  return true;
}

void Runtime::DeactivateInstalledBridges(JNIEnv* env) noexcept {
  const std::size_t count = hook_host_ == nullptr ? 0 : hook_host_->HookCount();
  for (std::size_t index = 0; index < count; ++index) {
    if (hook_host_->OwnerAt(index) != hook_host::FeatureOwner::kLocation) {
      continue;
    }
    jobject bridge = hook_host_->BridgeAt(index);
    if (bridge != nullptr) {
      env->CallVoidMethod(bridge, bridge_deactivate_);
      ClearException(env);
    }
  }
}

RuntimeResult Runtime::Initialize(JNIEnv* env, const std::vector<std::uint8_t>& bridge_dex,
                                  std::uint32_t* activation_claim) {
  RuntimeResult result;
  std::string error;
  if (ActivationTimedOut(activation_claim)) {
    StoreControlRuntimeState(control_page_, ControlRuntimeState::kInactive);
    result.reason = "post_server_timeout";
    return result;
  }
  if (!art_ready_) {
    result.reason = "art_not_prepared";
    return result;
  }
  if (!AcquireSystemServerClassLoader(env, &error) || !LoadBridge(env, bridge_dex, &error) ||
      !CacheFramework(env, &error)) {
    return FailInitialization(env, error);
  }
  if (ActivationTimedOut(activation_claim)) {
    return FailInitialization(env, "post_server_timeout");
  }
  {
    std::unique_lock gate(g_dispatch_gate);
    g_runtime.store(this, std::memory_order_release);
    g_dispatch_accepting.store(true, std::memory_order_release);
  }

  const struct HookSpec {
    int id;
    const char* class_name;
    const char* method_name;
    std::vector<const char*> parameters;
    bool is_static;
  } hooks[] = {
      {kLocationHook,
       "com.android.server.location.provider.LocationProviderManager",
       "onReportLocation",
       {"android.location.LocationResult"},
       false},
      {kStatusHook,
       "com.android.server.location.gnss.GnssStatusProvider",
       "onReportSvStatus",
       {"android.location.GnssStatus"},
       false},
      {kNmeaHook,
       "com.android.server.location.gnss.GnssNmeaProvider$1",
       "lambda$apply$0",
       {"long", "android.location.IGnssNmeaListener"},
       false},
      {kMeasurementHook,
       "com.android.server.location.gnss.GnssMeasurementsProvider",
       "$r8$lambda$S8pdLPl99PS7zjoxENRN9LwkjGc",
       {"android.location.GnssMeasurementsEvent",
        "android.location.IGnssMeasurementsListener"},
       true},
      {kNavigationHook,
       "com.android.server.location.gnss.GnssNavigationMessageProvider",
       "$r8$lambda$f-SZ_rst97IBLhPC3S2XayaZh7U",
       {"android.location.GnssNavigationMessage",
        "android.location.IGnssNavigationMessageListener"},
       true},
  };
  for (const HookSpec& hook : hooks) {
    if (ActivationTimedOut(activation_claim)) {
      return FailInitialization(env, "post_server_timeout");
    }
    if (!InstallHook(env, hook.id, hook.class_name, hook.method_name, hook.parameters,
                     hook.is_static, &error)) {
      return FailInitialization(env, error);
    }
    result.installed_hooks.emplace_back(std::string(hook.class_name) + "." + hook.method_name);
    if (ActivationTimedOut(activation_claim)) {
      return FailInitialization(env, "post_server_timeout");
    }
  }
  if (hook_host_ == nullptr || hook_host_->HookCount() != kHookCount) {
    return FailInitialization(env, "hook_count_mismatch");
  }
  if (config_.enabled && !ActivateInstalledBridges(env, &error)) {
    return FailInitialization(env, error);
  }
  if (ActivationTimedOut(activation_claim)) {
    return FailInitialization(env, "post_server_timeout");
  }
  std::uint32_t expected_claim = kRuntimeActivationPending;
  if (!__atomic_compare_exchange_n(activation_claim, &expected_claim,
                                   kRuntimeActivationCommitted, false, __ATOMIC_ACQ_REL,
                                   __ATOMIC_ACQUIRE)) {
    return FailInitialization(env, "post_server_timeout");
  }
  result.ready = true;
  if (config_.enabled) {
    active_.store(true, std::memory_order_release);
    StoreControlRuntimeState(control_page_, ControlRuntimeState::kActive);
    PublishControlAck(control_page_, applied_generation_, ControlAckState::kApplied,
                      ControlReason::kNone);
    result.active = true;
    result.reason = config_.raw_gnss_mode == RawGnssMode::kPassthrough
                        ? "active:passthrough:physical_raw_warning"
                        : "active:blocked";
  } else {
    StoreControlRuntimeState(control_page_, ControlRuntimeState::kWaiting);
    result.reason = "waiting_for_coordinates";
  }
  return result;
}


RuntimeResult Runtime::InitializeApplication(
    JNIEnv* env, const std::vector<std::uint8_t>& bridge_dex) {
  RuntimeResult result;
  std::string error;
  if (!art_ready_) {
    result.reason = "application_art_not_prepared";
    return result;
  }
  if (application_control_page_ == nullptr || application_control_writable_ ||
      !ValidateControlIdentity(*application_control_page_, application_server_pid_, boot_id_,
                               application_boot_generation_,
                               application_boot_fields_digest_, &error) ||
      (LoadControlRuntimeState(*application_control_page_) != ControlRuntimeState::kActive &&
       LoadControlRuntimeState(*application_control_page_) != ControlRuntimeState::kWaiting)) {
    result.reason = error.empty() ? "application_control_invalid" : error;
    return result;
  }
  if (!AcquireApplicationClassLoader(env, &error) || !LoadBridge(env, bridge_dex, &error) ||
      !CacheApplication(env, &error)) {
    return FailInitialization(env, error);
  }
  {
    std::unique_lock gate(g_dispatch_gate);
    g_runtime.store(this, std::memory_order_release);
    g_dispatch_accepting.store(true, std::memory_order_release);
  }
  const struct HookSpec {
    int id;
    const char* class_name;
    const char* method_name;
    std::vector<const char*> parameters;
  } hooks[] = {
      {kAppParcelHook,
       "android.location.Location$1",
       "createFromParcel",
       {"android.os.Parcel"}},
  };
  for (const HookSpec& hook : hooks) {
    if (!InstallHook(env, hook.id, hook.class_name, hook.method_name, hook.parameters, false,
                     &error)) {
      return FailInitialization(env, error);
    }
    result.installed_hooks.emplace_back(
        std::string(hook.class_name) + "." + hook.method_name);
  }
  if (hook_host_ == nullptr || hook_host_->HookCount() != kAppHookCount) {
    return FailInitialization(env, "application_hook_count_mismatch");
  }
  if (application_fail_closed_ && config_.enabled) {
    for (std::size_t index = 0; index < hook_host_->HookCount(); ++index) {
      jobject bridge = hook_host_->BridgeAt(index);
      env->CallVoidMethod(bridge, bridge_activate_);
      if (env->ExceptionCheck()) {
        ClearException(env);
        return FailInitialization(env, "application_fail_closed_activation_failed");
      }
    }
  }
  result.ready = true;
  if (config_.enabled) {
    active_.store(true, std::memory_order_release);
    result.active = true;
    result.reason = "application_delivery_active";
  } else {
    result.reason = "application_delivery_waiting";
  }
  return result;
}

bool Runtime::Rollback(JNIEnv* env) {
  active_.store(false, std::memory_order_release);
  StoreControlRuntimeState(control_page_, ControlRuntimeState::kInactive);
  if (application_control_writable_) {
    StoreControlRuntimeState(application_control_page_, ControlRuntimeState::kInactive);
  }
  if (bridge_deactivate_ != nullptr) {
    DeactivateInstalledBridges(env);
  }
  g_dispatch_accepting.store(false, std::memory_order_release);
  {
    std::unique_lock gate(g_dispatch_gate);
    if (g_runtime.load(std::memory_order_acquire) == this) {
      g_runtime.store(nullptr, std::memory_order_release);
    }
  }
  const bool complete = hook_host_ != nullptr && hook_host_->RollbackTo(env, 0);
  if (!complete) {
    rollback_incomplete_ = true;
    return false;
  }
  if (bridge_class_ != nullptr) {
    env->UnregisterNatives(bridge_class_);
    ClearException(env);
    env->DeleteGlobalRef(bridge_class_);
    bridge_class_ = nullptr;
  }
  bridge_constructor_ = nullptr;
  bridge_callback_ = nullptr;
  bridge_set_backup_ = nullptr;
  bridge_activate_ = nullptr;
  bridge_deactivate_ = nullptr;
  if (cache_ != nullptr) {
    const std::array classes = {
        cache_->location,    cache_->location_result, cache_->list,   cache_->array_list,
        cache_->gnss_status, cache_->nmea_listener,   cache_->method, cache_->long_class,
    };
    for (jclass value : classes) {
      if (value != nullptr) {
        env->DeleteGlobalRef(value);
      }
    }
    cache_.reset();
  }
  if (system_class_loader_ != nullptr) {
    env->DeleteGlobalRef(system_class_loader_);
    system_class_loader_ = nullptr;
  }
  if (bridge_loader_ != nullptr) {
    env->DeleteGlobalRef(bridge_loader_);
    bridge_loader_ = nullptr;
  }
  rollback_incomplete_ = false;
  return true;
}

jobject Runtime::CallBackup(JNIEnv* env, jobject backup, jobjectArray args,
                            bool static_target) noexcept {
  if (cache_ == nullptr || backup == nullptr || args == nullptr) {
    return nullptr;
  }
  const jsize length = env->GetArrayLength(args);
  if (env->ExceptionCheck()) {
    ClearException(env);
    return nullptr;
  }
  jobject receiver = static_target || length == 0 ? nullptr : env->GetObjectArrayElement(args, 0);
  if (env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(receiver);
    return nullptr;
  }
  jclass object_class = env->FindClass("java/lang/Object");
  if (object_class == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(receiver);
    return nullptr;
  }
  const jsize parameter_count = static_target ? length : std::max<jsize>(0, length - 1);
  jobjectArray parameters = env->NewObjectArray(parameter_count, object_class, nullptr);
  if (parameters == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(object_class);
    env->DeleteLocalRef(receiver);
    return nullptr;
  }
  for (jsize index = 0; parameters != nullptr && index < parameter_count; ++index) {
    jobject value = env->GetObjectArrayElement(args, index + (static_target ? 0 : 1));
    if (env->ExceptionCheck()) {
      ClearException(env);
      env->DeleteLocalRef(value);
      env->DeleteLocalRef(parameters);
      env->DeleteLocalRef(object_class);
      env->DeleteLocalRef(receiver);
      return nullptr;
    }
    env->SetObjectArrayElement(parameters, index, value);
    const bool set_failed = env->ExceptionCheck();
    if (set_failed) {
      ClearException(env);
    }
    env->DeleteLocalRef(value);
    if (set_failed) {
      env->DeleteLocalRef(parameters);
      env->DeleteLocalRef(object_class);
      env->DeleteLocalRef(receiver);
      return nullptr;
    }
  }
  jobject result = env->CallObjectMethod(backup, cache_->method_invoke, receiver, parameters);
  if (env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(result);
    result = nullptr;
  }
  env->DeleteLocalRef(parameters);
  env->DeleteLocalRef(object_class);
  env->DeleteLocalRef(receiver);
  return result;
}

jobjectArray Runtime::ReplaceArgument(JNIEnv* env, jobjectArray args, int index,
                                      jobject replacement) noexcept {
  if (args == nullptr || replacement == nullptr) {
    return nullptr;
  }
  jclass object_class = env->FindClass("java/lang/Object");
  if (object_class == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    return nullptr;
  }
  const jsize length = env->GetArrayLength(args);
  if (env->ExceptionCheck() || index < 0 || index >= length) {
    ClearException(env);
    env->DeleteLocalRef(object_class);
    return nullptr;
  }
  jobjectArray copy = env->NewObjectArray(length, object_class, nullptr);
  const bool copy_failed = copy == nullptr || env->ExceptionCheck();
  if (copy_failed) {
    ClearException(env);
  }
  env->DeleteLocalRef(object_class);
  if (copy_failed) {
    env->DeleteLocalRef(copy);
    return nullptr;
  }
  for (jsize position = 0; position < length; ++position) {
    jobject value = position == index ? replacement : env->GetObjectArrayElement(args, position);
    if (env->ExceptionCheck()) {
      ClearException(env);
      env->DeleteLocalRef(value);
      env->DeleteLocalRef(copy);
      return nullptr;
    }
    env->SetObjectArrayElement(copy, position, value);
    const bool set_failed = env->ExceptionCheck();
    if (set_failed) {
      ClearException(env);
    }
    if (position != index) {
      env->DeleteLocalRef(value);
    }
    if (set_failed) {
      env->DeleteLocalRef(copy);
      return nullptr;
    }
  }
  return copy;
}

jobject Runtime::TransformLocation(JNIEnv* env, jobject backup, jobjectArray args) noexcept {
  const jsize argument_count = env->GetArrayLength(args);
  if (env->ExceptionCheck() || argument_count < 2) {
    ClearException(env);
    return nullptr;
  }
  jobject original_result = env->GetObjectArrayElement(args, 1);
  if (original_result == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(original_result);
    return nullptr;
  }
  jobject list = env->CallObjectMethod(original_result, cache_->location_result_as_list);
  if (list == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(list);
    env->DeleteLocalRef(original_result);
    return nullptr;
  }
  const jint count = env->CallIntMethod(list, cache_->list_size);
  if (env->ExceptionCheck() || count < 0) {
    ClearException(env);
    env->DeleteLocalRef(list);
    env->DeleteLocalRef(original_result);
    return nullptr;
  }
  jobject output_list =
      env->NewObject(cache_->array_list, cache_->array_list_constructor, count);
  if (output_list == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(output_list);
    env->DeleteLocalRef(list);
    env->DeleteLocalRef(original_result);
    return nullptr;
  }
  const auto abort = [&](jobject original, jobject copy, jstring provider_string,
                         const char* provider_utf) -> jobject {
    ClearException(env);
    if (provider_utf != nullptr) {
      env->ReleaseStringUTFChars(provider_string, provider_utf);
    }
    env->DeleteLocalRef(provider_string);
    env->DeleteLocalRef(copy);
    env->DeleteLocalRef(original);
    env->DeleteLocalRef(output_list);
    env->DeleteLocalRef(list);
    env->DeleteLocalRef(original_result);
    return nullptr;
  };
  for (jint index = 0; index < count; ++index) {
    jobject original = env->CallObjectMethod(list, cache_->list_get, index);
    if (original == nullptr || env->ExceptionCheck()) {
      return abort(original, nullptr, nullptr, nullptr);
    }
    jobject copy = env->NewObject(cache_->location, cache_->location_copy, original);
    if (copy == nullptr || env->ExceptionCheck()) {
      return abort(original, copy, nullptr, nullptr);
    }
    jstring provider_string = static_cast<jstring>(
        env->CallObjectMethod(copy, cache_->location_get_provider));
    if (provider_string == nullptr || env->ExceptionCheck()) {
      return abort(original, copy, provider_string, nullptr);
    }
    const char* provider_utf = env->GetStringUTFChars(provider_string, nullptr);
    if (provider_utf == nullptr || env->ExceptionCheck()) {
      return abort(original, copy, provider_string, provider_utf);
    }
    const jlong wall = env->CallLongMethod(copy, cache_->location_get_time);
    if (env->ExceptionCheck()) {
      return abort(original, copy, provider_string, provider_utf);
    }
    const jlong elapsed = env->CallLongMethod(copy, cache_->location_get_elapsed);
    if (env->ExceptionCheck()) {
      return abort(original, copy, provider_string, provider_utf);
    }
    const jlong normalized_wall = wall > 0 ? wall : WallTimeMs();
    const jlong normalized_elapsed = elapsed > 0 ? elapsed : ElapsedNs();
    const Sample sample = model_.Update(provider_utf, normalized_wall, normalized_elapsed);
    env->ReleaseStringUTFChars(provider_string, provider_utf);
    provider_utf = nullptr;
    if (wall <= 0) {
      env->CallVoidMethod(copy, cache_->location_set_time, sample.wall_time_ms);
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_elapsed, sample.elapsed_realtime_ns);
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_latitude, sample.latitude_deg);
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_longitude, sample.longitude_deg);
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_accuracy,
                          static_cast<jfloat>(sample.horizontal_accuracy_m));
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_altitude, sample.altitude_ellipsoid_m);
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_vertical_accuracy,
                          static_cast<jfloat>(sample.vertical_accuracy_m));
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_msl_altitude, sample.altitude_msl_m);
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_msl_accuracy,
                          static_cast<jfloat>(sample.msl_altitude_accuracy_m));
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_speed,
                          static_cast<jfloat>(sample.speed_mps));
    }
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_speed_accuracy,
                          static_cast<jfloat>(sample.speed_accuracy_mps));
    }
    if (!env->ExceptionCheck() && sample.has_bearing) {
      env->CallVoidMethod(copy, cache_->location_set_bearing,
                          static_cast<jfloat>(sample.bearing_deg));
      if (!env->ExceptionCheck()) {
        env->CallVoidMethod(copy, cache_->location_set_bearing_accuracy,
                            static_cast<jfloat>(sample.bearing_accuracy_deg));
      }
    } else if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_remove_bearing);
      if (!env->ExceptionCheck()) {
        env->CallVoidMethod(copy, cache_->location_remove_bearing_accuracy);
      }
    }
    const jboolean complete = env->ExceptionCheck()
        ? JNI_FALSE
        : env->CallBooleanMethod(copy, cache_->location_is_complete);
    if (env->ExceptionCheck() || complete != JNI_TRUE) {
      return abort(original, copy, provider_string, nullptr);
    }
    const jboolean added =
        env->CallBooleanMethod(output_list, cache_->array_list_add, copy);
    if (env->ExceptionCheck() || added != JNI_TRUE) {
      return abort(original, copy, provider_string, nullptr);
    }
    env->DeleteLocalRef(provider_string);
    env->DeleteLocalRef(copy);
    env->DeleteLocalRef(original);
  }
  jobject transformed = output_list == nullptr
                            ? nullptr
                            : env->CallStaticObjectMethod(cache_->location_result,
                                                          cache_->location_result_create,
                                                          output_list);
  if (transformed == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(transformed);
    env->DeleteLocalRef(output_list);
    env->DeleteLocalRef(list);
    env->DeleteLocalRef(original_result);
    return nullptr;
  }
  jobject validated =
      env->CallObjectMethod(transformed, cache_->location_result_validate);
  if (validated == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(validated);
    env->DeleteLocalRef(transformed);
    env->DeleteLocalRef(output_list);
    env->DeleteLocalRef(list);
    env->DeleteLocalRef(original_result);
    return nullptr;
  }
  env->DeleteLocalRef(validated);
  jobjectArray replacement = ReplaceArgument(env, args, 1, transformed);
  jobject result = replacement == nullptr ? nullptr : CallBackup(env, backup, replacement, false);
  if (replacement == nullptr) {
    ClearException(env);
  }
  env->DeleteLocalRef(replacement);
  env->DeleteLocalRef(transformed);
  env->DeleteLocalRef(output_list);
  env->DeleteLocalRef(list);
  env->DeleteLocalRef(original_result);
  return result;
}

jobject Runtime::TransformStatus(JNIEnv* env, jobject backup, jobjectArray args) noexcept {
  const Sample latest = model_.Latest();
  const std::int64_t wall = latest.wall_time_ms > 0 ? latest.wall_time_ms : WallTimeMs();
  const ModelSnapshot snapshot = model_.Snapshot(wall);
  const auto& satellites = snapshot.satellites;
  const jsize count = static_cast<jsize>(satellites.size());
  jintArray packed = env->NewIntArray(count);
  jfloatArray cn0 = nullptr;
  jfloatArray elevation = nullptr;
  jfloatArray azimuth = nullptr;
  jfloatArray carrier = nullptr;
  jfloatArray baseband = nullptr;
  if (packed != nullptr && !env->ExceptionCheck()) {
    cn0 = env->NewFloatArray(count);
  }
  if (cn0 != nullptr && !env->ExceptionCheck()) {
    elevation = env->NewFloatArray(count);
  }
  if (elevation != nullptr && !env->ExceptionCheck()) {
    azimuth = env->NewFloatArray(count);
  }
  if (azimuth != nullptr && !env->ExceptionCheck()) {
    carrier = env->NewFloatArray(count);
  }
  if (carrier != nullptr && !env->ExceptionCheck()) {
    baseband = env->NewFloatArray(count);
  }
  const auto delete_arrays = [&]() {
    env->DeleteLocalRef(packed);
    env->DeleteLocalRef(cn0);
    env->DeleteLocalRef(elevation);
    env->DeleteLocalRef(azimuth);
    env->DeleteLocalRef(carrier);
    env->DeleteLocalRef(baseband);
  };
  if (packed == nullptr || cn0 == nullptr || elevation == nullptr || azimuth == nullptr ||
      carrier == nullptr || baseband == nullptr || env->ExceptionCheck()) {
    ClearException(env);
    delete_arrays();
    return nullptr;
  }
  std::vector<jint> packed_values(count);
  std::vector<jfloat> cn0_values(count), elevation_values(count), azimuth_values(count),
      carrier_values(count), baseband_values(count);
  for (jsize index = 0; index < count; ++index) {
    const Satellite& satellite = satellites[index];
    int flags = 1 | 2 | 8 | 16;
    if (satellite.used_in_fix) {
      flags |= 4;
    }
    packed_values[index] = (satellite.svid << 12) | (satellite.constellation << 8) | flags;
    cn0_values[index] = static_cast<jfloat>(satellite.cn0_db_hz);
    elevation_values[index] = static_cast<jfloat>(satellite.elevation_deg);
    azimuth_values[index] = static_cast<jfloat>(satellite.azimuth_deg);
    carrier_values[index] = static_cast<jfloat>(satellite.carrier_frequency_hz);
    baseband_values[index] = static_cast<jfloat>(satellite.baseband_cn0_db_hz);
  }
  env->SetIntArrayRegion(packed, 0, count, packed_values.data());
  if (!env->ExceptionCheck()) {
    env->SetFloatArrayRegion(cn0, 0, count, cn0_values.data());
  }
  if (!env->ExceptionCheck()) {
    env->SetFloatArrayRegion(elevation, 0, count, elevation_values.data());
  }
  if (!env->ExceptionCheck()) {
    env->SetFloatArrayRegion(azimuth, 0, count, azimuth_values.data());
  }
  if (!env->ExceptionCheck()) {
    env->SetFloatArrayRegion(carrier, 0, count, carrier_values.data());
  }
  if (!env->ExceptionCheck()) {
    env->SetFloatArrayRegion(baseband, 0, count, baseband_values.data());
  }
  if (env->ExceptionCheck()) {
    ClearException(env);
    delete_arrays();
    return nullptr;
  }
  jobject status = env->CallStaticObjectMethod(cache_->gnss_status, cache_->gnss_status_wrap, count,
                                                packed, cn0, elevation, azimuth, carrier, baseband);
  jobjectArray replacement =
      status == nullptr || env->ExceptionCheck() ? nullptr : ReplaceArgument(env, args, 1, status);
  jobject result = replacement == nullptr ? nullptr : CallBackup(env, backup, replacement, false);
  if (replacement == nullptr) {
    ClearException(env);
  }
  env->DeleteLocalRef(replacement);
  env->DeleteLocalRef(status);
  delete_arrays();
  return result;
}

jobject Runtime::DeliverNmea(JNIEnv* env, jobjectArray args) noexcept {
  const jsize argument_count = env->GetArrayLength(args);
  if (env->ExceptionCheck() || argument_count < 3) {
    ClearException(env);
    return nullptr;
  }
  jobject boxed_timestamp = env->GetObjectArrayElement(args, 1);
  if (env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(boxed_timestamp);
    return nullptr;
  }
  jobject listener = env->GetObjectArrayElement(args, 2);
  if (env->ExceptionCheck()) {
    ClearException(env);
    env->DeleteLocalRef(boxed_timestamp);
    env->DeleteLocalRef(listener);
    return nullptr;
  }
  jlong timestamp = WallTimeMs();
  if (boxed_timestamp != nullptr) {
    timestamp = env->CallLongMethod(boxed_timestamp, cache_->long_value);
    if (env->ExceptionCheck()) {
      ClearException(env);
      env->DeleteLocalRef(boxed_timestamp);
      env->DeleteLocalRef(listener);
      return nullptr;
    }
  }
  const ModelSnapshot snapshot = model_.SnapshotForNmea(WallTimeMs(), ElapsedNs());
  const auto sentences = FormatNmea(snapshot.sample, snapshot.satellites);
  if (!sentences.empty() && listener != nullptr) {
    const std::size_t index =
        nmea_sequence_.fetch_add(1, std::memory_order_relaxed) % sentences.size();
    jstring value = env->NewStringUTF(sentences[index].c_str());
    if (value != nullptr && !env->ExceptionCheck()) {
      env->CallVoidMethod(listener, cache_->nmea_received, timestamp, value);
    }
    ClearException(env);
    env->DeleteLocalRef(value);
  }
  ClearException(env);
  env->DeleteLocalRef(boxed_timestamp);
  env->DeleteLocalRef(listener);
  return nullptr;
}

jobject Runtime::ApplicationTransformFailure(JNIEnv* env, jobject original,
                                             bool delivery_active) noexcept {
  ClearException(env);
  if (ResolveApplicationCallbackDisposition(true, application_fail_closed_,
                                            delivery_active, false) ==
      ApplicationCallbackDisposition::kSuppressed) {
    env->DeleteLocalRef(original);
    return nullptr;
  }
  return original;
}

jobject Runtime::TransformApplicationParcelLocation(JNIEnv* env, jobject backup,
                                                    jobjectArray args,
                                                    bool configuration_valid) noexcept {
  jobject original = CallBackup(env, backup, args, false);
  if (!configuration_valid || original == nullptr || cache_ == nullptr) {
    return ApplicationTransformFailure(env, original, configuration_valid);
  }
  jobject copy = env->NewObject(cache_->location, cache_->location_copy, original);
  jstring provider = copy == nullptr || env->ExceptionCheck()
      ? nullptr
      : static_cast<jstring>(env->CallObjectMethod(copy, cache_->location_get_provider));
  const char* provider_utf = provider == nullptr || env->ExceptionCheck()
      ? nullptr
      : env->GetStringUTFChars(provider, nullptr);
  if (copy == nullptr || provider == nullptr || provider_utf == nullptr || env->ExceptionCheck()) {
    if (provider_utf != nullptr) {
      env->ReleaseStringUTFChars(provider, provider_utf);
    }
    env->DeleteLocalRef(provider);
    env->DeleteLocalRef(copy);
    return ApplicationTransformFailure(env, original, true);
  }
  const jlong wall = env->CallLongMethod(copy, cache_->location_get_time);
  const jlong elapsed = env->ExceptionCheck()
      ? 0
      : env->CallLongMethod(copy, cache_->location_get_elapsed);
  if (env->ExceptionCheck()) {
    env->ReleaseStringUTFChars(provider, provider_utf);
    env->DeleteLocalRef(provider);
    env->DeleteLocalRef(copy);
    return ApplicationTransformFailure(env, original, true);
  }
  const Sample sample = model_.Update(provider_utf, wall > 0 ? wall : WallTimeMs(),
                                      elapsed > 0 ? elapsed : ElapsedNs());
  env->ReleaseStringUTFChars(provider, provider_utf);
  if (wall <= 0) {
    env->CallVoidMethod(copy, cache_->location_set_time, sample.wall_time_ms);
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_elapsed, sample.elapsed_realtime_ns);
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_latitude, sample.latitude_deg);
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_longitude, sample.longitude_deg);
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_accuracy,
                        static_cast<jfloat>(sample.horizontal_accuracy_m));
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_altitude, sample.altitude_ellipsoid_m);
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_vertical_accuracy,
                        static_cast<jfloat>(sample.vertical_accuracy_m));
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_msl_altitude, sample.altitude_msl_m);
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_msl_accuracy,
                        static_cast<jfloat>(sample.msl_altitude_accuracy_m));
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_speed, static_cast<jfloat>(sample.speed_mps));
  }
  if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_set_speed_accuracy,
                        static_cast<jfloat>(sample.speed_accuracy_mps));
  }
  if (!env->ExceptionCheck() && sample.has_bearing) {
    env->CallVoidMethod(copy, cache_->location_set_bearing,
                        static_cast<jfloat>(sample.bearing_deg));
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_set_bearing_accuracy,
                          static_cast<jfloat>(sample.bearing_accuracy_deg));
    }
  } else if (!env->ExceptionCheck()) {
    env->CallVoidMethod(copy, cache_->location_remove_bearing);
    if (!env->ExceptionCheck()) {
      env->CallVoidMethod(copy, cache_->location_remove_bearing_accuracy);
    }
  }
  const jboolean complete = env->ExceptionCheck()
      ? JNI_FALSE
      : env->CallBooleanMethod(copy, cache_->location_is_complete);
  env->DeleteLocalRef(provider);
  if (env->ExceptionCheck() || complete != JNI_TRUE) {
    env->DeleteLocalRef(copy);
    return ApplicationTransformFailure(env, original, true);
  }
  env->DeleteLocalRef(original);
  return copy;
}

bool Runtime::TryActivateWaitingRuntime(JNIEnv* env) noexcept {
  if (control_page_ == nullptr ||
      LoadControlRuntimeState(*control_page_) != ControlRuntimeState::kWaiting) {
    return false;
  }
  std::string identity_error;
  if (!ValidateControlIdentity(*control_page_, static_cast<std::uint32_t>(getpid()), boot_id_,
                               config_.config_generation, boot_fields_digest_, &identity_error)) {
    return false;
  }
  Config candidate;
  ControlReason reason = ControlReason::kNone;
  const ControlReadResult read =
      ReadPublishedControlConfig(*control_page_, applied_generation_, &candidate, &reason);
  if (read != ControlReadResult::kReady) {
    return false;
  }
  std::string error;
  if (!ValidateLiveTransition(config_, candidate, applied_generation_, &error) ||
      !ActivateInstalledBridges(env, &error)) {
    PublishControlAck(control_page_, candidate.config_generation, ControlAckState::kRejected,
                      ControlReason::kInvalidConfig);
    return false;
  }
  if (!model_.Reconfigure(candidate, WallTimeMs(), ElapsedNs(), &error)) {
    DeactivateInstalledBridges(env);
    PublishControlAck(control_page_, candidate.config_generation, ControlAckState::kRejected,
                      ControlReason::kInvalidConfig);
    return false;
  }
  applied_generation_ = candidate.config_generation;
  rejected_generation_ = 0;
  nmea_sequence_.store(0, std::memory_order_relaxed);
  active_.store(true, std::memory_order_release);
  StoreControlRuntimeState(control_page_, ControlRuntimeState::kActive);
  PublishControlAck(control_page_, applied_generation_, ControlAckState::kApplied,
                    ControlReason::kNone);
  return true;
}

bool Runtime::TryActivateWaitingApplication(JNIEnv* env) noexcept {
  if (application_control_page_ == nullptr || application_control_writable_ ||
      LoadControlRuntimeState(*application_control_page_) != ControlRuntimeState::kActive) {
    return false;
  }
  Config candidate;
  ControlReason reason = ControlReason::kNone;
  const ControlReadResult read = ReadAppliedControlConfig(
      *application_control_page_, applied_generation_, &candidate, &reason);
  if (read != ControlReadResult::kReady) {
    return false;
  }
  std::string error;
  if (!ValidateControlIdentity(*application_control_page_, application_server_pid_, boot_id_,
                               application_boot_generation_,
                               application_boot_fields_digest_, &error) ||
      !ValidateLiveTransition(config_, candidate, applied_generation_, &error)) {
    return false;
  }
  if (application_fail_closed_ && !ActivateInstalledBridges(env, &error)) {
    return false;
  }
  if (!model_.Reconfigure(candidate, WallTimeMs(), ElapsedNs(), &error)) {
    if (application_fail_closed_) {
      DeactivateInstalledBridges(env);
    }
    return false;
  }
  applied_generation_ = candidate.config_generation;
  active_.store(true, std::memory_order_release);
  return true;
}

jobject Runtime::Dispatch(JNIEnv* env, int hook_id, jobject backup, jobjectArray args) noexcept {
  const bool is_static = hook_id == kMeasurementHook || hook_id == kNavigationHook;
  if (g_in_callback) {
    return active_.load(std::memory_order_acquire) ? nullptr
                                                   : CallBackup(env, backup, args, is_static);
  }
  std::lock_guard dispatch_lock(dispatch_mutex_);
  g_in_callback = true;
  jobject result = nullptr;
  if (!active_.load(std::memory_order_acquire)) {
    if (hook_id == kAppParcelHook) {
      TryActivateWaitingApplication(env);
    } else {
      TryActivateWaitingRuntime(env);
    }
  }
  if (!active_.load(std::memory_order_acquire)) {
    result = CallBackup(env, backup, args, is_static);
  } else {
    const bool application_configuration_valid = hook_id == kAppParcelHook
        ? CheckApplicationConfiguration()
        : true;
    if (hook_id != kAppParcelHook) {
      CheckLiveConfiguration();
    }
    switch (hook_id) {
      case kLocationHook:
        result = TransformLocation(env, backup, args);
        break;
      case kStatusHook:
        result = TransformStatus(env, backup, args);
        break;
      case kNmeaHook:
        result = DeliverNmea(env, args);
        break;
      case kMeasurementHook:
      case kNavigationHook:
        result = config_.raw_gnss_mode == RawGnssMode::kPassthrough
                     ? CallBackup(env, backup, args, true)
                     : nullptr;
        break;
      case kAppParcelHook:
        result = TransformApplicationParcelLocation(
            env, backup, args, application_configuration_valid);
        break;
      default:
        result = nullptr;
    }
  }
  ClearException(env);
  g_in_callback = false;
  return result;
}

void Runtime::CheckLiveConfiguration() noexcept {
  if (control_page_ == nullptr) {
    return;
  }
  std::string identity_error;
  if (!ValidateControlIdentity(*control_page_, static_cast<std::uint32_t>(getpid()), boot_id_,
                               config_.config_generation, boot_fields_digest_, &identity_error)) {
    const std::uint64_t generation = LoadPublishedGeneration(*control_page_);
    if (generation > 0 && generation <= kMaximumControlGeneration &&
        generation != rejected_generation_) {
      PublishControlAck(control_page_, generation, ControlAckState::kRejected,
                        ControlReason::kIdentityMismatch);
      rejected_generation_ = generation;
    }
    return;
  }

  Config candidate;
  ControlReason reason = ControlReason::kNone;
  const ControlReadResult result =
      ReadPublishedControlConfig(*control_page_, applied_generation_, &candidate, &reason);
  if (result == ControlReadResult::kNoUpdate || result == ControlReadResult::kRetry) {
    return;
  }
  const std::uint64_t generation = LoadPublishedGeneration(*control_page_);
  if (result != ControlReadResult::kReady) {
    if (generation > 0 && generation <= kMaximumControlGeneration &&
        generation != rejected_generation_) {
      PublishControlAck(control_page_, generation, ControlAckState::kRejected, reason);
      rejected_generation_ = generation;
    }
    return;
  }

  std::string reconfigure_error;
  if (!model_.Reconfigure(candidate, WallTimeMs(), ElapsedNs(), &reconfigure_error)) {
    ControlReason rejection = ControlReason::kInvalidConfig;
    if (reconfigure_error == "stale_generation") {
      rejection = ControlReason::kStaleGeneration;
    } else if (reconfigure_error == "boot_field_mismatch") {
      rejection = ControlReason::kBootFieldMismatch;
    }
    PublishControlAck(control_page_, candidate.config_generation, ControlAckState::kRejected,
                      rejection);
    rejected_generation_ = candidate.config_generation;
    return;
  }
  applied_generation_ = candidate.config_generation;
  rejected_generation_ = 0;
  nmea_sequence_.store(0, std::memory_order_relaxed);
  PublishControlAck(control_page_, applied_generation_, ControlAckState::kApplied,
                    ControlReason::kNone);
}

bool Runtime::CheckApplicationConfiguration() noexcept {
  if (application_control_page_ == nullptr || application_control_writable_) {
    return false;
  }
  std::string identity_error;
  if (!ValidateControlIdentity(*application_control_page_, application_server_pid_, boot_id_,
                               application_boot_generation_,
                               application_boot_fields_digest_, &identity_error) ||
      LoadControlRuntimeState(*application_control_page_) != ControlRuntimeState::kActive) {
    return false;
  }

  Config candidate;
  ControlReason reason = ControlReason::kNone;
  const ControlReadResult result = ReadAppliedControlConfig(
      *application_control_page_, applied_generation_, &candidate, &reason);
  if (result != ControlReadResult::kReady) {
    return true;
  }
  std::string reconfigure_error;
  if (!model_.Reconfigure(candidate, WallTimeMs(), ElapsedNs(), &reconfigure_error)) {
    return true;
  }
  applied_generation_ = candidate.config_generation;
  rejected_generation_ = 0;
  return true;
}

}  // namespace zygveil::location
