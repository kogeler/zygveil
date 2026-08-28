// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <jni.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "model.hpp"
#include "control_protocol.hpp"
#include "hook_host.hpp"

namespace zygveil::location {

inline constexpr std::uint32_t kRuntimeActivationPending = 0;
inline constexpr std::uint32_t kRuntimeActivationCommitted = 1;
inline constexpr std::uint32_t kRuntimeActivationTimedOut = 2;

struct RuntimeResult {
  bool active = false;
  bool ready = false;
  bool retention_required = false;
  std::string reason;
  std::vector<std::string> installed_hooks;
};

class Runtime {
 public:
  Runtime(Config config, ControlPage* control_page, int control_descriptor,
          ControlPage* application_control_page, bool application_control_writable,
          bool application_fail_closed, std::string boot_id);
  ~Runtime();

  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  bool PrepareArt(JNIEnv* env, std::string* error);
  hook_host::ArtHookHost* HookHost() const noexcept;
  RuntimeResult Initialize(JNIEnv* env, const std::vector<std::uint8_t>& bridge_dex,
                           std::uint32_t* activation_claim);
  RuntimeResult InitializeApplication(JNIEnv* env,
                                      const std::vector<std::uint8_t>& bridge_dex);
  jobject Dispatch(JNIEnv* env, int hook_id, jobject backup, jobjectArray args) noexcept;

 private:
  struct JniCache;

  bool AcquireSystemServerClassLoader(JNIEnv* env, std::string* error);
  bool AcquireApplicationClassLoader(JNIEnv* env, std::string* error);
  bool LoadBridge(JNIEnv* env, const std::vector<std::uint8_t>& bridge_dex,
                  std::string* error);
  bool CacheFramework(JNIEnv* env, std::string* error);
  bool CacheApplication(JNIEnv* env, std::string* error);
  bool InstallHook(JNIEnv* env, int hook_id, const char* class_name, const char* method_name,
                   const std::vector<const char*>& parameter_types, bool static_target,
                   std::string* error);
  bool Rollback(JNIEnv* env);
  RuntimeResult FailInitialization(JNIEnv* env, std::string reason);
  jobject CallBackup(JNIEnv* env, jobject backup, jobjectArray args, bool static_target) noexcept;
  jobject TransformLocation(JNIEnv* env, jobject backup, jobjectArray args) noexcept;
  jobject TransformStatus(JNIEnv* env, jobject backup, jobjectArray args) noexcept;
  jobject DeliverNmea(JNIEnv* env, jobjectArray args) noexcept;
  jobject TransformApplicationParcelLocation(JNIEnv* env, jobject backup, jobjectArray args,
                                             bool configuration_valid) noexcept;
  jobject ApplicationTransformFailure(JNIEnv* env, jobject original,
                                      bool delivery_active) noexcept;
  jobject LoadClass(JNIEnv* env, const char* name) noexcept;
  jobject ResolveMethod(JNIEnv* env, const char* class_name, const char* method_name,
                        const std::vector<const char*>& parameter_types) noexcept;
  jobjectArray ReplaceArgument(JNIEnv* env, jobjectArray args, int index,
                               jobject replacement) noexcept;
  void ClearException(JNIEnv* env) const noexcept;
  void CheckLiveConfiguration() noexcept;
  bool CheckApplicationConfiguration() noexcept;
  bool ActivateInstalledBridges(JNIEnv* env, std::string* error) noexcept;
  void DeactivateInstalledBridges(JNIEnv* env) noexcept;
  bool TryActivateWaitingRuntime(JNIEnv* env) noexcept;
  bool TryActivateWaitingApplication(JNIEnv* env) noexcept;

  Config config_;
  StationaryModel model_;
  ControlPage* control_page_ = nullptr;
  int control_descriptor_ = -1;
  ControlPage* application_control_page_ = nullptr;
  bool application_control_writable_ = false;
  bool application_fail_closed_ = false;
  std::uint32_t application_server_pid_ = 0;
  std::uint64_t application_boot_generation_ = 0;
  std::uint64_t application_boot_fields_digest_ = 0;
  std::string boot_id_;
  std::uint64_t boot_fields_digest_ = 0;
  std::uint64_t applied_generation_ = 0;
  std::uint64_t rejected_generation_ = 0;
  std::recursive_mutex dispatch_mutex_;
  bool art_ready_ = false;
  std::atomic<bool> active_{false};
  jobject system_class_loader_ = nullptr;
  jobject bridge_loader_ = nullptr;
  jclass bridge_class_ = nullptr;
  jmethodID bridge_constructor_ = nullptr;
  jmethodID bridge_callback_ = nullptr;
  jmethodID bridge_set_backup_ = nullptr;
  jmethodID bridge_activate_ = nullptr;
  jmethodID bridge_deactivate_ = nullptr;
  std::unique_ptr<hook_host::ArtHookHost> hook_host_;
  std::atomic<std::uint64_t> nmea_sequence_{0};
  std::unique_ptr<JniCache> cache_;
  bool rollback_incomplete_ = false;
};

}  // namespace zygveil::location
