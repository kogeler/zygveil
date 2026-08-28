// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <jni.h>

#include <cstddef>
#include <string>
#include <vector>

#include "config.hpp"

namespace zygveil::hook_host {
class ArtHookHost;
}

namespace zygveil::server_vpn {

struct RuntimeResult {
  bool active = false;
  bool retention_required = false;
  std::size_t hook_count = 0;
  std::string reason;
};

class Runtime final {
 public:
  Runtime(Config config, hook_host::ArtHookHost* hook_host);
  ~Runtime() = default;

  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  RuntimeResult Initialize(JNIEnv* env, const std::vector<std::uint8_t>& bridge_dex,
                           std::uint32_t* activation_claim);
  const Config& config() const noexcept;

 private:
  void ClearException(JNIEnv* env) const noexcept;
  jobject LoadClass(JNIEnv* env, jobject loader, const char* class_name) noexcept;
  void Cleanup(JNIEnv* env) noexcept;
  bool LoadBridge(JNIEnv* env, const std::vector<std::uint8_t>& bridge_dex,
                  std::string* error);
  bool PrepareCatalog(JNIEnv* env, std::string* error);
  bool ConfigureBridge(JNIEnv* env, std::string* error);
  void DeactivateInstalled(JNIEnv* env, std::size_t checkpoint) noexcept;

  Config config_;
  hook_host::ArtHookHost* hook_host_ = nullptr;
  jobject system_class_loader_ = nullptr;
  jobject bridge_loader_ = nullptr;
  jclass bridge_class_ = nullptr;
  jmethodID bridge_constructor_ = nullptr;
  jmethodID bridge_callback_ = nullptr;
  jmethodID bridge_set_backup_ = nullptr;
  jmethodID bridge_activate_ = nullptr;
  jmethodID bridge_deactivate_ = nullptr;
  jmethodID bridge_prepare_runtime_ = nullptr;
  jmethodID bridge_configure_runtime_ = nullptr;
  jmethodID bridge_resolved_hooks_ = nullptr;
  jmethodID bridge_runtime_ready_ = nullptr;
  jmethodID bridge_reset_runtime_ = nullptr;
};

}  // namespace zygveil::server_vpn
