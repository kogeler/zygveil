// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <jni.h>

#include <cstddef>
#include <string>
#include <vector>

namespace zygveil::hook_host {

enum class FeatureOwner {
  kLocation,
  kServerVpn,
};

struct BridgeContract {
  jclass bridge_class = nullptr;
  jmethodID constructor = nullptr;
  jmethodID callback = nullptr;
  jmethodID set_backup = nullptr;
};

class ArtHookHost final {
 public:
  using Checkpoint = std::size_t;

  ArtHookHost() = default;
  ~ArtHookHost() = default;

  ArtHookHost(const ArtHookHost&) = delete;
  ArtHookHost& operator=(const ArtHookHost&) = delete;

  bool Prepare(JNIEnv* env, std::string* error);
  bool Ready() const noexcept;
  Checkpoint CreateCheckpoint() const noexcept;
  std::size_t HookCount() const noexcept;
  std::size_t HookCountSince(Checkpoint checkpoint) const noexcept;
  jobject BridgeAt(std::size_t index) const noexcept;
  FeatureOwner OwnerAt(std::size_t index) const noexcept;
  bool Install(JNIEnv* env, FeatureOwner owner, int hook_id, bool static_target,
               jobject target, const BridgeContract& bridge, std::string* error);
  bool RollbackTo(JNIEnv* env, Checkpoint checkpoint) noexcept;
  bool RollbackIncomplete() const noexcept;

 private:
  struct HookRecord {
    FeatureOwner owner = FeatureOwner::kLocation;
    jobject target = nullptr;
    jobject bridge = nullptr;
  };

  std::vector<HookRecord> hooks_;
  bool art_ready_ = false;
  bool rollback_incomplete_ = false;
};

}  // namespace zygveil::hook_host
