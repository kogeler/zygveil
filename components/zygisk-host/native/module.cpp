// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include <android/dlext.h>
#include <android/log.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <jni.h>
#include <link.h>
#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <zygisk.hpp>

#include "model.hpp"
#include "control_protocol.hpp"
#include "locationctl_core.hpp"
#include "process_liveness.hpp"
#include "runtime.hpp"
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
#include "config.hpp"
#include "status.hpp"
#include "../../server-vpn/runtime/native/runtime.hpp"
#endif

namespace zygveil::location {
namespace {

constexpr char kModuleDirectory[] = "/data/adb/modules/zygveil";
constexpr char kLogTag[] = "ZygVeil";
constexpr std::string_view kRuntimeReadyMarker = "zygveil-runtime-ready-v1";
constexpr std::size_t kMaximumConfigBytes = 32 * 1024;
constexpr std::size_t kMaximumDexBytes = 1024 * 1024;
constexpr std::size_t kMaximumShadowhookHelperBytes = 64 * 1024;
constexpr std::size_t kMaximumStatusBytes = 4096;
constexpr std::uint32_t kStatusChannelMagic = 0x47464c53;
constexpr std::uint32_t kStatusChannelVersion = 5;
constexpr std::size_t kBootIdLength = 36;
constexpr int kStatusWaitAttempts = 1200;
constexpr long kStatusWaitNanoseconds = 50 * 1000 * 1000;
constexpr int kStatusCommitWaitAttempts = 100;
constexpr int kControlHandshakeTimeoutMs = 10 * 1000;
constexpr int kControlReplacementWaitSeconds = 2;
constexpr int kSystemServerIdentityWaitAttempts = 100;
constexpr char kStatusDescriptorToken = 'S';
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
constexpr char kServerVpnStatusDescriptorToken = 'V';
constexpr char kServerVpnStatusLockName[] = ".server-vpn-runtime-status.lock";
constexpr char kServerVpnStatusTemporaryName[] = ".server-vpn-runtime-status.tmp";
constexpr char kServerVpnStatusName[] = "server-vpn-runtime-status.properties";
constexpr std::string_view kServerVpnStatusMemfdProcTarget =
    "/memfd:zygveil-server-vpn-status (deleted)";
#endif
constexpr char kControlDescriptorToken = 'C';
constexpr std::uint32_t kControlBrokerMagic = 0x47464c42;
constexpr std::uint32_t kControlBrokerVersion = 1;
constexpr std::uint32_t kCompanionPending = 0;
constexpr std::uint32_t kCompanionReady = 1;
constexpr std::uint32_t kCompanionFailed = 2;
constexpr std::string_view kStatusMemfdProcTarget =
    "/memfd:zygveil-location-status (deleted)";
constexpr char kRuntimeStatusLockName[] = ".runtime-status.lock";
constexpr char kApplicationControlName[] = ".app-control";
constexpr uid_t kSystemServerUid = 1000;
constexpr gid_t kSystemServerGid = 1000;
std::unique_ptr<Runtime> g_persistent_runtime;
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
std::unique_ptr<::zygveil::server_vpn::Runtime> g_persistent_server_vpn_runtime;
#endif
std::vector<std::uint8_t> g_shadowhook_helper;

struct SharedStatus {
  std::uint32_t magic = kStatusChannelMagic;
  std::uint32_t version = kStatusChannelVersion;
  std::uint32_t raw_mode = static_cast<std::uint32_t>(RawGnssMode::kBlocked);
  std::uint32_t initial_length = 0;
  std::uint32_t final_length = 0;
  std::uint32_t final_ready = 0;
  std::uint32_t companion_state = kCompanionPending;
  std::uint32_t server_pid = 0;
  std::uint32_t activation_claim = kRuntimeActivationPending;
  std::uint64_t config_generation = 0;
  std::uint64_t server_start_ticks = 0;
  std::array<char, kBootIdLength + 1> boot_id{};
  std::array<char, 512> initial_body{};
  std::array<char, kMaximumStatusBytes> final_body{};
};

struct InitContext {
  JavaVM* vm = nullptr;
  std::unique_ptr<Runtime> runtime;
  RawGnssMode raw_gnss_mode = RawGnssMode::kBlocked;
  std::uint64_t config_generation = 0;
  int control_fd = 0;
  std::uint32_t control_owner_pid = 0;
  std::uint64_t control_owner_start_ticks = 0;
  std::string boot_id;
  std::vector<std::uint8_t> bridge;
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
  std::unique_ptr<::zygveil::server_vpn::Runtime> server_vpn_runtime;
  std::optional<::zygveil::server_vpn::Config> server_vpn_config;
  std::vector<std::uint8_t> server_vpn_bridge;
  SharedStatus* server_vpn_status = nullptr;
#endif
  SharedStatus* status = nullptr;
};

struct ControlBrokerReceipt {
  std::uint32_t magic = kControlBrokerMagic;
  std::uint32_t version = kControlBrokerVersion;
  std::uint32_t accepted = 0;
  std::uint32_t control_owner_pid = 0;
  std::uint64_t control_owner_start_ticks = 0;
  std::int32_t control_fd = -1;
  std::uint32_t reserved = 0;
};

struct ControlBrokerState {
  int descriptor = -1;
  int process_descriptor = -1;
  std::uint32_t server_pid = 0;
  std::uint64_t server_start_ticks = 0;
  std::uint64_t config_generation = 0;
  std::array<char, kBootIdLength + 1> boot_id{};
};

pthread_mutex_t g_control_broker_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_control_broker_condition = PTHREAD_COND_INITIALIZER;
ControlBrokerState g_control_broker;

bool ValidateStatusChannelDescriptorFor(int descriptor, std::string_view expected_target) {
  struct stat status {};
  if (descriptor < 0 || fstat(descriptor, &status) != 0) {
    return false;
  }
  const int flags = fcntl(descriptor, F_GETFL);
  const int seals = fcntl(descriptor, F_GET_SEALS);
  const bool owner_allowed = status.st_uid == 0 || status.st_uid == kSystemServerUid;
  const bool group_allowed = status.st_gid == 0 || status.st_gid == kSystemServerGid;
  if (flags < 0 || seals != kControlMemfdSeals || (flags & O_ACCMODE) != O_RDWR ||
      !S_ISREG(status.st_mode) || !owner_allowed || !group_allowed || status.st_nlink != 0 ||
      (status.st_mode & 07777) != kControlMemfdMode ||
      status.st_size != static_cast<off_t>(sizeof(SharedStatus))) {
    return false;
  }
  const std::string path = "/proc/self/fd/" + std::to_string(descriptor);
  std::array<char, 128> target{};
  ssize_t count;
  do {
    count = readlink(path.c_str(), target.data(), target.size() - 1);
  } while (count < 0 && errno == EINTR);
  return count == static_cast<ssize_t>(expected_target.size()) &&
      std::string_view(target.data(), static_cast<std::size_t>(count)) ==
      expected_target;
}

bool ValidateStatusChannelDescriptor(int descriptor) {
  return ValidateStatusChannelDescriptorFor(descriptor, kStatusMemfdProcTarget);
}

ControlPage* CreateControlPage(const Config& config, std::string_view boot_id,
                               int* control_descriptor, std::string* error) {
  *control_descriptor = -1;
  if (geteuid() != 0 || getegid() != 0) {
    *error = "pre_server_identity_invalid";
    return nullptr;
  }
  const int descriptor =
      memfd_create(kControlMemfdName.data(), MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (descriptor < 0) {
    *error = "control_memfd_create_failed";
    return nullptr;
  }
  if (ftruncate(descriptor, sizeof(ControlPage)) != 0) {
    *error = "control_memfd_resize_failed";
    close(descriptor);
    return nullptr;
  }
  if (fcntl(descriptor, F_ADD_SEALS, kControlMemfdSeals) != 0) {
    *error = "control_memfd_seal_failed";
    close(descriptor);
    return nullptr;
  }
  if (!ValidateControlMemfdDescriptor(descriptor, 0, 0, error)) {
    close(descriptor);
    return nullptr;
  }
  void* mapping =
      mmap(nullptr, sizeof(ControlPage), PROT_READ | PROT_WRITE, MAP_SHARED, descriptor, 0);
  if (mapping == MAP_FAILED) {
    *error = "control_memfd_map_failed";
    close(descriptor);
    return nullptr;
  }
  auto* page = static_cast<ControlPage*>(mapping);
  if (!InitializeControlPage(page, config, static_cast<std::uint32_t>(getpid()), boot_id, error) ||
      msync(page, sizeof(ControlPage), MS_SYNC) != 0) {
    if (error->empty()) {
      *error = "control_memfd_sync_failed";
    }
    munmap(page, sizeof(ControlPage));
    close(descriptor);
    return nullptr;
  }
  *control_descriptor = descriptor;
  return page;
}

bool ReadFully(int descriptor, void* buffer, std::size_t bytes) {
  auto* output = static_cast<std::uint8_t*>(buffer);
  while (bytes > 0) {
    const ssize_t count = read(descriptor, output, bytes);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return false;
    }
    output += count;
    bytes -= static_cast<std::size_t>(count);
  }
  return true;
}

bool WriteFully(int descriptor, const void* buffer, std::size_t bytes) {
  const auto* input = static_cast<const std::uint8_t*>(buffer);
  while (bytes > 0) {
    const ssize_t count = write(descriptor, input, bytes);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      return false;
    }
    input += count;
    bytes -= static_cast<std::size_t>(count);
  }
  return true;
}

bool SleepFully(long nanoseconds) {
  struct timespec remaining {
    .tv_sec = 0, .tv_nsec = nanoseconds
  };
  while (nanosleep(&remaining, &remaining) != 0) {
    if (errno != EINTR) {
      return false;
    }
  }
  return true;
}

std::string Trim(std::string value) {
  while (!value.empty() && (value.back() == '\n' || value.back() == '\r' || value.back() == ' ')) {
    value.pop_back();
  }
  return value;
}

bool ReadAt(int directory, const char* name, std::size_t maximum, std::vector<std::uint8_t>* output) {
  const int descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    return false;
  }
  struct stat status {};
  const bool valid = fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode) &&
                     status.st_size >= 0 && static_cast<std::size_t>(status.st_size) <= maximum;
  if (!valid) {
    close(descriptor);
    return false;
  }
  output->resize(static_cast<std::size_t>(status.st_size));
  const bool read = output->empty() || ReadFully(descriptor, output->data(), output->size());
  close(descriptor);
  return read;
}

bool ReadTextAt(int directory, const char* name, std::size_t maximum, std::string* output) {
  std::vector<std::uint8_t> bytes;
  if (!ReadAt(directory, name, maximum, &bytes)) {
    return false;
  }
  output->assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  return true;
}

bool ReadRootAt(int directory, const char* name, std::size_t maximum,
                mode_t expected_mode, std::vector<std::uint8_t>* output) {
  const int descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat status {};
  const bool valid = descriptor >= 0 && fstat(descriptor, &status) == 0 &&
                     S_ISREG(status.st_mode) && status.st_uid == 0 && status.st_gid == 0 &&
                     status.st_nlink == 1 && (status.st_mode & 07777) == expected_mode &&
                     status.st_size > 0 && static_cast<std::size_t>(status.st_size) <= maximum;
  if (!valid) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    return false;
  }
  output->resize(static_cast<std::size_t>(status.st_size));
  const bool read = ReadFully(descriptor, output->data(), output->size());
  close(descriptor);
  return read;
}

bool ReadRootTextAt(int directory, const char* name, std::size_t maximum,
                    mode_t expected_mode, std::string* output) {
  std::vector<std::uint8_t> bytes;
  if (!ReadRootAt(directory, name, maximum, expected_mode, &bytes)) {
    return false;
  }
  output->assign(reinterpret_cast<const char*>(bytes.data()), bytes.size());
  return true;
}

bool ReadPrivateTextAt(int directory, const char* name, std::size_t maximum,
                       std::string* output) {
  return ReadRootTextAt(directory, name, maximum, 0600, output);
}

bool ReadBootId(std::string* output) {
  const int descriptor = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return false;
  }
  std::array<char, kBootIdLength + 2> bytes{};
  ssize_t count;
  do {
    count = read(descriptor, bytes.data(), bytes.size());
  } while (count < 0 && errno == EINTR);
  close(descriptor);
  if (count < static_cast<ssize_t>(kBootIdLength)) {
    return false;
  }
  output->assign(bytes.data(), kBootIdLength);
  for (std::size_t index = 0; index < output->size(); ++index) {
    const char value = (*output)[index];
    const bool separator = index == 8 || index == 13 || index == 18 || index == 23;
    if ((separator && value != '-') ||
        (!separator && !((value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')))) {
      output->clear();
      return false;
    }
  }
  return true;
}

bool ReadProcessStartTicks(std::uint32_t pid, std::uint64_t* output) {
  const std::string path = "/proc/" + std::to_string(pid) + "/stat";
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    return false;
  }
  std::array<char, 1024> body{};
  ssize_t count;
  do {
    count = read(descriptor, body.data(), body.size() - 1);
  } while (count < 0 && errno == EINTR);
  close(descriptor);
  if (count <= 0 || count == static_cast<ssize_t>(body.size() - 1)) {
    return false;
  }
  const auto parsed = ParseProcessStartTicks(
      std::string_view(body.data(), static_cast<std::size_t>(count)));
  if (!parsed.has_value()) {
    return false;
  }
  *output = *parsed;
  return true;
}

void* LoadLibraryFromBytes(const char* soname, const std::vector<std::uint8_t>& bytes) {
  if (bytes.empty()) {
    return nullptr;
  }
  const int descriptor = memfd_create(soname, MFD_CLOEXEC);
  if (descriptor < 0 || !WriteFully(descriptor, bytes.data(), bytes.size()) ||
      lseek(descriptor, 0, SEEK_SET) < 0) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    return nullptr;
  }
  android_dlextinfo info{};
  info.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
  info.library_fd = descriptor;
  void* handle = android_dlopen_ext(soname, RTLD_NOW | RTLD_LOCAL, &info);
  close(descriptor);
  return handle;
}

void ReleaseShadowhookHelperBytes() {
  g_shadowhook_helper.clear();
  g_shadowhook_helper.shrink_to_fit();
}

}  // namespace

extern "C" void* zygveil_shadowhook_dlopen(const char* filename, int flags) {
  if (filename != nullptr && std::strcmp(filename, "libshadowhook_nothing.so") == 0) {
    void* handle = LoadLibraryFromBytes(filename, g_shadowhook_helper);
    if (handle != nullptr) {
      ReleaseShadowhookHelperBytes();
    }
    return handle;
  }
  return dlopen(filename, flags);
}

extern "C" int zygveil_shadowhook_dlclose(void* handle) {
  return dlclose(handle);
}

extern "C" void* xdl_open(const char* filename, int flags);
extern "C" bool sh_util_ends_with(const char* value, const char* suffix);

namespace {

constexpr std::string_view kShadowhookDeletedMemfd =
    "/memfd:libshadowhook_nothing.so (deleted)";

int FindShadowhookHelper(struct dl_phdr_info* info, std::size_t, void* opaque) {
  if (info == nullptr || info->dlpi_name == nullptr ||
      std::string_view(info->dlpi_name) != kShadowhookDeletedMemfd) {
    return 0;
  }
  auto* name = static_cast<std::array<char, 512>*>(opaque);
  const std::size_t length = std::strlen(info->dlpi_name);
  if (length == 0 || length >= name->size()) {
    return 0;
  }
  std::memcpy(name->data(), info->dlpi_name, length + 1);
  return 1;
}

}  // namespace

extern "C" void* zygveil_shadowhook_xdl_open(const char* filename, int flags) {
  void* handle = xdl_open(filename, flags);
  if (handle != nullptr || filename == nullptr ||
      std::strcmp(filename, "libshadowhook_nothing.so") != 0) {
    return handle;
  }
  std::array<char, 512> mapped_name{};
  dl_iterate_phdr(FindShadowhookHelper, &mapped_name);
  return mapped_name.front() == '\0' ? nullptr : xdl_open(mapped_name.data(), flags);
}

extern "C" bool zygveil_shadowhook_ends_with(const char* value, const char* suffix) {
  if (sh_util_ends_with(value, suffix)) {
    return true;
  }
  if (value == nullptr || suffix == nullptr ||
      std::strcmp(suffix, "libshadowhook_nothing.so") != 0) {
    return false;
  }
  return std::string_view(value) == kShadowhookDeletedMemfd;
}

namespace {

std::string StatusBody(std::string_view state, std::string_view reason,
                       RawGnssMode mode, std::size_t hooks, std::uint32_t server_pid = 0,
                       std::uint64_t config_generation = 0,
                       std::string_view boot_id = "unavailable", int control_fd = 0,
                       std::uint64_t server_start_ticks = 0,
                       std::uint32_t control_owner_pid = 0,
                       std::uint64_t control_owner_start_ticks = 0) {
  const std::string_view safe_reason =
      ValidRuntimeStatusReason(reason) ? reason : std::string_view{"runtime_reason_redacted"};
  return "schema_version=4\nstate=" + std::string(state) + "\nreason=" +
         std::string(safe_reason) + "\nraw_gnss_mode=" + std::string(RawGnssModeName(mode)) +
         "\nhook_count=" + std::to_string(hooks) +
         "\nsystem_server_pid=" + std::to_string(server_pid) +
         "\nsystem_server_start_ticks=" + std::to_string(server_start_ticks) +
         "\nconfig_generation=" + std::to_string(config_generation) +
         "\nboot_id=" + std::string(boot_id) + "\ncontrol_fd=" +
         std::to_string(control_fd) + "\ncontrol_owner_pid=" +
         std::to_string(control_owner_pid) + "\ncontrol_owner_start_ticks=" +
         std::to_string(control_owner_start_ticks) + "\n";
}

#ifdef ZYGVEIL_SERVER_VPN_FEATURE
std::string ServerVpnStatusBody(
    std::string_view state, std::string_view reason,
    const std::optional<::zygveil::server_vpn::Config>& config,
    std::size_t hooks, std::uint32_t server_pid, std::uint64_t server_start_ticks,
    std::string_view boot_id) {
  const std::string_view safe_reason = ::zygveil::server_vpn::ValidStatusReason(reason)
      ? reason
      : std::string_view{"runtime_reason_redacted"};
  ::zygveil::server_vpn::RuntimeStatus status{
      .state = std::string(state),
      .reason = std::string(safe_reason),
      .system_server_pid = server_pid,
      .system_server_start_ticks = server_start_ticks,
      .boot_id = std::string(boot_id),
      .config_generation = config.has_value() ? config->config_generation : 0,
      .hook_count = static_cast<std::uint32_t>(hooks),
      .target_set_sha256 = config.has_value()
          ? ::zygveil::server_vpn::TargetSetSha256(*config)
          : std::string(64, '0'),
  };
  std::string error;
  if (!::zygveil::server_vpn::ValidateRuntimeStatus(status, &error)) {
    status.state = "inactive";
    status.reason = "runtime_status_invalid";
    status.hook_count = 0;
  }
  return ::zygveil::server_vpn::EncodeRuntimeStatus(status);
}
#endif

SharedStatus* OpenStatusChannel(zygisk::Api* api, std::string_view boot_id,
                                int* companion_socket) {
  *companion_socket = -1;
  std::uint64_t server_start_ticks = 0;
  if (!ReadProcessStartTicks(static_cast<std::uint32_t>(getpid()), &server_start_ticks)) {
    return nullptr;
  }
  const std::string initial =
      StatusBody("arming", "pre_server_initializing", RawGnssMode::kBlocked, 0,
                 static_cast<std::uint32_t>(getpid()), 0, boot_id, 0,
                 server_start_ticks);
  if (initial.size() > SharedStatus{}.initial_body.size()) {
    return nullptr;
  }
  const int descriptor =
      memfd_create("zygveil-location-status", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (descriptor < 0 || ftruncate(descriptor, sizeof(SharedStatus)) != 0 ||
      fcntl(descriptor, F_ADD_SEALS, kControlMemfdSeals) != 0 ||
      !ValidateStatusChannelDescriptor(descriptor)) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    return nullptr;
  }
  void* mapping = mmap(nullptr, sizeof(SharedStatus), PROT_READ | PROT_WRITE, MAP_SHARED,
                       descriptor, 0);
  if (mapping == MAP_FAILED) {
    close(descriptor);
    return nullptr;
  }
  auto* status = new (mapping) SharedStatus();
  status->server_pid = static_cast<std::uint32_t>(getpid());
  status->server_start_ticks = server_start_ticks;
  std::memcpy(status->boot_id.data(), boot_id.data(), boot_id.size());
  status->initial_length = static_cast<std::uint32_t>(initial.size());
  std::memcpy(status->initial_body.data(), initial.data(), initial.size());
  const int socket = api->connectCompanion();
  const bool sent = socket >= 0 &&
      SendChannelDescriptor(socket, descriptor, kStatusDescriptorToken);
  close(descriptor);
  if (!sent) {
    if (socket >= 0) {
      close(socket);
    }
    munmap(mapping, sizeof(SharedStatus));
    return nullptr;
  }
  *companion_socket = socket;
  return status;
}

#ifdef ZYGVEIL_SERVER_VPN_FEATURE
SharedStatus* OpenServerVpnStatusChannel(zygisk::Api* api, std::string_view boot_id,
                                         int* companion_socket) {
  *companion_socket = -1;
  std::uint64_t server_start_ticks = 0;
  if (!ReadProcessStartTicks(static_cast<std::uint32_t>(getpid()), &server_start_ticks)) {
    return nullptr;
  }
  const std::string initial = ServerVpnStatusBody(
      "arming", "pre_server_initializing", std::nullopt, 0,
      static_cast<std::uint32_t>(getpid()), server_start_ticks, boot_id);
  if (initial.size() > SharedStatus{}.initial_body.size()) {
    return nullptr;
  }
  const int descriptor =
      memfd_create("zygveil-server-vpn-status", MFD_CLOEXEC | MFD_ALLOW_SEALING);
  if (descriptor < 0 || ftruncate(descriptor, sizeof(SharedStatus)) != 0 ||
      fcntl(descriptor, F_ADD_SEALS, kControlMemfdSeals) != 0 ||
      !ValidateStatusChannelDescriptorFor(descriptor, kServerVpnStatusMemfdProcTarget)) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    return nullptr;
  }
  void* mapping = mmap(nullptr, sizeof(SharedStatus), PROT_READ | PROT_WRITE, MAP_SHARED,
                       descriptor, 0);
  if (mapping == MAP_FAILED) {
    close(descriptor);
    return nullptr;
  }
  auto* status = new (mapping) SharedStatus();
  status->server_pid = static_cast<std::uint32_t>(getpid());
  status->server_start_ticks = server_start_ticks;
  std::memcpy(status->boot_id.data(), boot_id.data(), boot_id.size());
  status->initial_length = static_cast<std::uint32_t>(initial.size());
  std::memcpy(status->initial_body.data(), initial.data(), initial.size());
  const int socket = api->connectCompanion();
  const bool sent = socket >= 0 &&
      SendChannelDescriptor(socket, descriptor, kServerVpnStatusDescriptorToken);
  close(descriptor);
  if (!sent) {
    if (socket >= 0) {
      close(socket);
    }
    munmap(mapping, sizeof(SharedStatus));
    return nullptr;
  }
  *companion_socket = socket;
  return status;
}
#endif

void PublishStatus(SharedStatus* status, const std::string& body) {
  if (status == nullptr || body.empty() || body.size() > status->final_body.size()) {
    return;
  }
  std::memcpy(status->final_body.data(), body.data(), body.size());
  status->final_length = static_cast<std::uint32_t>(body.size());
  __atomic_store_n(&status->final_ready, 1U, __ATOMIC_RELEASE);
}

void CloseStatusChannel(SharedStatus** status, int* companion_socket = nullptr) {
  if (companion_socket != nullptr && *companion_socket >= 0) {
    close(*companion_socket);
    *companion_socket = -1;
  }
  if (*status != nullptr) {
    munmap(*status, sizeof(SharedStatus));
    *status = nullptr;
  }
}

bool WaitForStatusCompanion(SharedStatus* status) {
  if (status == nullptr) {
    return false;
  }
  constexpr int kReadyWaitAttempts = static_cast<int>(
      static_cast<long long>(kControlHandshakeTimeoutMs) * 1'000'000LL /
      kStatusWaitNanoseconds);
  for (int attempt = 0; attempt < kReadyWaitAttempts; ++attempt) {
    const std::uint32_t state =
        __atomic_load_n(&status->companion_state, __ATOMIC_ACQUIRE);
    if (state == kCompanionReady) {
      return true;
    }
    if (state == kCompanionFailed || !SleepFully(kStatusWaitNanoseconds)) {
      break;
    }
  }
  std::uint32_t expected_claim = kRuntimeActivationPending;
  __atomic_compare_exchange_n(&status->activation_claim, &expected_claim,
                              kRuntimeActivationTimedOut, false, __ATOMIC_ACQ_REL,
                              __ATOMIC_ACQUIRE);
  return false;
}

bool IsSystemServerProcess(std::uint32_t pid, std::uint64_t expected_start_ticks) {
  if (pid == 0 || kill(static_cast<pid_t>(pid), 0) != 0) {
    return false;
  }
  std::uint64_t actual_start_ticks = 0;
  if (expected_start_ticks == 0 || !ReadProcessStartTicks(pid, &actual_start_ticks) ||
      actual_start_ticks != expected_start_ticks) {
    return false;
  }
  const std::string path = "/proc/" + std::to_string(pid) + "/cmdline";
  const int descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    return false;
  }
  std::array<char, 64> command{};
  ssize_t count;
  do {
    count = read(descriptor, command.data(), command.size());
  } while (count < 0 && errno == EINTR);
  close(descriptor);
  constexpr std::string_view expected = "system_server";
  return count > static_cast<ssize_t>(expected.size()) &&
         std::memcmp(command.data(), expected.data(), expected.size()) == 0 &&
         command[expected.size()] == '\0';
}

bool ValidateControlMemfdTarget(int descriptor) {
  const std::string path = "/proc/self/fd/" + std::to_string(descriptor);
  std::array<char, 128> target{};
  ssize_t count;
  do {
    count = readlink(path.c_str(), target.data(), target.size() - 1);
  } while (count < 0 && errno == EINTR);
  return count == static_cast<ssize_t>(kControlMemfdProcTarget.size()) &&
      std::string_view(target.data(), static_cast<std::size_t>(count)) ==
      kControlMemfdProcTarget;
}

bool ValidateApplicationControlDescriptor(int descriptor, int expected_access_mode,
                                          std::string* error) {
  struct stat status {};
  const int flags = descriptor >= 0 ? fcntl(descriptor, F_GETFL) : -1;
  if (flags < 0 || (flags & O_ACCMODE) != expected_access_mode ||
      fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
      status.st_uid != 0 || status.st_gid != 0 || status.st_nlink != 1 ||
      (status.st_mode & 07777) != 0600 ||
      status.st_size != static_cast<off_t>(sizeof(ControlPage))) {
    *error = "application_control_file_identity_invalid";
    return false;
  }
  return true;
}

bool RegisterControlBroker(zygisk::Api* api, int descriptor,
                           ControlBrokerReceipt* receipt, std::string* error) {
  const int socket = api == nullptr ? -1 : api->connectCompanion();
  if (socket < 0 || !SendChannelDescriptor(socket, descriptor, kControlDescriptorToken) ||
      !ReceiveChannelBytes(socket, receipt, sizeof(*receipt),
                           kControlHandshakeTimeoutMs, error)) {
    if (socket >= 0) {
      close(socket);
    }
    if (error->empty()) {
      *error = "control_broker_registration_failed";
    }
    return false;
  }
  close(socket);
  std::uint64_t actual_start_ticks = 0;
  if (receipt->magic != kControlBrokerMagic ||
      receipt->version != kControlBrokerVersion || receipt->accepted != 1 ||
      receipt->control_owner_pid == 0 || receipt->control_owner_start_ticks == 0 ||
      receipt->control_fd < 3 ||
      !ReadProcessStartTicks(receipt->control_owner_pid, &actual_start_ticks) ||
      actual_start_ticks != receipt->control_owner_start_ticks) {
    *error = "control_broker_receipt_invalid";
    return false;
  }
  return true;
}

ControlPage* MapApplicationControlPageAt(int directory, std::string_view boot_id,
                                         Config* config, std::string* error) {
  std::string status_text;
  const bool status_read = ReadRootTextAt(
      directory, "runtime-status.properties", kMaximumStatusBytes, 0644, &status_text);
  const auto status = status_read ? ParseRuntimeControlStatus(status_text, error) : std::nullopt;
  if (!status.has_value() || status->state != "ready" || status->boot_id != boot_id) {
    if (error->empty()) {
      *error = "application_control_status_invalid";
    }
    return nullptr;
  }
  const int descriptor =
      openat(directory, kApplicationControlName, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0 || !ValidateApplicationControlDescriptor(descriptor, O_RDONLY, error)) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    if (error->empty()) {
      *error = "application_control_file_invalid";
    }
    return nullptr;
  }
  void* mapping = mmap(nullptr, sizeof(ControlPage), PROT_READ, MAP_SHARED, descriptor, 0);
  close(descriptor);
  if (mapping == MAP_FAILED) {
    *error = "application_control_file_map_failed";
    return nullptr;
  }
  auto* page = static_cast<ControlPage*>(mapping);
  errno = 0;
  if (mprotect(page, sizeof(ControlPage), PROT_READ | PROT_WRITE) == 0) {
    mprotect(page, sizeof(ControlPage), PROT_READ);
    munmap(page, sizeof(ControlPage));
    *error = "application_control_mapping_writable";
    return nullptr;
  }
  Config applied;
  ControlReason reason = ControlReason::kNone;
  const ControlRuntimeState runtime_state = LoadControlRuntimeState(*page);
  const bool config_valid =
      (runtime_state == ControlRuntimeState::kWaiting ||
       runtime_state == ControlRuntimeState::kActive) &&
      ReadAppliedControlConfig(*page, 0, &applied, &reason) == ControlReadResult::kReady &&
      ((runtime_state == ControlRuntimeState::kWaiting && !applied.enabled) ||
       (runtime_state == ControlRuntimeState::kActive && applied.enabled)) &&
      ValidateControlIdentity(*page, status->system_server_pid, boot_id,
                              status->config_generation,
                              BootFieldsDigest(EncodeConfig(applied)), error);
  if (!config_valid) {
    if (error->empty()) {
      *error = "application_control_page_invalid";
    }
    munmap(page, sizeof(ControlPage));
    return nullptr;
  }
  *config = applied;
  return page;
}

bool WaitForSystemServerProcess(std::uint32_t pid, std::uint64_t expected_start_ticks,
                                int process_descriptor = -1) {
  for (int attempt = 0; attempt < kSystemServerIdentityWaitAttempts; ++attempt) {
    if (process_descriptor >= 0 &&
        WaitProcessLiveness(process_descriptor, 0) != ProcessLivenessResult::kAlive) {
      return false;
    }
    if (IsSystemServerProcess(pid, expected_start_ticks)) {
      return true;
    }
    if (!SleepFully(kStatusWaitNanoseconds)) {
      return false;
    }
  }
  return false;
}

int OpenStatusDirectory() {
  const int directory = open(kModuleDirectory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  struct stat status {};
  const bool valid = directory >= 0 && fstat(directory, &status) == 0 &&
                     S_ISDIR(status.st_mode) && status.st_uid == 0 && status.st_gid == 0 &&
                     status.st_nlink != 0 && (status.st_mode & 07777) == 0755;
  if (!valid) {
    if (directory >= 0) {
      close(directory);
    }
    return -1;
  }
  return directory;
}

int LockRuntimeStatus(int directory) {
  const int descriptor = openat(directory, kRuntimeStatusLockName,
                                O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  struct stat status {};
  const bool valid = descriptor >= 0 && fstat(descriptor, &status) == 0 &&
                     S_ISREG(status.st_mode) && status.st_uid == 0 && status.st_gid == 0 &&
                     status.st_nlink == 1 && (status.st_mode & 07777) == 0600;
  if (!valid || !AcquireControlLock(descriptor, ControlLockMode::kWait)) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    return -1;
  }
  return descriptor;
}

bool WriteStatusFile(const std::string& body, std::uint32_t server_pid,
                     std::uint64_t server_start_ticks) {
  if (body.empty() || body.size() > kMaximumStatusBytes) {
    return false;
  }
  const int directory = OpenStatusDirectory();
  if (directory < 0) {
    return false;
  }
  const int lock = LockRuntimeStatus(directory);
  if (lock < 0) {
    close(directory);
    return false;
  }
  std::string error;
  const bool written = IsSystemServerProcess(server_pid, server_start_ticks) &&
      WriteRuntimeControlStatusAt(directory, body, server_pid, 0, 0, &error);
  close(lock);
  close(directory);
  return written;
}

#ifdef ZYGVEIL_SERVER_VPN_FEATURE
bool WriteServerVpnStatusFile(const std::string& body, std::uint32_t server_pid,
                              std::uint64_t server_start_ticks) {
  std::string parse_error;
  const auto parsed = ::zygveil::server_vpn::ParseRuntimeStatus(body, &parse_error);
  if (!parsed.has_value() || parsed->system_server_pid != server_pid ||
      parsed->system_server_start_ticks != server_start_ticks) {
    return false;
  }
  const int directory = OpenStatusDirectory();
  if (directory < 0) {
    return false;
  }
  const int lock = openat(directory, kServerVpnStatusLockName,
                          O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  struct stat lock_status {};
  const bool lock_valid = lock >= 0 && fstat(lock, &lock_status) == 0 &&
      S_ISREG(lock_status.st_mode) && lock_status.st_uid == 0 &&
      lock_status.st_gid == 0 && lock_status.st_nlink == 1 &&
      (lock_status.st_mode & 07777) == 0600 &&
      AcquireControlLock(lock, ControlLockMode::kWait);
  if (!lock_valid || !IsSystemServerProcess(server_pid, server_start_ticks)) {
    if (lock >= 0) {
      close(lock);
    }
    close(directory);
    return false;
  }
  const int temporary = openat(
      directory, kServerVpnStatusTemporaryName,
      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
  struct stat temporary_status {};
  bool written = temporary >= 0 && fstat(temporary, &temporary_status) == 0 &&
      S_ISREG(temporary_status.st_mode) && temporary_status.st_uid == 0 &&
      temporary_status.st_gid == 0 && temporary_status.st_nlink == 1 &&
      (temporary_status.st_mode & 07777) == 0600 &&
      WriteFully(temporary, body.data(), body.size()) && fsync(temporary) == 0 &&
      fchmod(temporary, 0644) == 0 && fsync(temporary) == 0;
  if (temporary >= 0) {
    close(temporary);
  }
  written = written &&
      renameat(directory, kServerVpnStatusTemporaryName,
               directory, kServerVpnStatusName) == 0 &&
      fsync(directory) == 0;
  if (!written) {
    unlinkat(directory, kServerVpnStatusTemporaryName, 0);
  }
  close(lock);
  close(directory);
  return written;
}

void HandleServerVpnStatusChannel(int socket, int descriptor) {
  if (!ValidateStatusChannelDescriptorFor(descriptor, kServerVpnStatusMemfdProcTarget)) {
    close(descriptor);
    close(socket);
    return;
  }
  void* mapping = mmap(nullptr, sizeof(SharedStatus), PROT_READ | PROT_WRITE, MAP_SHARED,
                       descriptor, 0);
  close(descriptor);
  if (mapping == MAP_FAILED) {
    close(socket);
    return;
  }
  auto* status = static_cast<SharedStatus*>(mapping);
  if (status->magic != kStatusChannelMagic || status->version != kStatusChannelVersion ||
      status->server_pid == 0 || status->server_start_ticks == 0 ||
      status->initial_length == 0 || status->initial_length > status->initial_body.size()) {
    munmap(mapping, sizeof(SharedStatus));
    close(socket);
    return;
  }
  close(socket);
  const std::string initial(status->initial_body.data(), status->initial_length);
  const bool initial_written =
      WaitForSystemServerProcess(status->server_pid, status->server_start_ticks) &&
      WriteServerVpnStatusFile(initial, status->server_pid, status->server_start_ticks);
  __atomic_store_n(&status->companion_state,
                   initial_written ? kCompanionReady : kCompanionFailed,
                   __ATOMIC_RELEASE);
  if (!initial_written) {
    std::uint32_t expected_claim = kRuntimeActivationPending;
    __atomic_compare_exchange_n(&status->activation_claim, &expected_claim,
                                kRuntimeActivationTimedOut, false, __ATOMIC_ACQ_REL,
                                __ATOMIC_ACQUIRE);
  }
  for (int attempt = 0; attempt < kStatusWaitAttempts; ++attempt) {
    if (__atomic_load_n(&status->final_ready, __ATOMIC_ACQUIRE) != 0) {
      break;
    }
    if (!SleepFully(kStatusWaitNanoseconds)) {
      break;
    }
  }
  if (__atomic_load_n(&status->final_ready, __ATOMIC_ACQUIRE) == 0) {
    std::uint32_t expected_claim = kRuntimeActivationPending;
    if (!__atomic_compare_exchange_n(&status->activation_claim, &expected_claim,
                                     kRuntimeActivationTimedOut, false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE) &&
        expected_claim == kRuntimeActivationCommitted) {
      for (int attempt = 0; attempt < kStatusCommitWaitAttempts; ++attempt) {
        if (__atomic_load_n(&status->final_ready, __ATOMIC_ACQUIRE) != 0) {
          break;
        }
        if (!SleepFully(kStatusWaitNanoseconds)) {
          break;
        }
      }
    }
  }
  if (__atomic_load_n(&status->final_ready, __ATOMIC_ACQUIRE) != 0 &&
      status->final_length > 0 && status->final_length <= status->final_body.size()) {
    WriteServerVpnStatusFile(
        std::string(status->final_body.data(), status->final_length),
        status->server_pid, status->server_start_ticks);
  } else {
    const std::size_t boot_id_length =
        strnlen(status->boot_id.data(), status->boot_id.size());
    const bool committed = __atomic_load_n(&status->activation_claim, __ATOMIC_ACQUIRE) ==
        kRuntimeActivationCommitted;
    const std::string fallback = ServerVpnStatusBody(
        committed ? "arming" : "inactive",
        committed ? "post_server_commit_delayed" : "post_server_timeout", std::nullopt, 0,
        status->server_pid, status->server_start_ticks,
        std::string_view(status->boot_id.data(), boot_id_length));
    WriteServerVpnStatusFile(fallback, status->server_pid, status->server_start_ticks);
  }
  munmap(mapping, sizeof(SharedStatus));
}
#endif

void* InitializeRuntime(void* opaque) {
  std::unique_ptr<InitContext> context(static_cast<InitContext*>(opaque));
  pthread_setname_np(pthread_self(), "ZygVeilHookInit");
  __android_log_print(ANDROID_LOG_INFO, kLogTag, "event=runtime_init_enter");
  const std::uint64_t server_start_ticks =
      context->status == nullptr ? 0 : context->status->server_start_ticks;
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
  const std::uint64_t server_vpn_start_ticks = context->server_vpn_status == nullptr
      ? 0
      : context->server_vpn_status->server_start_ticks;
  const bool server_vpn_status_ready = context->server_vpn_status != nullptr &&
      WaitForStatusCompanion(context->server_vpn_status);
  if (!server_vpn_status_ready && context->server_vpn_status != nullptr) {
    PublishStatus(
        context->server_vpn_status,
        ServerVpnStatusBody(
            "inactive", "status_companion_unavailable", context->server_vpn_config, 0,
            static_cast<std::uint32_t>(getpid()), server_vpn_start_ticks,
            context->boot_id));
    CloseStatusChannel(&context->server_vpn_status);
  }
#endif
  const bool location_status_ready = context->status != nullptr &&
      WaitForStatusCompanion(context->status);
  if (!location_status_ready && context->status != nullptr) {
    PublishStatus(context->status,
                  StatusBody("inactive", "status_companion_unavailable",
                             context->raw_gnss_mode, 0,
                             static_cast<std::uint32_t>(getpid()),
                             context->config_generation, context->boot_id, 0,
                             server_start_ticks));
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "event=runtime_init_failed reason=status_companion_unavailable");
    CloseStatusChannel(&context->status);
  }
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
  if (!location_status_ready && !server_vpn_status_ready) {
    return nullptr;
  }
#else
  if (!location_status_ready) {
    return nullptr;
  }
#endif
  JNIEnv* env = nullptr;
  if (context->vm == nullptr ||
      context->vm->AttachCurrentThread(&env, nullptr) != JNI_OK || env == nullptr) {
    if (location_status_ready) {
      PublishStatus(context->status,
                    StatusBody("inactive", "jni_attach_failed", context->raw_gnss_mode, 0,
                               static_cast<std::uint32_t>(getpid()),
                               context->config_generation, context->boot_id, 0,
                               server_start_ticks));
      CloseStatusChannel(&context->status);
    }
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
    if (server_vpn_status_ready) {
      PublishStatus(
          context->server_vpn_status,
          ServerVpnStatusBody(
              "inactive", "jni_attach_failed", context->server_vpn_config, 0,
              static_cast<std::uint32_t>(getpid()), server_vpn_start_ticks,
              context->boot_id));
      CloseStatusChannel(&context->server_vpn_status);
    }
#endif
    __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                        "event=runtime_init_failed reason=jni_attach_failed");
    return nullptr;
  }
  auto runtime = std::move(context->runtime);
  RuntimeResult result;
  result.reason = "location_not_requested";
  if (location_status_ready) {
    result = runtime->Initialize(env, context->bridge,
                                 &context->status->activation_claim);
    __android_log_print(ANDROID_LOG_INFO, kLogTag,
                        "event=runtime_init_result active=%s reason=%s hook_count=%zu",
                        result.active ? "true" : "false", result.reason.c_str(),
                        result.installed_hooks.size());
    PublishStatus(context->status,
                  StatusBody(result.ready ? "ready" : "inactive", result.reason,
                             context->raw_gnss_mode,
                             result.ready ? result.installed_hooks.size() : 0,
                             static_cast<std::uint32_t>(getpid()),
                             context->config_generation, context->boot_id,
                             result.ready ? context->control_fd : 0,
                             server_start_ticks,
                             result.ready ? context->control_owner_pid : 0,
                             result.ready ? context->control_owner_start_ticks : 0));
    CloseStatusChannel(&context->status);
  }
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
  ::zygveil::server_vpn::RuntimeResult server_vpn_result;
  server_vpn_result.reason = "server_vpn_not_requested";
  if (server_vpn_status_ready && context->server_vpn_runtime != nullptr) {
    server_vpn_result = context->server_vpn_runtime->Initialize(
        env, context->server_vpn_bridge,
        &context->server_vpn_status->activation_claim);
    __android_log_print(
        server_vpn_result.active ? ANDROID_LOG_INFO : ANDROID_LOG_WARN, kLogTag,
        "event=server_vpn_runtime_result state=%s reason=%s hook_count=%zu engine_owner=shared",
        server_vpn_result.active ? "active" : "inactive",
        server_vpn_result.reason.c_str(), server_vpn_result.hook_count);
    PublishStatus(
        context->server_vpn_status,
        ServerVpnStatusBody(
            server_vpn_result.active ? "active" : "inactive",
            server_vpn_result.reason, context->server_vpn_config,
            server_vpn_result.active ? server_vpn_result.hook_count : 0,
            static_cast<std::uint32_t>(getpid()), server_vpn_start_ticks,
            context->boot_id));
    CloseStatusChannel(&context->server_vpn_status);
    if (server_vpn_result.retention_required) {
      g_persistent_server_vpn_runtime = std::move(context->server_vpn_runtime);
    }
  }
  if (result.ready || result.retention_required || server_vpn_result.retention_required) {
#else
  if (result.ready || result.retention_required) {
#endif
    g_persistent_runtime = std::move(runtime);
  }
  context->vm->DetachCurrentThread();
  return nullptr;
}

class LocationModule final : public zygisk::ModuleBase {
 public:
  void onLoad(zygisk::Api* api, JNIEnv* env) override {
    api_ = api;
    env_ = env;
    if (env_ != nullptr) {
      env_->GetJavaVM(&vm_);
    }
  }

  void preAppSpecialize(zygisk::AppSpecializeArgs*) override {
    app_ready_ = false;
    const int directory = api_->getModuleDir();
    std::string runtime_ready;
    std::vector<std::uint8_t> shadowhook_helper;
    std::string error;
    const bool files_ready = directory >= 0 && ReadBootId(&boot_id_) &&
        ReadTextAt(directory, ".guard", 256, &runtime_ready) &&
        ReadAt(directory, "bridge.dex", kMaximumDexBytes, &bridge_dex_) &&
        ReadAt(directory, "libshadowhook_nothing.so", kMaximumShadowhookHelperBytes,
               &shadowhook_helper);
    const bool runtime_inputs_valid =
        files_ready && Trim(runtime_ready) == kRuntimeReadyMarker;
    if (runtime_inputs_valid) {
      application_control_page_ =
          MapApplicationControlPageAt(directory, boot_id_, &config_, &error);
    }
    if (directory >= 0) {
      close(directory);
    }
    if (!runtime_inputs_valid || application_control_page_ == nullptr) {
      const std::string_view reason = !files_ready ? "application_inputs_unavailable"
          : !runtime_inputs_valid ? "runtime_prerequisite_missing"
                         : error.empty() ? "application_control_unavailable"
                                         : std::string_view{error};
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
#ifdef ZYGVEIL_LOCATION_APP_POC
                          "event=pre_app_poc_inactive reason=%.*s",
#else
                          "event=pre_app_delivery_inactive reason=%.*s",
#endif
                          static_cast<int>(reason.size()), reason.data());
      bridge_dex_.clear();
      ReleaseShadowhookHelperBytes();
      api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
      return;
    }
    g_shadowhook_helper = std::move(shadowhook_helper);
    app_ready_ = true;
    __android_log_print(ANDROID_LOG_INFO, kLogTag,
#ifdef ZYGVEIL_LOCATION_APP_POC
                        "event=pre_app_poc_ready scope=global delivery=shared_applied");
#else
                        "event=pre_app_delivery_ready scope=global delivery=shared_applied");
#endif
  }

  void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
    if (!app_ready_) {
      return;
    }
    std::string error;
    auto runtime = std::make_unique<Runtime>(config_, nullptr, -1,
                                             application_control_page_, false,
#ifdef ZYGVEIL_LOCATION_APP_POC
                                             false,
#else
                                             true,
#endif
                                             boot_id_);
    application_control_page_ = nullptr;
    if (env_ == nullptr || !runtime->PrepareArt(env_, &error)) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
#ifdef ZYGVEIL_LOCATION_APP_POC
                          "event=post_app_poc_inactive reason=%s",
#else
                          "event=post_app_delivery_inactive reason=%s",
#endif
                          env_ == nullptr ? "jni_unavailable" : error.c_str());
      ReleaseShadowhookHelperBytes();
      return;
    }
    RuntimeResult result = runtime->InitializeApplication(env_, bridge_dex_);
    __android_log_print(ANDROID_LOG_INFO, kLogTag,
#ifdef ZYGVEIL_LOCATION_APP_POC
                        "event=post_app_poc_result active=%s reason=%s hook_count=%zu",
#else
                        "event=post_app_delivery_result active=%s reason=%s hook_count=%zu",
#endif
                        result.active ? "true" : "false", result.reason.c_str(),
                        result.installed_hooks.size());
    ReleaseShadowhookHelperBytes();
    bridge_dex_.clear();
    bridge_dex_.shrink_to_fit();
    if (result.ready || result.retention_required) {
      g_persistent_runtime = std::move(runtime);
    }
  }

  void preServerSpecialize(zygisk::ServerSpecializeArgs*) override {
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "event=pre_server_enter");
    const bool boot_ready = ReadBootId(&boot_id_);
    if (!boot_ready) {
      boot_id_ = "unavailable";
    }
    if (boot_ready) {
      status_ = OpenStatusChannel(api_, boot_id_, &companion_socket_);
    }
    if (companion_socket_ >= 0) {
      close(companion_socket_);
      companion_socket_ = -1;
    }
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
    if (boot_ready) {
      server_vpn_status_ = OpenServerVpnStatusChannel(
          api_, boot_id_, &server_vpn_companion_socket_);
    }
    if (server_vpn_companion_socket_ >= 0) {
      close(server_vpn_companion_socket_);
      server_vpn_companion_socket_ = -1;
    }
#endif

    const auto publish_location_inactive = [&](std::string_view reason, RawGnssMode mode,
                                                std::uint64_t generation) {
      if (status_ != nullptr) {
        PublishStatus(status_, StatusBody(
            "inactive", reason, mode, 0, static_cast<std::uint32_t>(getpid()),
            generation, boot_id_, 0, status_->server_start_ticks));
        CloseStatusChannel(&status_);
      }
      const std::string_view safe_reason = ValidRuntimeStatusReason(reason)
          ? reason
          : std::string_view{"runtime_reason_redacted"};
      __android_log_print(ANDROID_LOG_WARN, kLogTag,
                          "event=location_feature_inactive reason=%.*s",
                          static_cast<int>(safe_reason.size()), safe_reason.data());
    };
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
    const auto publish_server_vpn_inactive = [&](
        std::string_view reason,
        const std::optional<::zygveil::server_vpn::Config>& parsed_config) {
      if (server_vpn_status_ != nullptr) {
        PublishStatus(
            server_vpn_status_,
            ServerVpnStatusBody(
                "inactive", reason, parsed_config, 0,
                static_cast<std::uint32_t>(getpid()),
                server_vpn_status_->server_start_ticks, boot_id_));
        CloseStatusChannel(&server_vpn_status_);
      }
      const std::string_view safe_reason = ::zygveil::server_vpn::ValidStatusReason(reason)
          ? reason
          : std::string_view{"runtime_reason_redacted"};
      __android_log_print(ANDROID_LOG_WARN, kLogTag,
                          "event=server_vpn_feature_inactive reason=%.*s",
                          static_cast<int>(safe_reason.size()), safe_reason.data());
    };
#endif

    const int directory = api_->getModuleDir();
    if (directory < 0) {
      publish_location_inactive("module_dir_unavailable", RawGnssMode::kBlocked, 0);
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
      publish_server_vpn_inactive("module_dir_unavailable", std::nullopt);
#endif
      api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
      return;
    }

    std::string config_text;
    std::string runtime_ready;
    std::vector<std::uint8_t> shadowhook_helper;
    const bool common_inputs = boot_ready &&
        ReadRootTextAt(directory, ".guard", 256, 0644, &runtime_ready) &&
        ReadRootAt(directory, "libshadowhook_nothing.so",
                   kMaximumShadowhookHelperBytes, 0644, &shadowhook_helper);
    const bool common_guard_valid =
        common_inputs && Trim(runtime_ready) == kRuntimeReadyMarker;

    std::string location_error;
    const bool location_inputs = common_inputs &&
        ReadPrivateTextAt(directory, "config.properties", kMaximumConfigBytes, &config_text) &&
        ReadAt(directory, "bridge.dex", kMaximumDexBytes, &bridge_dex_);
    const auto parsed_location = location_inputs
        ? ParseConfig(config_text, &location_error)
        : std::nullopt;
    if (!common_inputs || !common_guard_valid || !location_inputs ||
        !parsed_location.has_value()) {
      const std::string reason = !boot_ready ? "boot_identity_unavailable"
          : !common_inputs || !location_inputs ? "immutable_input_missing"
          : !common_guard_valid ? "runtime_prerequisite_missing"
          : "config_invalid";
      publish_location_inactive(
          reason,
          parsed_location.has_value() ? parsed_location->raw_gnss_mode
                                      : RawGnssMode::kBlocked,
          parsed_location.has_value() ? parsed_location->config_generation : 0);
      bridge_dex_.clear();
    } else {
      config_ = *parsed_location;
      if (status_ == nullptr) {
        __android_log_print(
            ANDROID_LOG_WARN, kLogTag,
            "event=location_feature_inactive reason=status_channel_unavailable");
        bridge_dex_.clear();
      } else {
        __atomic_store_n(&status_->raw_mode,
                         static_cast<std::uint32_t>(config_.raw_gnss_mode),
                         __ATOMIC_RELEASE);
        __atomic_store_n(&status_->config_generation, config_.config_generation,
                         __ATOMIC_RELEASE);
        std::string control_error;
        control_page_ = CreateControlPage(
            config_, boot_id_, &control_descriptor_, &control_error);
        ControlBrokerReceipt broker_receipt;
        const bool broker_ready = control_page_ != nullptr &&
            RegisterControlBroker(
                api_, control_descriptor_, &broker_receipt, &control_error);
        if (control_descriptor_ >= 0) {
          close(control_descriptor_);
          control_descriptor_ = -1;
        }
        if (!broker_ready) {
          if (control_page_ != nullptr) {
            StoreControlRuntimeState(control_page_, ControlRuntimeState::kInactive);
            munmap(control_page_, sizeof(ControlPage));
            control_page_ = nullptr;
          }
          publish_location_inactive(
              control_error.empty() ? std::string_view{"control_broker_unavailable"}
                                    : std::string_view{control_error},
              config_.raw_gnss_mode, config_.config_generation);
          bridge_dex_.clear();
        } else {
          control_owner_pid_ = broker_receipt.control_owner_pid;
          control_owner_start_ticks_ = broker_receipt.control_owner_start_ticks;
          broker_control_fd_ = broker_receipt.control_fd;
          location_ready_ = true;
        }
      }
    }

#ifdef ZYGVEIL_SERVER_VPN_FEATURE
    std::string server_vpn_config_text;
    std::string server_vpn_error;
    const bool server_vpn_inputs = common_inputs && common_guard_valid &&
        ReadRootTextAt(directory, "server-vpn-config.properties",
                       ::zygveil::server_vpn::kMaximumConfigBytes, 0644,
                       &server_vpn_config_text) &&
        ReadRootAt(directory, "server-vpn-bridge.dex", kMaximumDexBytes, 0644,
                   &server_vpn_bridge_dex_);
    const auto parsed_server_vpn = server_vpn_inputs
        ? ::zygveil::server_vpn::ParseConfig(server_vpn_config_text, &server_vpn_error)
        : std::nullopt;
    if (parsed_server_vpn.has_value() && server_vpn_status_ != nullptr) {
      server_vpn_config_ = *parsed_server_vpn;
      __atomic_store_n(&server_vpn_status_->config_generation,
                       server_vpn_config_->config_generation, __ATOMIC_RELEASE);
      server_vpn_ready_ = true;
    } else {
      server_vpn_bridge_dex_.clear();
      const std::string_view reason = !boot_ready ? "boot_identity_unavailable"
          : !common_inputs ? "immutable_input_missing"
          : !common_guard_valid ? "runtime_prerequisite_missing"
          : !server_vpn_inputs ? "packaged_policy_or_bridge_missing"
          : !parsed_server_vpn.has_value() ?
              (server_vpn_error.empty() ? std::string_view{"config_invalid"}
                                        : std::string_view{server_vpn_error})
          : "status_channel_unavailable";
      publish_server_vpn_inactive(reason, parsed_server_vpn);
    }
    __android_log_print(
        server_vpn_ready_ ? ANDROID_LOG_INFO : ANDROID_LOG_WARN, kLogTag,
        "event=server_vpn_inputs state=%s reason=%s",
        server_vpn_ready_ ? "ready" : "inactive",
        server_vpn_ready_ ? "valid_inputs" : "input_rejected");
#endif
    close(directory);
    ready_ = location_ready_
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
        || server_vpn_ready_
#endif
        ;
    if (!ready_) {
      api_->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
      return;
    }
    g_shadowhook_helper = std::move(shadowhook_helper);
    __android_log_print(ANDROID_LOG_INFO, kLogTag,
                        "event=pre_server_ready location=%s server_vpn=%s engine_owner=shared",
                        location_ready_ ? "ready" : "inactive",
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
                        server_vpn_ready_ ? "ready" : "inactive"
#else
                        "not_built"
#endif
    );
  }

  void postServerSpecialize(const zygisk::ServerSpecializeArgs*) override {
    if (!ready_) {
      return;
    }
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "event=post_server_enter");
    std::string error;
    if (location_ready_ && control_page_ == nullptr) {
      location_ready_ = false;
      if (status_ != nullptr) {
        PublishStatus(
            status_, StatusBody(
                "inactive", "control_page_unavailable", config_.raw_gnss_mode, 0,
                static_cast<std::uint32_t>(getpid()), config_.config_generation,
                boot_id_, 0, status_->server_start_ticks));
        CloseStatusChannel(&status_);
      }
    }
    const int control_fd = location_ready_ ? broker_control_fd_ : 0;
    auto runtime = std::make_unique<Runtime>(config_, control_page_, -1,
                                             nullptr, false, false, boot_id_);
    control_page_ = nullptr;
    application_control_page_ = nullptr;
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "event=post_server_art_prepare_enter");
    if (env_ == nullptr || !runtime->PrepareArt(env_, &error)) {
      const std::string reason = env_ == nullptr ? "post_server_jni_unavailable" : error;
      if (location_ready_ && status_ != nullptr) {
        PublishStatus(status_, StatusBody(
            "inactive", reason, config_.raw_gnss_mode, 0,
            static_cast<std::uint32_t>(getpid()), config_.config_generation,
            boot_id_, 0, status_->server_start_ticks));
        CloseStatusChannel(&status_);
      }
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
      if (server_vpn_ready_ && server_vpn_status_ != nullptr) {
        PublishStatus(
            server_vpn_status_,
            ServerVpnStatusBody(
                "inactive", "shared_hook_host_unavailable", server_vpn_config_, 0,
                static_cast<std::uint32_t>(getpid()),
                server_vpn_status_->server_start_ticks, boot_id_));
        CloseStatusChannel(&server_vpn_status_);
      }
#endif
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                          "event=post_server_inactive reason=%s", reason.c_str());
      ReleaseShadowhookHelperBytes();
      return;
    }
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "event=post_server_art_prepare_ready");
    auto context = std::make_unique<InitContext>();
    context->vm = vm_;
    context->runtime = std::move(runtime);
    if (location_ready_) {
      context->raw_gnss_mode = config_.raw_gnss_mode;
      context->config_generation = config_.config_generation;
      context->control_fd = control_fd;
      context->control_owner_pid = control_owner_pid_;
      context->control_owner_start_ticks = control_owner_start_ticks_;
      context->bridge = std::move(bridge_dex_);
      context->status = status_;
    }
    context->boot_id = boot_id_;
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
    if (server_vpn_ready_ && server_vpn_config_.has_value() &&
        server_vpn_status_ != nullptr) {
      context->server_vpn_config = server_vpn_config_;
      context->server_vpn_bridge = std::move(server_vpn_bridge_dex_);
      context->server_vpn_status = server_vpn_status_;
      context->server_vpn_runtime =
          std::make_unique<::zygveil::server_vpn::Runtime>(
              *server_vpn_config_, context->runtime->HookHost());
      server_vpn_status_ = nullptr;
    }
#endif
    pthread_t thread{};
    const int result = pthread_create(&thread, nullptr, InitializeRuntime, context.get());
    if (result != 0) {
      __android_log_print(ANDROID_LOG_ERROR, kLogTag,
                          "event=post_server_inactive reason=init_thread_failed code=%d", result);
      if (location_ready_ && status_ != nullptr) {
        PublishStatus(status_, StatusBody(
            "inactive", "init_thread_failed", config_.raw_gnss_mode, 0,
            static_cast<std::uint32_t>(getpid()), config_.config_generation,
            boot_id_, 0, status_->server_start_ticks));
        CloseStatusChannel(&status_);
      }
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
      if (context->server_vpn_status != nullptr) {
        PublishStatus(
            context->server_vpn_status,
            ServerVpnStatusBody(
                "inactive", "init_thread_failed", server_vpn_config_, 0,
                static_cast<std::uint32_t>(getpid()),
                context->server_vpn_status->server_start_ticks, boot_id_));
        CloseStatusChannel(&context->server_vpn_status);
      }
#endif
      ReleaseShadowhookHelperBytes();
      return;
    }
    status_ = nullptr;
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
    server_vpn_status_ = nullptr;
#endif
    context.release();
    pthread_detach(thread);
    __android_log_print(ANDROID_LOG_INFO, kLogTag, "event=post_server_thread_started");
  }

 private:
  zygisk::Api* api_ = nullptr;
  JNIEnv* env_ = nullptr;
  JavaVM* vm_ = nullptr;
  Config config_;
  std::string boot_id_;
  std::vector<std::uint8_t> bridge_dex_;
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
  std::optional<::zygveil::server_vpn::Config> server_vpn_config_;
  std::vector<std::uint8_t> server_vpn_bridge_dex_;
  SharedStatus* server_vpn_status_ = nullptr;
  int server_vpn_companion_socket_ = -1;
#endif
  SharedStatus* status_ = nullptr;
  ControlPage* control_page_ = nullptr;
  ControlPage* application_control_page_ = nullptr;
  int control_descriptor_ = -1;
  int broker_control_fd_ = -1;
  std::uint32_t control_owner_pid_ = 0;
  std::uint64_t control_owner_start_ticks_ = 0;
  int companion_socket_ = -1;
  bool ready_ = false;
  bool location_ready_ = false;
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
  bool server_vpn_ready_ = false;
#endif
  bool app_ready_ = false;
};

void HandleStatusChannel(int socket, int descriptor) {
  if (!ValidateStatusChannelDescriptor(descriptor)) {
    close(descriptor);
    close(socket);
    return;
  }
  void* mapping = mmap(nullptr, sizeof(SharedStatus), PROT_READ | PROT_WRITE, MAP_SHARED,
                       descriptor, 0);
  close(descriptor);
  if (mapping == MAP_FAILED) {
    close(socket);
    return;
  }
  auto* status = static_cast<SharedStatus*>(mapping);
  if (status->magic != kStatusChannelMagic || status->version != kStatusChannelVersion ||
      status->server_pid == 0 || status->server_start_ticks == 0 ||
      status->initial_length == 0 || status->initial_length > status->initial_body.size()) {
    munmap(mapping, sizeof(SharedStatus));
    close(socket);
    return;
  }
  close(socket);
  const bool initial_written =
      WaitForSystemServerProcess(status->server_pid, status->server_start_ticks) &&
      WriteStatusFile(std::string(status->initial_body.data(), status->initial_length),
                      status->server_pid, status->server_start_ticks);
  const bool companion_ready = initial_written;
  __atomic_store_n(&status->companion_state,
                   companion_ready ? kCompanionReady : kCompanionFailed,
                   __ATOMIC_RELEASE);
  if (!companion_ready) {
    std::uint32_t expected_claim = kRuntimeActivationPending;
    __atomic_compare_exchange_n(&status->activation_claim, &expected_claim,
                                kRuntimeActivationTimedOut, false, __ATOMIC_ACQ_REL,
                                __ATOMIC_ACQUIRE);
  }
  for (int attempt = 0; attempt < kStatusWaitAttempts; ++attempt) {
    if (__atomic_load_n(&status->final_ready, __ATOMIC_ACQUIRE) != 0) {
      break;
    }
    if (!SleepFully(kStatusWaitNanoseconds)) {
      break;
    }
  }
  if (__atomic_load_n(&status->final_ready, __ATOMIC_ACQUIRE) == 0) {
    std::uint32_t expected_claim = kRuntimeActivationPending;
    if (!__atomic_compare_exchange_n(&status->activation_claim, &expected_claim,
                                     kRuntimeActivationTimedOut, false, __ATOMIC_ACQ_REL,
                                     __ATOMIC_ACQUIRE) &&
        expected_claim == kRuntimeActivationCommitted) {
      for (int attempt = 0; attempt < kStatusCommitWaitAttempts; ++attempt) {
        if (__atomic_load_n(&status->final_ready, __ATOMIC_ACQUIRE) != 0) {
          break;
        }
        if (!SleepFully(kStatusWaitNanoseconds)) {
          break;
        }
      }
    }
  }
  if (__atomic_load_n(&status->final_ready, __ATOMIC_ACQUIRE) != 0 &&
      status->final_length > 0 && status->final_length <= status->final_body.size()) {
    WriteStatusFile(std::string(status->final_body.data(), status->final_length),
                    status->server_pid, status->server_start_ticks);
  } else {
    RawGnssMode mode = RawGnssMode::kBlocked;
    const std::uint32_t raw_mode = __atomic_load_n(&status->raw_mode, __ATOMIC_ACQUIRE);
    if (raw_mode <= static_cast<std::uint32_t>(RawGnssMode::kUnsupported)) {
      mode = static_cast<RawGnssMode>(raw_mode);
    }
    const std::size_t boot_id_length = strnlen(status->boot_id.data(), status->boot_id.size());
    const std::string_view boot_id(status->boot_id.data(), boot_id_length);
    const bool committed = __atomic_load_n(&status->activation_claim, __ATOMIC_ACQUIRE) ==
        kRuntimeActivationCommitted;
    WriteStatusFile(
        StatusBody(committed ? "arming" : "inactive",
                   committed ? "post_server_commit_delayed" : "post_server_timeout", mode, 0,
                   status->server_pid,
                   __atomic_load_n(&status->config_generation, __ATOMIC_ACQUIRE), boot_id, 0,
                   status->server_start_ticks),
        status->server_pid, status->server_start_ticks);
  }
  munmap(mapping, sizeof(SharedStatus));
}

ControlPage* CreateApplicationControlPage(const ControlPage& source, Config* armed,
                                          std::string* error) {
  ControlReason reason = ControlReason::kNone;
  if (ReadAppliedControlConfig(source, 0, armed, &reason) != ControlReadResult::kReady) {
    *error = "application_control_initial_config_invalid";
    return nullptr;
  }
  const int directory = OpenStatusDirectory();
  if (directory < 0) {
    *error = "application_control_directory_unavailable";
    return nullptr;
  }
  int descriptor = openat(directory, kApplicationControlName,
                          O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  struct stat status {};
  const bool identity_valid = descriptor >= 0 && fstat(descriptor, &status) == 0 &&
      S_ISREG(status.st_mode) && status.st_uid == 0 && status.st_gid == 0 &&
      status.st_nlink == 1 && (status.st_mode & 07777) == 0600;
  if (!identity_valid || ftruncate(descriptor, sizeof(ControlPage)) != 0 ||
      !ValidateApplicationControlDescriptor(descriptor, O_RDWR, error)) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    close(directory);
    if (error->empty()) {
      *error = "application_control_file_prepare_failed";
    }
    return nullptr;
  }
  void* mapping = mmap(nullptr, sizeof(ControlPage), PROT_READ | PROT_WRITE, MAP_SHARED,
                       descriptor, 0);
  close(descriptor);
  close(directory);
  if (mapping == MAP_FAILED) {
    *error = "application_control_file_map_failed";
    return nullptr;
  }
  auto* page = static_cast<ControlPage*>(mapping);
  const std::string_view boot_id(source.header.boot_id.data());
  if (!InitializeControlPage(page, *armed, source.header.server_pid, boot_id, error) ||
      msync(page, sizeof(ControlPage), MS_SYNC) != 0) {
    if (error->empty()) {
      *error = "application_control_file_sync_failed";
    }
    munmap(page, sizeof(ControlPage));
    return nullptr;
  }
  return page;
}

void MonitorApplicationControlPage(const ControlPage* source, ControlPage* delivery,
                                   const Config& armed, std::uint32_t server_pid,
                                   std::uint64_t server_start_ticks,
                                   int process_descriptor) {
  bool healthy =
      WaitForSystemServerProcess(server_pid, server_start_ticks, process_descriptor);
  while (healthy &&
         WaitProcessLiveness(process_descriptor, 0) == ProcessLivenessResult::kAlive) {
    const ControlRuntimeState state = LoadControlRuntimeState(*source);
    if (state == ControlRuntimeState::kInactive ||
        state == ControlRuntimeState::kUninitialized) {
      break;
    }
    if (state == ControlRuntimeState::kWaiting) {
      if (LoadControlRuntimeState(*delivery) == ControlRuntimeState::kArming) {
        StoreControlRuntimeState(delivery, ControlRuntimeState::kWaiting);
      }
      Config candidate;
      ControlReason reason = ControlReason::kNone;
      const ControlReadResult result = ReadPublishedControlConfig(
          *source, LoadPublishedGeneration(*delivery), &candidate, &reason);
      if (result == ControlReadResult::kReady && candidate.enabled) {
        std::string error;
        if (!PublishControlConfig(delivery, armed, candidate, &error)) {
          healthy = false;
          break;
        }
      } else if (result != ControlReadResult::kNoUpdate &&
                 result != ControlReadResult::kRetry) {
        healthy = false;
        break;
      }
    }
    if (state == ControlRuntimeState::kActive) {
      Config candidate;
      ControlReason reason = ControlReason::kNone;
      const ControlReadResult result = ReadAppliedControlConfig(
          *source, LoadAppliedGeneration(*delivery), &candidate, &reason);
      if (result == ControlReadResult::kReady) {
        std::string error;
        const std::uint64_t delivery_published = LoadPublishedGeneration(*delivery);
        if (delivery_published < candidate.config_generation &&
            !PublishControlConfig(delivery, armed, candidate, &error)) {
          healthy = false;
          break;
        }
        if (LoadPublishedGeneration(*delivery) != candidate.config_generation) {
          healthy = false;
          break;
        }
        PublishControlAck(delivery, candidate.config_generation,
                          ControlAckState::kApplied, ControlReason::kNone);
        StoreControlRuntimeState(delivery, ControlRuntimeState::kActive);
      } else if (result == ControlReadResult::kNoUpdate && armed.enabled &&
                 LoadAppliedGeneration(*delivery) == LoadAppliedGeneration(*source)) {
        StoreControlRuntimeState(delivery, ControlRuntimeState::kActive);
      } else if (result != ControlReadResult::kNoUpdate &&
                 result != ControlReadResult::kRetry) {
        healthy = false;
        break;
      }
    }
    const ProcessLivenessResult liveness =
        WaitProcessLiveness(process_descriptor, static_cast<int>(kStatusWaitNanoseconds / 1000000));
    if (liveness == ProcessLivenessResult::kExited) {
      break;
    }
    if (liveness != ProcessLivenessResult::kAlive) {
      healthy = false;
    }
  }
  StoreControlRuntimeState(delivery, ControlRuntimeState::kInactive);
  msync(delivery, sizeof(ControlPage), MS_ASYNC);
  munmap(delivery, sizeof(ControlPage));
  munmap(const_cast<ControlPage*>(source), sizeof(ControlPage));
  pthread_mutex_lock(&g_control_broker_mutex);
  if (g_control_broker.server_pid == server_pid &&
      g_control_broker.server_start_ticks == server_start_ticks) {
    if (g_control_broker.descriptor >= 0) {
      close(g_control_broker.descriptor);
    }
    if (g_control_broker.process_descriptor >= 0) {
      close(g_control_broker.process_descriptor);
    }
    g_control_broker = {};
    pthread_cond_broadcast(&g_control_broker_condition);
  }
  pthread_mutex_unlock(&g_control_broker_mutex);
}

void HandleControlRegistration(int socket, int descriptor) {
  std::string error;
  if (!ValidateControlMemfdDescriptor(descriptor, 0, 0, &error) ||
      !ValidateControlMemfdTarget(descriptor)) {
    if (descriptor >= 0) {
      close(descriptor);
    }
    close(socket);
    return;
  }
  void* mapping = mmap(nullptr, sizeof(ControlPage), PROT_READ, MAP_SHARED, descriptor, 0);
  if (mapping == MAP_FAILED) {
    close(descriptor);
    close(socket);
    return;
  }
  const auto* page = static_cast<const ControlPage*>(mapping);
  const std::uint32_t server_pid = page->header.server_pid;
  const std::uint64_t config_generation = page->header.boot_config_generation;
  const std::size_t boot_id_length =
      strnlen(page->header.boot_id.data(), kControlBootIdBytes);
  std::uint64_t server_start_ticks = 0;
  const bool page_valid = boot_id_length == kBootIdLength &&
      ValidateControlPage(*page, &error) &&
      LoadControlRuntimeState(*page) == ControlRuntimeState::kArming &&
      ReadProcessStartTicks(server_pid, &server_start_ticks);
  int process_descriptor = page_valid
      ? OpenProcessLivenessHandle(static_cast<pid_t>(server_pid), server_start_ticks, &error)
      : -1;
  std::array<char, kBootIdLength + 1> boot_id{};
  if (page_valid) {
    std::memcpy(boot_id.data(), page->header.boot_id.data(), kBootIdLength);
  }
  if (!page_valid || process_descriptor < 0) {
    if (process_descriptor >= 0) {
      close(process_descriptor);
    }
    munmap(mapping, sizeof(ControlPage));
    close(descriptor);
    close(socket);
    return;
  }

  ControlBrokerReceipt receipt;
  Config application_armed;
  ControlPage* application_page = nullptr;
  std::uint64_t owner_start_ticks = 0;
  int registered_process_descriptor = -1;
  pthread_mutex_lock(&g_control_broker_mutex);
  if (g_control_broker.descriptor >= 0 &&
      (g_control_broker.process_descriptor < 0 ||
       WaitProcessLiveness(g_control_broker.process_descriptor, 0) !=
           ProcessLivenessResult::kAlive)) {
    timespec deadline{};
    if (clock_gettime(CLOCK_REALTIME, &deadline) == 0) {
      deadline.tv_sec += kControlReplacementWaitSeconds;
      while (g_control_broker.descriptor >= 0 &&
             pthread_cond_timedwait(&g_control_broker_condition,
                                    &g_control_broker_mutex, &deadline) == 0) {
      }
    }
  }
  if (g_control_broker.descriptor < 0 &&
      ReadProcessStartTicks(static_cast<std::uint32_t>(getpid()), &owner_start_ticks)) {
    application_page = CreateApplicationControlPage(*page, &application_armed, &error);
    if (application_page != nullptr) {
      g_control_broker.descriptor = descriptor;
      g_control_broker.process_descriptor = process_descriptor;
      g_control_broker.server_pid = server_pid;
      g_control_broker.server_start_ticks = server_start_ticks;
      g_control_broker.config_generation = config_generation;
      g_control_broker.boot_id = boot_id;
      registered_process_descriptor = process_descriptor;
      receipt.accepted = 1;
      receipt.control_owner_pid = static_cast<std::uint32_t>(getpid());
      receipt.control_owner_start_ticks = owner_start_ticks;
      receipt.control_fd = descriptor;
      descriptor = -1;
      process_descriptor = -1;
    }
  }
  pthread_mutex_unlock(&g_control_broker_mutex);
  WriteFully(socket, &receipt, sizeof(receipt));
  const bool registered = receipt.accepted == 1;
  if (descriptor >= 0) {
    close(descriptor);
  }
  if (process_descriptor >= 0) {
    close(process_descriptor);
  }
  close(socket);
  if (registered) {
    MonitorApplicationControlPage(page, application_page, application_armed,
                                  server_pid, server_start_ticks,
                                  registered_process_descriptor);
  } else {
    if (application_page != nullptr) {
      munmap(application_page, sizeof(ControlPage));
    }
    munmap(mapping, sizeof(ControlPage));
  }
}

void CompanionHandler(int socket) {
  std::string error;
  auto message = ReceiveChannelMessage(socket, kControlHandshakeTimeoutMs, &error);
  if (!message.has_value()) {
    close(socket);
    return;
  }
  if (message->token == kStatusDescriptorToken && message->descriptor >= 0) {
    HandleStatusChannel(socket, message->descriptor);
    return;
  }
#ifdef ZYGVEIL_SERVER_VPN_FEATURE
  if (message->token == kServerVpnStatusDescriptorToken && message->descriptor >= 0) {
    HandleServerVpnStatusChannel(socket, message->descriptor);
    return;
  }
#endif
  if (message->token == kControlDescriptorToken && message->descriptor >= 0) {
    HandleControlRegistration(socket, message->descriptor);
    return;
  }
  if (message->descriptor >= 0) {
    close(message->descriptor);
  }
  close(socket);
}

}  // namespace
}  // namespace zygveil::location

REGISTER_ZYGISK_MODULE(zygveil::location::LocationModule)
REGISTER_ZYGISK_COMPANION(zygveil::location::CompanionHandler)
