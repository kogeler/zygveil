// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "control_protocol.hpp"

#include <array>
#include <atomic>
#include <bit>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

std::atomic<int> tests = 0;

void Check(bool condition, const char* name) {
  tests.fetch_add(1, std::memory_order_relaxed);
  if (!condition) {
    std::cerr << "FAIL " << name << '\n';
    std::exit(1);
  }
}

zygveil::location::Config TestConfig() {
  zygveil::location::Config config;
  config.enabled = true;
  config.center_latitude_deg = 12.5;
  config.center_longitude_deg = -45.25;
  config.config_generation = 1;
  config.random_seed = 123456789;
  return config;
}

}  // namespace

int main() {
  using namespace zygveil::location;

  const char checksum_vector[] = "123456789";
  Check(Crc32c(checksum_vector, std::strlen(checksum_vector)) == 0xe3069283U,
        "CRC32C standard vector");
  Check(sizeof(ControlPage) == 4096, "page size fixed");
  Check(alignof(ControlPage) == 64, "page alignment fixed");

  int sockets[2] = {-1, -1};
  Check(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == 0,
        "companion socket pair opens");
  std::array<char, 64> descriptor_template{};
  std::strcpy(descriptor_template.data(), "/tmp/location-page-fd-XXXXXX");
  const int sent_descriptor = mkstemp(descriptor_template.data());
  Check(sent_descriptor >= 0, "companion descriptor fixture opens");
  struct stat sent_status {};
  Check(fstat(sent_descriptor, &sent_status) == 0, "companion descriptor fixture stats");
  Check(SendChannelDescriptor(sockets[0], sent_descriptor, 'P'),
        "companion descriptor sends");
  const int received_descriptor = ReceiveChannelDescriptor(sockets[1], 'P', 1000);
  struct stat received_status {};
  Check(received_descriptor >= 0 && fstat(received_descriptor, &received_status) == 0 &&
            received_status.st_dev == sent_status.st_dev &&
            received_status.st_ino == sent_status.st_ino,
        "companion descriptor identity survives transfer");
  Check((fcntl(received_descriptor, F_GETFD) & FD_CLOEXEC) != 0,
        "companion descriptor is close-on-exec");
  Check(SendChannelDescriptor(sockets[0], sent_descriptor, 'X'),
        "wrong-token descriptor sends");
  Check(ReceiveChannelDescriptor(sockets[1], 'P', 1000) < 0,
        "wrong-token descriptor rejected");
  const char descriptor_free_token = 'P';
  Check(send(sockets[0], &descriptor_free_token, sizeof(descriptor_free_token), MSG_NOSIGNAL) ==
            static_cast<ssize_t>(sizeof(descriptor_free_token)),
        "descriptor-free token sends");
  Check(ReceiveChannelDescriptor(sockets[1], 'P', 1000) < 0,
        "descriptor-free token rejected");
  Check(SendChannelToken(sockets[0], 'A'), "plain companion token sends");
  const auto plain_message = ReceiveChannelMessage(sockets[1], 1000);
  Check(plain_message.has_value() && plain_message->token == 'A' &&
            plain_message->descriptor < 0,
        "plain companion message receives atomically");
  Check(SendChannelDescriptor(sockets[0], sent_descriptor, 'R'),
        "routed descriptor message sends");
  const auto routed_message = ReceiveChannelMessage(sockets[1], 1000);
  Check(routed_message.has_value() && routed_message->token == 'R' &&
            routed_message->descriptor >= 0,
        "routed descriptor token and ancillary receive atomically");
  close(routed_message->descriptor);
  Check(SendChannelToken(sockets[0], 'X'), "wrong plain companion token sends");
  Check(!ReceiveChannelToken(sockets[1], 'A', 1000),
        "wrong plain companion token rejected");
  close(received_descriptor);
  close(sent_descriptor);
  close(sockets[0]);
  close(sockets[1]);
  unlink(descriptor_template.data());

  int byte_sockets[2] = {-1, -1};
  Check(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, byte_sockets) == 0,
        "bounded byte channel opens");
  const std::array<std::byte, 8> sent_bytes = {
      std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
      std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8},
  };
  std::array<std::byte, 8> received_bytes{};
  std::thread fragmented_sender([&]() {
    Check(send(byte_sockets[0], sent_bytes.data(), 3, MSG_NOSIGNAL) == 3,
          "bounded byte channel first fragment sends");
    usleep(5000);
    Check(send(byte_sockets[0], sent_bytes.data() + 3, sent_bytes.size() - 3,
               MSG_NOSIGNAL) == static_cast<ssize_t>(sent_bytes.size() - 3),
          "bounded byte channel second fragment sends");
  });
  std::string channel_error;
  Check(ReceiveChannelBytes(byte_sockets[1], received_bytes.data(), received_bytes.size(),
                            1000, &channel_error) &&
            received_bytes == sent_bytes,
        "bounded byte channel assembles fragmented receipt");
  fragmented_sender.join();
  channel_error.clear();
  std::byte timeout_byte{};
  Check(!ReceiveChannelBytes(byte_sockets[1], &timeout_byte, 1, 20, &channel_error) &&
            channel_error == "channel_read_timeout",
        "bounded byte channel times out without receipt");
  Check(!ReceiveChannelBytes(-1, &timeout_byte, 1, 20, &channel_error),
        "bounded byte channel rejects invalid descriptor");
  close(byte_sockets[0]);
  close(byte_sockets[1]);

  const int control_descriptor =
      memfd_create(kControlMemfdName.data(), MFD_CLOEXEC | MFD_ALLOW_SEALING);
  Check(control_descriptor >= 0 && ftruncate(control_descriptor, sizeof(ControlPage)) == 0 &&
            fcntl(control_descriptor, F_ADD_SEALS, kControlMemfdSeals) == 0,
        "sealed control memfd fixture created");
  std::string memfd_error;
  Check(ValidateControlMemfdDescriptor(control_descriptor, geteuid(), getegid(), &memfd_error),
        "sealed control memfd validates");
  std::array<char, 64> memfd_link{};
  const std::string memfd_path = "/proc/self/fd/" + std::to_string(control_descriptor);
  const ssize_t memfd_link_size =
      readlink(memfd_path.c_str(), memfd_link.data(), memfd_link.size() - 1);
  Check(memfd_link_size == static_cast<ssize_t>(kControlMemfdProcTarget.size()) &&
            std::string_view(memfd_link.data(), static_cast<std::size_t>(memfd_link_size)) ==
                kControlMemfdProcTarget,
        "sealed control memfd has fixed proc target");
  const int read_only_descriptor = open(memfd_path.c_str(), O_RDONLY | O_CLOEXEC);
  Check(read_only_descriptor >= 0 &&
            ValidateControlMemfdDescriptor(read_only_descriptor, geteuid(), getegid(),
                                            &memfd_error, O_RDONLY),
        "sealed control memfd validates after read-only proc reopen");
  Check(!ValidateControlMemfdDescriptor(read_only_descriptor, geteuid(), getegid(),
                                        &memfd_error),
        "read-only control memfd rejected by writable validator");
  const int unsealed_descriptor =
      memfd_create(kControlMemfdName.data(), MFD_CLOEXEC | MFD_ALLOW_SEALING);
  Check(unsealed_descriptor >= 0 && ftruncate(unsealed_descriptor, sizeof(ControlPage)) == 0 &&
            !ValidateControlMemfdDescriptor(unsealed_descriptor, geteuid(), getegid(),
                                            &memfd_error),
        "unsealed control memfd rejected");
  const int wrong_mode_descriptor =
      memfd_create(kControlMemfdName.data(), MFD_CLOEXEC | MFD_ALLOW_SEALING);
  Check(wrong_mode_descriptor >= 0 &&
            ftruncate(wrong_mode_descriptor, sizeof(ControlPage)) == 0 &&
            fcntl(wrong_mode_descriptor, F_ADD_SEALS, kControlMemfdSeals) == 0 &&
            fchmod(wrong_mode_descriptor, 0600) == 0 &&
            !ValidateControlMemfdDescriptor(wrong_mode_descriptor, geteuid(), getegid(),
                                            &memfd_error),
        "non-kernel control memfd mode rejected");
  close(wrong_mode_descriptor);
  close(unsealed_descriptor);
  close(read_only_descriptor);
  close(control_descriptor);

  Config armed = TestConfig();
  WireConfig wire = EncodeConfig(armed);
  std::string error;
  const auto decoded = DecodeConfig(wire, &error);
  Check(decoded.has_value(), "wire round trip decodes");
  Check(decoded->center_latitude_deg == armed.center_latitude_deg,
        "wire latitude round trip");
  Check(decoded->random_seed == armed.random_seed, "wire seed round trip");
  const std::uint64_t boot_digest = BootFieldsDigest(wire);
  Check(boot_digest != 0, "boot digest nonzero");
  wire.center_latitude_deg += 1.0;
  Check(BootFieldsDigest(wire) == boot_digest, "live field excluded from boot digest");
  wire.enabled = 0;
  Check(BootFieldsDigest(wire) == boot_digest, "one-way activation excluded from boot digest");
  wire.enabled = 1;
  wire.speed_max_mps += 0.1;
  Check(BootFieldsDigest(wire) != boot_digest, "boot field included in digest");

  ControlPage page{};
  constexpr std::string_view boot_id = "11111111-2222-3333-4444-555555555555";
  Check(InitializeControlPage(&page, armed, 4242, boot_id, &error), "page initializes");
  Check(ValidateControlPage(page, &error), "initialized page validates");
  Check(ValidateControlIdentity(page, 4242, boot_id, 1, boot_digest, &error),
        "page identity validates");
  Check(!ValidateControlIdentity(page, 4243, boot_id, 1, boot_digest, &error),
        "wrong PID rejected");
  Check(LoadControlRuntimeState(page) == ControlRuntimeState::kArming,
        "page starts arming");
  StoreControlRuntimeState(&page, ControlRuntimeState::kActive);
  Check(LoadControlRuntimeState(page) == ControlRuntimeState::kActive,
        "page becomes active");
  Check(LoadPublishedGeneration(page) == 1, "boot generation published");
  Check(LoadAppliedGeneration(page) == 1, "boot generation applied");
  ControlAck acknowledgement = ReadControlAck(page);
  Check(acknowledgement.generation == 1 && acknowledgement.state == ControlAckState::kApplied,
        "boot generation acknowledged");

  Config next = armed;
  next.config_generation = 2;
  next.center_latitude_deg = -33.75;
  next.center_longitude_deg = 179.5;
  next.altitude_ellipsoid_m = 90.0;
  next.altitude_msl_m = 55.0;
  Check(PublishControlConfig(&page, armed, next, &error), "valid config publishes");
  acknowledgement = ReadControlAck(page);
  Check(acknowledgement.generation == 2 &&
            acknowledgement.state == ControlAckState::kPending,
        "new generation pending");
  Check(LoadAppliedGeneration(page) == 1, "pending retains prior applied generation");
  Config observed;
  ControlReason reason = ControlReason::kInternalError;
  Check(ReadAppliedControlConfig(page, 1, &observed, &reason) ==
            ControlReadResult::kNoUpdate,
        "pending generation remains invisible to applied readers");
  Check(ReadAppliedControlConfig(page, 0, &observed, &reason) == ControlReadResult::kReady &&
            observed.config_generation == 1,
        "new applied reader retains boot generation while update is pending");
  Check(ReadPublishedControlConfig(page, 1, &observed, &reason) == ControlReadResult::kReady,
        "new generation reads");
  Check(observed.config_generation == 2 && observed.center_latitude_deg == -33.75 &&
            observed.altitude_msl_m == 55.0,
        "complete live fields read");
  PublishControlAck(&page, 2, ControlAckState::kApplied, ControlReason::kNone);
  acknowledgement = ReadControlAck(page);
  Check(acknowledgement.generation == 2 && acknowledgement.state == ControlAckState::kApplied,
        "runtime acknowledgement publishes");
  Check(LoadAppliedGeneration(page) == 2, "applied generation advances on acknowledgement");
  Check(ReadAppliedControlConfig(page, 1, &observed, &reason) == ControlReadResult::kReady &&
            observed.config_generation == 2 && observed.center_latitude_deg == -33.75,
        "applied reader switches to acknowledged complete generation");
  Check(ReadPublishedControlConfig(page, 2, &observed, &reason) ==
            ControlReadResult::kNoUpdate,
        "applied generation has no update");

  Config waiting = armed;
  waiting.enabled = false;
  ControlPage waiting_page{};
  Check(InitializeControlPage(&waiting_page, waiting, 4242, boot_id, &error),
        "waiting page initializes");
  StoreControlRuntimeState(&waiting_page, ControlRuntimeState::kWaiting);
  Config first = waiting;
  first.enabled = true;
  first.config_generation = 2;
  first.center_latitude_deg = 45.0;
  Check(PublishControlConfig(&waiting_page, waiting, first, &error),
        "first enabled generation publishes while waiting");
  first.enabled = false;
  first.config_generation = 3;
  Check(!PublishControlConfig(&waiting_page, waiting, first, &error) &&
            error == "activation_required",
        "waiting publication cannot remain disabled");

  Config stale = next;
  Check(!PublishControlConfig(&page, armed, stale, &error) && error == "stale_generation",
        "stale publication rejected");
  Config boot_change = next;
  boot_change.config_generation = 3;
  boot_change.speed_max_mps += 0.1;
  Check(!PublishControlConfig(&page, armed, boot_change, &error) &&
            error == "boot_field_mismatch",
        "boot field change rejected");
  Config invalid = next;
  invalid.config_generation = 3;
  invalid.center_longitude_deg = std::numeric_limits<double>::quiet_NaN();
  Check(!PublishControlConfig(&page, armed, invalid, &error), "non-finite update rejected");
  invalid = next;
  invalid.config_generation = kMaximumControlGeneration + 1;
  Check(!PublishControlConfig(&page, armed, invalid, &error), "generation wrap rejected");

  ControlPage interrupted = page;
  Config interrupted_config = next;
  interrupted_config.config_generation = 3;
  ControlSlot partial{};
  partial.generation = 3;
  partial.payload_size = sizeof(WireConfig);
  partial.payload = EncodeConfig(interrupted_config);
  interrupted.slots[1] = std::bit_cast<ControlSlotStorage>(partial);
  Check(LoadPublishedGeneration(interrupted) == 2, "partial slot stays unpublished");
  Check(ReadPublishedControlConfig(interrupted, 2, &observed, &reason) ==
            ControlReadResult::kNoUpdate,
        "partial slot ignored");

  ControlPage corrupt = page;
  Config corrupt_config = next;
  corrupt_config.config_generation = 3;
  Check(PublishControlConfig(&corrupt, armed, corrupt_config, &error),
        "corruption fixture publishes");
  auto* corrupt_slot = reinterpret_cast<unsigned char*>(&corrupt.slots[1]);
  corrupt_slot[offsetof(ControlSlot, checksum)] ^= 1U;
  Check(ReadPublishedControlConfig(corrupt, 2, &observed, &reason) ==
            ControlReadResult::kInvalid &&
            reason == ControlReason::kChecksumMismatch,
        "checksum corruption rejected");
  Check(ReadAppliedControlConfig(corrupt, 2, &observed, &reason) ==
            ControlReadResult::kNoUpdate,
        "corrupt pending generation remains invisible to applied readers");
  PublishControlAck(&corrupt, 3, ControlAckState::kApplied, ControlReason::kNone);
  Check(ReadAppliedControlConfig(corrupt, 2, &observed, &reason) ==
            ControlReadResult::kInvalid &&
            reason == ControlReason::kChecksumMismatch,
        "corrupt applied generation is rejected");
  corrupt.header.applied_generation = 4;
  Check(ReadAppliedControlConfig(corrupt, 2, &observed, &reason) ==
            ControlReadResult::kInvalid &&
            reason == ControlReason::kInvalidSlot,
        "applied generation ahead of publication is rejected");
  corrupt.header.magic = 0;
  Check(!ValidateControlPage(corrupt, &error), "corrupt page rejected");
  Check(InitializeControlPage(&corrupt, armed, 4242, boot_id, &error) &&
            ValidateControlPage(corrupt, &error),
        "corrupt page recreated");

  ControlPage concurrent{};
  Check(InitializeControlPage(&concurrent, armed, 4242, boot_id, &error),
        "concurrent page initializes");
  StoreControlRuntimeState(&concurrent, ControlRuntimeState::kActive);
  constexpr std::uint64_t final_generation = 2000;
  std::atomic<bool> publisher_done = false;
  std::atomic<bool> concurrency_failed = false;
  std::array<std::uint64_t, 4> reader_observations{};
  std::vector<std::thread> readers;
  for (int reader = 0; reader < 4; ++reader) {
    readers.emplace_back([&, reader]() {
      std::uint64_t applied = 1;
      while (!publisher_done.load(std::memory_order_acquire) ||
             applied < LoadPublishedGeneration(concurrent)) {
        Config value;
        ControlReason read_reason = ControlReason::kNone;
        const auto result =
            ReadPublishedControlConfig(concurrent, applied, &value, &read_reason);
        if (result == ControlReadResult::kReady) {
          if (value.config_generation <= applied ||
              BootFieldsDigest(EncodeConfig(value)) != boot_digest ||
              !std::isfinite(value.center_latitude_deg)) {
            concurrency_failed.store(true, std::memory_order_release);
            return;
          }
          applied = value.config_generation;
          ++reader_observations[reader];
        } else if (result == ControlReadResult::kInvalid ||
                   result == ControlReadResult::kStale) {
          concurrency_failed.store(true, std::memory_order_release);
          return;
        }
      }
    });
  }
  std::thread publisher([&]() {
    Config value = armed;
    for (std::uint64_t generation = 2; generation <= final_generation; ++generation) {
      value.config_generation = generation;
      value.center_latitude_deg = -80.0 + static_cast<double>(generation % 1600) / 10.0;
      value.center_longitude_deg = -179.0 + static_cast<double>(generation % 3580) / 10.0;
      std::string publish_error;
      if (!PublishControlConfig(&concurrent, armed, value, &publish_error)) {
        concurrency_failed.store(true, std::memory_order_release);
        break;
      }
      PublishControlAck(&concurrent, generation, ControlAckState::kApplied,
                        ControlReason::kNone);
    }
    publisher_done.store(true, std::memory_order_release);
  });
  publisher.join();
  for (auto& reader : readers) {
    reader.join();
  }
  Check(!concurrency_failed.load(std::memory_order_acquire),
        "concurrent readers never observe invalid slot");
  for (const auto observations : reader_observations) {
    Check(observations > 0, "concurrent reader observes a valid update");
  }
  Check(LoadPublishedGeneration(concurrent) == final_generation,
        "concurrent final generation published");
  Check(ReadPublishedControlConfig(concurrent, final_generation - 1, &observed, &reason) ==
            ControlReadResult::kReady &&
            observed.config_generation == final_generation,
        "concurrent final payload readable");

  StoreControlRuntimeState(&concurrent, ControlRuntimeState::kInactive);
  Config inactive_update = observed;
  inactive_update.config_generation++;
  Check(!PublishControlConfig(&concurrent, armed, inactive_update, &error) &&
            error == "runtime_inactive",
        "inactive runtime rejects publication");

  std::cout << "schema_version=1\nstatus=PASS\ntests="
            << tests.load(std::memory_order_relaxed)
            << "\ncategories=layout,crc,identity,channel,publication,ack,stale,corrupt,"
               "interrupted,concurrency,recovery\n";
  return 0;
}
