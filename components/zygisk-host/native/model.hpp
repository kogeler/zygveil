// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace zygveil::location {

inline constexpr double kMaximumJitterMeters = 10000.0;
inline constexpr double kMaximumCorrelationTimeSeconds = 86400.0;
inline constexpr double kMaximumSpeedMetersPerSecond = 1000.0;
inline constexpr std::uint64_t kMaximumConfigGeneration = UINT64_MAX >> 2U;

enum class RawGnssMode { kBlocked, kPassthrough, kUnsupported };

struct Config {
  int schema_version = 1;
  bool enabled = false;
  RawGnssMode raw_gnss_mode = RawGnssMode::kBlocked;
  double center_latitude_deg = 0.0;
  double center_longitude_deg = 0.0;
  double altitude_ellipsoid_m = 35.0;
  double altitude_msl_m = 5.0;
  double horizontal_jitter_sigma_m = 1.2;
  double horizontal_jitter_radius_m = 4.0;
  double horizontal_correlation_time_s = 40.0;
  double vertical_jitter_sigma_m = 1.5;
  double accuracy_correlation_time_s = 30.0;
  double speed_deadband_mps = 0.04;
  double speed_max_mps = 0.35;
  double bearing_min_speed_mps = 0.2;
  std::uint64_t random_seed = 1;
  std::uint64_t config_generation = 1;
};

struct Sample {
  std::uint64_t config_generation = 0;
  std::int64_t wall_time_ms = 0;
  std::int64_t elapsed_realtime_ns = 0;
  double latitude_deg = 0.0;
  double longitude_deg = 0.0;
  double east_m = 0.0;
  double north_m = 0.0;
  double altitude_ellipsoid_m = 0.0;
  double altitude_msl_m = 0.0;
  double horizontal_accuracy_m = 0.0;
  double vertical_accuracy_m = 0.0;
  double msl_altitude_accuracy_m = 0.0;
  double speed_mps = 0.0;
  double speed_accuracy_mps = 0.0;
  bool has_bearing = false;
  double bearing_deg = 0.0;
  double bearing_accuracy_deg = 0.0;
};

struct ModelUpdate {
  std::string_view provider;
  std::int64_t wall_time_ms = 0;
  std::int64_t elapsed_realtime_ns = 0;
};

struct Satellite {
  int svid = 0;
  int constellation = 1;
  double carrier_frequency_hz = 1575420000.0;
  double azimuth_deg = 0.0;
  double elevation_deg = 0.0;
  double cn0_db_hz = 0.0;
  double baseband_cn0_db_hz = 0.0;
  bool has_ephemeris = true;
  bool has_almanac = true;
  bool used_in_fix = false;
};

struct ModelSnapshot {
  Sample sample;
  std::vector<Satellite> satellites;
};

struct ActivationInputs {
  bool guard_valid = false;
  bool bridge_ready = false;
  bool location_hook = false;
  bool status_hook = false;
  bool nmea_hook = false;
  bool measurement_hook = false;
  bool navigation_hook = false;
};

struct ActivationDecision {
  bool active = false;
  std::string reason;
};

std::optional<Config> ParseConfig(std::string_view text, std::string* error);
bool ValidateConfig(const Config& config, std::string* error);
bool BootInvariantFieldsEqual(const Config& left, const Config& right);
bool ValidateLiveTransition(const Config& armed, const Config& candidate,
                            std::uint64_t applied_generation, std::string* error);
std::string_view RawGnssModeName(RawGnssMode mode);
ActivationDecision DecideActivation(const Config& config, const ActivationInputs& inputs);

class StationaryModel {
 public:
  explicit StationaryModel(Config config);

  Sample Update(std::string_view provider, std::int64_t wall_time_ms,
                std::int64_t elapsed_realtime_ns);
  std::vector<Sample> UpdateBatch(std::span<const ModelUpdate> updates);
  bool Reconfigure(const Config& candidate, std::int64_t wall_time_ms,
                   std::int64_t elapsed_realtime_ns, std::string* error);
  Sample Latest() const;
  std::vector<Satellite> Satellites(std::int64_t wall_time_ms) const;
  ModelSnapshot Snapshot(std::int64_t wall_time_ms) const;
  ModelSnapshot SnapshotForNmea(std::int64_t wall_time_ms,
                                std::int64_t elapsed_realtime_ns);

 private:
  double Uniform();
  double Normal();
  double Correlated(double previous, double sigma, double tau_s, double dt_s);
  Sample UpdateLocked(std::string_view provider, std::int64_t wall_time_ms,
                      std::int64_t elapsed_realtime_ns);
  std::vector<Satellite> SatellitesLocked(std::int64_t wall_time_ms) const;
  void ResetLocked(Config config, std::int64_t wall_time_ms,
                   std::int64_t elapsed_realtime_ns);
  static std::uint64_t GenerationSeed(const Config& config);
  static double Clamp(double value, double minimum, double maximum);

  Config config_;
  mutable std::mutex mutex_;
  std::uint64_t rng_state_;
  bool has_spare_normal_ = false;
  double spare_normal_ = 0.0;
  bool initialized_ = false;
  std::int64_t last_elapsed_ns_ = 0;
  double east_m_ = 0.0;
  double north_m_ = 0.0;
  double vertical_noise_m_ = 0.0;
  double accuracy_noise_m_ = 0.0;
  double filtered_speed_mps_ = 0.0;
  Sample latest_;
};

std::vector<std::string> FormatNmea(const Sample& sample,
                                    const std::vector<Satellite>& satellites);
bool NmeaChecksumValid(std::string_view sentence);

}  // namespace zygveil::location
