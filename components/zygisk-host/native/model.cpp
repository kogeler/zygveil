// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "model.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <cstdarg>
#include <map>
#include <utility>

namespace zygveil::location {
namespace {

constexpr double kPi = 3.14159265358979323846;
constexpr double kWgs84A = 6378137.0;
constexpr double kWgs84E2 = 6.69437999014e-3;
constexpr std::array<std::string_view, 17> kConfigKeys = {
    "schema_version",
    "enabled",
    "raw_gnss_mode",
    "center_latitude_deg",
    "center_longitude_deg",
    "altitude_ellipsoid_m",
    "altitude_msl_m",
    "horizontal_jitter_sigma_m",
    "horizontal_jitter_radius_m",
    "horizontal_correlation_time_s",
    "vertical_jitter_sigma_m",
    "accuracy_correlation_time_s",
    "speed_deadband_mps",
    "speed_max_mps",
    "bearing_min_speed_mps",
    "random_seed",
    "config_generation",
};

std::string Trim(std::string_view input) {
  const auto first = input.find_first_not_of(" \t\r");
  if (first == std::string_view::npos) {
    return {};
  }
  const auto last = input.find_last_not_of(" \t\r");
  return std::string(input.substr(first, last - first + 1));
}

bool ParseDouble(std::string_view text, double* output) {
  std::string owned(text);
  char* end = nullptr;
  errno = 0;
  const double value = std::strtod(owned.c_str(), &end);
  if (errno != 0 || end == owned.c_str() || *end != '\0' || !std::isfinite(value)) {
    return false;
  }
  *output = value;
  return true;
}

bool ParseUnsigned(std::string_view text, std::uint64_t* output) {
  const auto result = std::from_chars(text.data(), text.data() + text.size(), *output);
  return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

bool ParseInteger(std::string_view text, int* output) {
  const auto result = std::from_chars(text.data(), text.data() + text.size(), *output);
  return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}

bool SetError(std::string* error, std::string message) {
  if (error != nullptr) {
    *error = std::move(message);
  }
  return false;
}

double ProviderAccuracyCenter(std::string_view provider) {
  if (provider == "gps") {
    return 7.0;
  }
  if (provider == "fused") {
    return 11.0;
  }
  if (provider == "network") {
    return 65.0;
  }
  if (provider == "passive") {
    return 14.0;
  }
  return 18.0;
}

std::pair<double, double> ProviderAccuracyBounds(std::string_view provider) {
  if (provider == "gps") {
    return {3.0, 12.0};
  }
  if (provider == "fused") {
    return {4.0, 20.0};
  }
  if (provider == "network") {
    return {20.0, 150.0};
  }
  if (provider == "passive") {
    return {4.0, 30.0};
  }
  return {5.0, 50.0};
}

std::string FormatCoordinate(double degrees, bool latitude, char* hemisphere) {
  const bool negative = std::signbit(degrees);
  *hemisphere = latitude ? (negative ? 'S' : 'N') : (negative ? 'W' : 'E');
  const double absolute = std::abs(degrees);
  const int whole_degrees = static_cast<int>(std::floor(absolute));
  const double minutes = (absolute - static_cast<double>(whole_degrees)) * 60.0;
  std::array<char, 32> buffer{};
  std::snprintf(buffer.data(), buffer.size(), latitude ? "%02d%08.5f" : "%03d%08.5f",
                whole_degrees, minutes);
  return buffer.data();
}

std::string WithChecksum(std::string_view payload) {
  unsigned checksum = 0;
  for (const unsigned char character : payload) {
    checksum ^= character;
  }
  std::array<char, 8> suffix{};
  std::snprintf(suffix.data(), suffix.size(), "*%02X\r\n", checksum);
  std::string result;
  result.reserve(payload.size() + 7);
  result.push_back('$');
  result.append(payload);
  result.append(suffix.data());
  return result;
}

std::pair<double, double> NormalizeGeodetic(double latitude, double longitude) {
  if (latitude > 90.0) {
    latitude = 180.0 - latitude;
    longitude += 180.0;
  } else if (latitude < -90.0) {
    latitude = -180.0 - latitude;
    longitude += 180.0;
  }
  longitude = std::fmod(longitude + 180.0, 360.0);
  if (longitude < 0.0) {
    longitude += 360.0;
  }
  return {latitude, longitude - 180.0};
}

std::tm Utc(std::int64_t wall_time_ms) {
  const std::time_t seconds = static_cast<std::time_t>(wall_time_ms / 1000);
  std::tm result{};
  gmtime_r(&seconds, &result);
  return result;
}

std::string UtcTime(const std::tm& value, std::int64_t wall_time_ms) {
  std::array<char, 32> buffer{};
  std::snprintf(buffer.data(), buffer.size(), "%02d%02d%02d.%03lld", value.tm_hour,
                value.tm_min, value.tm_sec,
                static_cast<long long>(std::abs(wall_time_ms % 1000)));
  return buffer.data();
}

std::string UtcDate(const std::tm& value) {
  std::array<char, 32> buffer{};
  std::snprintf(buffer.data(), buffer.size(), "%02d%02d%02d", value.tm_mday,
                value.tm_mon + 1, (value.tm_year + 1900) % 100);
  return buffer.data();
}

void AppendFormat(std::string* destination, const char* format, ...) {
  std::array<char, 512> buffer{};
  va_list arguments;
  va_start(arguments, format);
  const int count = std::vsnprintf(buffer.data(), buffer.size(), format, arguments);
  va_end(arguments);
  if (count > 0 && static_cast<std::size_t>(count) < buffer.size()) {
    destination->append(buffer.data(), static_cast<std::size_t>(count));
  }
}

}  // namespace

std::optional<Config> ParseConfig(std::string_view text, std::string* error) {
  std::map<std::string, std::string> values;
  std::size_t offset = 0;
  int line_number = 0;
  while (offset <= text.size()) {
    const auto end = text.find('\n', offset);
    const auto length = end == std::string_view::npos ? text.size() - offset : end - offset;
    const std::string line = Trim(text.substr(offset, length));
    ++line_number;
    if (!line.empty() && line.front() != '#') {
      const auto separator = line.find('=');
      if (separator == std::string::npos) {
        SetError(error, "config line " + std::to_string(line_number) + " has no '='");
        return std::nullopt;
      }
      const std::string key = Trim(std::string_view(line).substr(0, separator));
      const std::string value = Trim(std::string_view(line).substr(separator + 1));
      if (key.empty() || value.empty()) {
        SetError(error, "config line " + std::to_string(line_number) + " is empty");
        return std::nullopt;
      }
      if (std::find(kConfigKeys.begin(), kConfigKeys.end(), key) == kConfigKeys.end()) {
        SetError(error, "unknown config key: " + key);
        return std::nullopt;
      }
      if (!values.emplace(key, value).second) {
        SetError(error, "duplicate config key: " + key);
        return std::nullopt;
      }
    }
    if (end == std::string_view::npos) {
      break;
    }
    offset = end + 1;
  }

  for (const auto key : kConfigKeys) {
    if (!values.contains(std::string(key))) {
      SetError(error, "missing config key: " + std::string(key));
      return std::nullopt;
    }
  }

  Config config;
  if (!ParseInteger(values["schema_version"], &config.schema_version)) {
    SetError(error, "schema_version is not an integer");
    return std::nullopt;
  }
  if (values["enabled"] == "true") {
    config.enabled = true;
  } else if (values["enabled"] == "false") {
    config.enabled = false;
  } else {
    SetError(error, "enabled is not true or false");
    return std::nullopt;
  }
  if (values["raw_gnss_mode"] == "blocked") {
    config.raw_gnss_mode = RawGnssMode::kBlocked;
  } else if (values["raw_gnss_mode"] == "passthrough") {
    config.raw_gnss_mode = RawGnssMode::kPassthrough;
  } else if (values["raw_gnss_mode"] == "unsupported") {
    config.raw_gnss_mode = RawGnssMode::kUnsupported;
  } else {
    SetError(error, "raw_gnss_mode is unknown");
    return std::nullopt;
  }

  const std::array<std::pair<const char*, double*>, 12> doubles = {{
      {"center_latitude_deg", &config.center_latitude_deg},
      {"center_longitude_deg", &config.center_longitude_deg},
      {"altitude_ellipsoid_m", &config.altitude_ellipsoid_m},
      {"altitude_msl_m", &config.altitude_msl_m},
      {"horizontal_jitter_sigma_m", &config.horizontal_jitter_sigma_m},
      {"horizontal_jitter_radius_m", &config.horizontal_jitter_radius_m},
      {"horizontal_correlation_time_s", &config.horizontal_correlation_time_s},
      {"vertical_jitter_sigma_m", &config.vertical_jitter_sigma_m},
      {"accuracy_correlation_time_s", &config.accuracy_correlation_time_s},
      {"speed_deadband_mps", &config.speed_deadband_mps},
      {"speed_max_mps", &config.speed_max_mps},
      {"bearing_min_speed_mps", &config.bearing_min_speed_mps},
  }};
  for (const auto& [key, destination] : doubles) {
    if (!ParseDouble(values[key], destination)) {
      SetError(error, std::string(key) + " is not finite numeric data");
      return std::nullopt;
    }
  }
  if (!ParseUnsigned(values["random_seed"], &config.random_seed)) {
    SetError(error, "random_seed is not an unsigned integer");
    return std::nullopt;
  }
  if (!ParseUnsigned(values["config_generation"], &config.config_generation) ||
      config.config_generation == 0) {
    SetError(error, "config_generation is not a positive unsigned integer");
    return std::nullopt;
  }
  if (!ValidateConfig(config, error)) {
    return std::nullopt;
  }
  return config;
}

bool ValidateConfig(const Config& config, std::string* error) {
  const auto finite = [](double value) { return std::isfinite(value); };
  if (config.schema_version != 1) {
    return SetError(error, "unsupported config schema");
  }
  if (config.config_generation == 0 ||
      config.config_generation > kMaximumConfigGeneration) {
    return SetError(error, "config_generation is outside the supported range");
  }
  if (!finite(config.center_latitude_deg) || config.center_latitude_deg < -90.0 ||
      config.center_latitude_deg > 90.0) {
    return SetError(error, "latitude is outside [-90, 90]");
  }
  if (!finite(config.center_longitude_deg) || config.center_longitude_deg < -180.0 ||
      config.center_longitude_deg > 180.0) {
    return SetError(error, "longitude is outside [-180, 180]");
  }
  const std::array nonnegative = {
      config.horizontal_jitter_sigma_m, config.horizontal_jitter_radius_m,
      config.vertical_jitter_sigma_m,    config.speed_deadband_mps,
      config.speed_max_mps,              config.bearing_min_speed_mps,
  };
  for (const double value : nonnegative) {
    if (!finite(value) || value < 0.0) {
      return SetError(error, "non-negative config value is invalid");
    }
  }
  if (config.horizontal_jitter_sigma_m > kMaximumJitterMeters ||
      config.horizontal_jitter_radius_m > kMaximumJitterMeters ||
      config.vertical_jitter_sigma_m > kMaximumJitterMeters) {
    return SetError(error, "jitter value exceeds supported maximum");
  }
  if (!finite(config.altitude_ellipsoid_m) || !finite(config.altitude_msl_m) ||
      config.altitude_ellipsoid_m < -12000.0 || config.altitude_ellipsoid_m > 100000.0 ||
      config.altitude_msl_m < -12000.0 || config.altitude_msl_m > 100000.0) {
    return SetError(error, "altitude is outside [-12000, 100000]");
  }
  if (!finite(config.horizontal_correlation_time_s) ||
      config.horizontal_correlation_time_s <= 0.0 ||
      !finite(config.accuracy_correlation_time_s) ||
      config.accuracy_correlation_time_s <= 0.0) {
    return SetError(error, "correlation time must be positive");
  }
  if (config.horizontal_correlation_time_s > kMaximumCorrelationTimeSeconds ||
      config.accuracy_correlation_time_s > kMaximumCorrelationTimeSeconds) {
    return SetError(error, "correlation time exceeds supported maximum");
  }
  if (config.speed_deadband_mps > kMaximumSpeedMetersPerSecond ||
      config.speed_max_mps > kMaximumSpeedMetersPerSecond ||
      config.bearing_min_speed_mps > kMaximumSpeedMetersPerSecond) {
    return SetError(error, "speed value exceeds supported maximum");
  }
  if (config.speed_deadband_mps > config.bearing_min_speed_mps ||
      config.bearing_min_speed_mps > config.speed_max_mps) {
    return SetError(error, "speed thresholds are not ordered");
  }
  if (config.raw_gnss_mode == RawGnssMode::kUnsupported) {
    return SetError(error, "unsupported mode is not implemented on this target");
  }
  return true;
}

bool BootInvariantFieldsEqual(const Config& left, const Config& right) {
  return left.schema_version == right.schema_version &&
         left.raw_gnss_mode == right.raw_gnss_mode &&
         left.horizontal_jitter_sigma_m == right.horizontal_jitter_sigma_m &&
         left.horizontal_jitter_radius_m == right.horizontal_jitter_radius_m &&
         left.horizontal_correlation_time_s == right.horizontal_correlation_time_s &&
         left.vertical_jitter_sigma_m == right.vertical_jitter_sigma_m &&
         left.accuracy_correlation_time_s == right.accuracy_correlation_time_s &&
         left.speed_deadband_mps == right.speed_deadband_mps &&
         left.speed_max_mps == right.speed_max_mps &&
         left.bearing_min_speed_mps == right.bearing_min_speed_mps &&
         left.random_seed == right.random_seed;
}

bool ValidateLiveTransition(const Config& armed, const Config& candidate,
                            std::uint64_t applied_generation, std::string* error) {
  std::string validation_error;
  if (!ValidateConfig(candidate, &validation_error)) {
    return SetError(error, "invalid_config:" + validation_error);
  }
  if (candidate.config_generation <= applied_generation) {
    return SetError(error, "stale_generation");
  }
  if (!candidate.enabled) {
    return SetError(error, armed.enabled ? "activation_regression" : "activation_required");
  }
  if (!BootInvariantFieldsEqual(armed, candidate)) {
    return SetError(error, "boot_field_mismatch");
  }
  return true;
}

std::string_view RawGnssModeName(RawGnssMode mode) {
  switch (mode) {
    case RawGnssMode::kBlocked:
      return "blocked";
    case RawGnssMode::kPassthrough:
      return "passthrough";
    case RawGnssMode::kUnsupported:
      return "unsupported";
  }
  return "invalid";
}

ActivationDecision DecideActivation(const Config& config, const ActivationInputs& inputs) {
  std::string config_error;
  if (!ValidateConfig(config, &config_error)) {
    return {false, "config:" + config_error};
  }
  if (!config.enabled) {
    return {false, "disabled_by_config"};
  }
  const std::array checks = {
      std::pair{"guard", inputs.guard_valid},
      std::pair{"bridge", inputs.bridge_ready},
      std::pair{"location_hook", inputs.location_hook},
      std::pair{"status_hook", inputs.status_hook},
      std::pair{"nmea_hook", inputs.nmea_hook},
      std::pair{"measurement_hook", inputs.measurement_hook},
      std::pair{"navigation_hook", inputs.navigation_hook},
  };
  for (const auto& [name, ready] : checks) {
    if (!ready) {
      return {false, std::string("missing:") + name};
    }
  }
  return {true, config.raw_gnss_mode == RawGnssMode::kPassthrough
                    ? "active:passthrough:physical_raw_warning"
                    : "active:blocked"};
}

StationaryModel::StationaryModel(Config config) : config_(config), rng_state_(0) {
  ResetLocked(std::move(config), 0, 0);
}

double StationaryModel::Uniform() {
  rng_state_ += 0x9e3779b97f4a7c15ULL;
  std::uint64_t value = rng_state_;
  value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
  value ^= value >> 31U;
  constexpr double denominator = static_cast<double>(std::uint64_t{1} << 53U);
  return (static_cast<double>(value >> 11U) + 0.5) / denominator;
}

double StationaryModel::Normal() {
  if (has_spare_normal_) {
    has_spare_normal_ = false;
    return spare_normal_;
  }
  const double radius = std::sqrt(-2.0 * std::log(Uniform()));
  const double angle = 2.0 * kPi * Uniform();
  spare_normal_ = radius * std::sin(angle);
  has_spare_normal_ = true;
  return radius * std::cos(angle);
}

double StationaryModel::Correlated(double previous, double sigma, double tau_s, double dt_s) {
  const double rho = std::exp(-dt_s / tau_s);
  return rho * previous + sigma * std::sqrt(std::max(0.0, 1.0 - rho * rho)) * Normal();
}

double StationaryModel::Clamp(double value, double minimum, double maximum) {
  return std::max(minimum, std::min(maximum, value));
}

Sample StationaryModel::Update(std::string_view provider, std::int64_t wall_time_ms,
                               std::int64_t elapsed_realtime_ns) {
  std::lock_guard lock(mutex_);
  return UpdateLocked(provider, wall_time_ms, elapsed_realtime_ns);
}

std::vector<Sample> StationaryModel::UpdateBatch(std::span<const ModelUpdate> updates) {
  std::lock_guard lock(mutex_);
  std::vector<Sample> result;
  result.reserve(updates.size());
  for (const ModelUpdate& update : updates) {
    result.push_back(
        UpdateLocked(update.provider, update.wall_time_ms, update.elapsed_realtime_ns));
  }
  return result;
}

Sample StationaryModel::UpdateLocked(std::string_view provider, std::int64_t wall_time_ms,
                                     std::int64_t elapsed_realtime_ns) {
  std::int64_t normalized_elapsed = elapsed_realtime_ns;
  if (last_elapsed_ns_ > 0 && normalized_elapsed <= last_elapsed_ns_) {
    normalized_elapsed = last_elapsed_ns_ + 1;
  }
  double dt_s = initialized_
                    ? static_cast<double>(normalized_elapsed - last_elapsed_ns_) / 1'000'000'000.0
                    : 1.0;
  dt_s = Clamp(dt_s, 1e-6, 60.0);
  const double previous_east = east_m_;
  const double previous_north = north_m_;
  east_m_ = Correlated(east_m_, config_.horizontal_jitter_sigma_m,
                       config_.horizontal_correlation_time_s, dt_s);
  north_m_ = Correlated(north_m_, config_.horizontal_jitter_sigma_m,
                        config_.horizontal_correlation_time_s, dt_s);
  const double radius = std::hypot(east_m_, north_m_);
  if (radius > config_.horizontal_jitter_radius_m && radius > 0.0) {
    const double scale = config_.horizontal_jitter_radius_m / radius;
    east_m_ *= scale;
    north_m_ *= scale;
  }
  vertical_noise_m_ = Correlated(vertical_noise_m_, config_.vertical_jitter_sigma_m,
                                 config_.horizontal_correlation_time_s * 1.5, dt_s);
  accuracy_noise_m_ = Correlated(accuracy_noise_m_, 2.0,
                                 config_.accuracy_correlation_time_s, dt_s);

  const double latitude_radians = config_.center_latitude_deg * kPi / 180.0;
  const double sin_latitude = std::sin(latitude_radians);
  const double denominator = std::sqrt(1.0 - kWgs84E2 * sin_latitude * sin_latitude);
  const double meridional_radius =
      kWgs84A * (1.0 - kWgs84E2) / (denominator * denominator * denominator);
  const double prime_vertical_radius = kWgs84A / denominator;
  const double longitude_scale = prime_vertical_radius * std::cos(latitude_radians);

  Sample sample;
  sample.config_generation = config_.config_generation;
  sample.wall_time_ms = wall_time_ms;
  sample.elapsed_realtime_ns = normalized_elapsed;
  sample.east_m = east_m_;
  sample.north_m = north_m_;
  const double latitude =
      config_.center_latitude_deg + north_m_ / meridional_radius * 180.0 / kPi;
  const double longitude =
      std::abs(longitude_scale) < 1e-9
          ? config_.center_longitude_deg
          : config_.center_longitude_deg + east_m_ / longitude_scale * 180.0 / kPi;
  const auto [normalized_latitude, normalized_longitude] =
      NormalizeGeodetic(latitude, longitude);
  sample.latitude_deg = normalized_latitude;
  sample.longitude_deg = normalized_longitude;
  sample.altitude_ellipsoid_m = config_.altitude_ellipsoid_m + vertical_noise_m_;
  sample.altitude_msl_m = config_.altitude_msl_m + vertical_noise_m_;
  const auto [accuracy_min, accuracy_max] = ProviderAccuracyBounds(provider);
  sample.horizontal_accuracy_m =
      Clamp(ProviderAccuracyCenter(provider) + accuracy_noise_m_, accuracy_min, accuracy_max);
  sample.vertical_accuracy_m = Clamp(sample.horizontal_accuracy_m * 1.7, 5.0, 20.0);
  sample.msl_altitude_accuracy_m = sample.vertical_accuracy_m;

  const double instantaneous_speed =
      std::hypot(east_m_ - previous_east, north_m_ - previous_north) / dt_s;
  filtered_speed_mps_ = 0.75 * filtered_speed_mps_ + 0.25 * instantaneous_speed;
  sample.speed_mps = filtered_speed_mps_ < config_.speed_deadband_mps
                         ? 0.0
                         : Clamp(filtered_speed_mps_, 0.0, config_.speed_max_mps);
  sample.speed_accuracy_mps = Clamp(0.05 + sample.horizontal_accuracy_m / 100.0, 0.05, 0.3);
  if (sample.speed_mps >= config_.bearing_min_speed_mps) {
    sample.has_bearing = true;
    sample.bearing_deg = std::atan2(east_m_ - previous_east, north_m_ - previous_north) *
                         180.0 / kPi;
    if (sample.bearing_deg < 0.0) {
      sample.bearing_deg += 360.0;
    }
    sample.bearing_accuracy_deg = 25.0;
  }

  initialized_ = true;
  last_elapsed_ns_ = normalized_elapsed;
  latest_ = sample;
  return sample;
}

bool StationaryModel::Reconfigure(const Config& candidate, std::int64_t wall_time_ms,
                                  std::int64_t elapsed_realtime_ns, std::string* error) {
  std::lock_guard lock(mutex_);
  if (!ValidateLiveTransition(config_, candidate, config_.config_generation, error)) {
    return false;
  }
  ResetLocked(candidate, wall_time_ms, elapsed_realtime_ns);
  return true;
}

std::uint64_t StationaryModel::GenerationSeed(const Config& config) {
  std::uint64_t value = config.random_seed ^
                        (config.config_generation + 0x9e3779b97f4a7c15ULL);
  value = (value ^ (value >> 30U)) * 0xbf58476d1ce4e5b9ULL;
  value = (value ^ (value >> 27U)) * 0x94d049bb133111ebULL;
  return value ^ (value >> 31U);
}

void StationaryModel::ResetLocked(Config config, std::int64_t wall_time_ms,
                                  std::int64_t elapsed_realtime_ns) {
  config_ = std::move(config);
  rng_state_ = GenerationSeed(config_);
  has_spare_normal_ = false;
  spare_normal_ = 0.0;
  initialized_ = false;
  if (elapsed_realtime_ns > last_elapsed_ns_) {
    last_elapsed_ns_ = elapsed_realtime_ns;
  }
  east_m_ = 0.0;
  north_m_ = 0.0;
  vertical_noise_m_ = 0.0;
  accuracy_noise_m_ = 0.0;
  filtered_speed_mps_ = 0.0;
  latest_ = {};
  latest_.config_generation = config_.config_generation;
  latest_.wall_time_ms = wall_time_ms;
  latest_.elapsed_realtime_ns = last_elapsed_ns_;
  latest_.latitude_deg = config_.center_latitude_deg;
  latest_.longitude_deg = config_.center_longitude_deg;
  latest_.altitude_ellipsoid_m = config_.altitude_ellipsoid_m;
  latest_.altitude_msl_m = config_.altitude_msl_m;
  latest_.horizontal_accuracy_m = ProviderAccuracyCenter("gps");
  latest_.vertical_accuracy_m = latest_.horizontal_accuracy_m * 1.7;
  latest_.msl_altitude_accuracy_m = latest_.vertical_accuracy_m;
  latest_.speed_accuracy_mps = 0.12;
}

Sample StationaryModel::Latest() const {
  std::lock_guard lock(mutex_);
  return latest_;
}

std::vector<Satellite> StationaryModel::Satellites(std::int64_t wall_time_ms) const {
  std::lock_guard lock(mutex_);
  return SatellitesLocked(wall_time_ms);
}

std::vector<Satellite> StationaryModel::SatellitesLocked(std::int64_t wall_time_ms) const {
  std::vector<Satellite> result;
  result.reserve(16);
  const double seconds = static_cast<double>(wall_time_ms) / 1000.0;
  for (int index = 0; index < 16; ++index) {
    const double phase = static_cast<double>(index) * 0.73 + seconds / 600.0;
    Satellite satellite;
    satellite.svid = index + 1;
    satellite.azimuth_deg = std::fmod(index * 41.0 + seconds * 0.02, 360.0);
    satellite.elevation_deg = Clamp(10.0 + 68.0 * std::abs(std::sin(phase)), 5.0, 85.0);
    satellite.cn0_db_hz = Clamp(25.0 + 16.0 * std::abs(std::cos(phase * 0.67)), 18.0, 48.0);
    satellite.baseband_cn0_db_hz = satellite.cn0_db_hz - 1.5;
    satellite.used_in_fix = index < 10;
    result.push_back(satellite);
  }
  return result;
}

ModelSnapshot StationaryModel::Snapshot(std::int64_t wall_time_ms) const {
  std::lock_guard lock(mutex_);
  return {latest_, SatellitesLocked(wall_time_ms)};
}

ModelSnapshot StationaryModel::SnapshotForNmea(std::int64_t wall_time_ms,
                                               std::int64_t elapsed_realtime_ns) {
  std::lock_guard lock(mutex_);
  if (latest_.wall_time_ms == 0) {
    UpdateLocked("gps", wall_time_ms, elapsed_realtime_ns);
  }
  return {latest_, SatellitesLocked(latest_.wall_time_ms)};
}

std::vector<std::string> FormatNmea(const Sample& sample,
                                    const std::vector<Satellite>& satellites) {
  const std::tm utc = Utc(sample.wall_time_ms);
  const std::string time = UtcTime(utc, sample.wall_time_ms);
  const std::string date = UtcDate(utc);
  char latitude_hemisphere = 'N';
  char longitude_hemisphere = 'E';
  const std::string latitude =
      FormatCoordinate(sample.latitude_deg, true, &latitude_hemisphere);
  const std::string longitude =
      FormatCoordinate(sample.longitude_deg, false, &longitude_hemisphere);
  const int used = static_cast<int>(std::count_if(
      satellites.begin(), satellites.end(), [](const Satellite& value) { return value.used_in_fix; }));
  const double hdop = std::clamp(sample.horizontal_accuracy_m / 5.0, 0.7, 9.9);
  const double vdop = std::clamp(sample.vertical_accuracy_m / 5.0, 1.0, 9.9);
  const double pdop = std::sqrt(hdop * hdop + vdop * vdop);
  const double geoid = sample.altitude_ellipsoid_m - sample.altitude_msl_m;

  std::vector<std::string> sentences;
  std::string gga;
  AppendFormat(&gga, "GPGGA,%s,%s,%c,%s,%c,1,%02d,%.1f,%.1f,M,%.1f,M,,", time.c_str(),
               latitude.c_str(), latitude_hemisphere, longitude.c_str(), longitude_hemisphere,
               used, hdop, sample.altitude_msl_m, geoid);
  sentences.push_back(WithChecksum(gga));

  std::string rmc;
  AppendFormat(&rmc, "GPRMC,%s,A,%s,%c,%s,%c,%.2f,", time.c_str(), latitude.c_str(),
               latitude_hemisphere, longitude.c_str(), longitude_hemisphere,
               sample.speed_mps * 1.9438444924406);
  if (sample.has_bearing) {
    AppendFormat(&rmc, "%.1f", sample.bearing_deg);
  }
  AppendFormat(&rmc, ",%s,,,A", date.c_str());
  sentences.push_back(WithChecksum(rmc));

  std::string gsa = "GPGSA,A,3";
  int emitted = 0;
  for (const Satellite& satellite : satellites) {
    if (satellite.used_in_fix && emitted < 12) {
      AppendFormat(&gsa, ",%02d", satellite.svid);
      ++emitted;
    }
  }
  while (emitted++ < 12) {
    gsa.push_back(',');
  }
  AppendFormat(&gsa, ",%.1f,%.1f,%.1f", pdop, hdop, vdop);
  sentences.push_back(WithChecksum(gsa));

  const int sentence_count = std::max(1, (static_cast<int>(satellites.size()) + 3) / 4);
  for (int sentence_index = 0; sentence_index < sentence_count; ++sentence_index) {
    std::string gsv;
    AppendFormat(&gsv, "GPGSV,%d,%d,%02zu", sentence_count, sentence_index + 1,
                 satellites.size());
    const int begin = sentence_index * 4;
    const int end = std::min(begin + 4, static_cast<int>(satellites.size()));
    for (int index = begin; index < end; ++index) {
      const Satellite& satellite = satellites[index];
      AppendFormat(&gsv, ",%02d,%02d,%03d,%02d", satellite.svid,
                   static_cast<int>(std::lround(satellite.elevation_deg)),
                   static_cast<int>(std::lround(satellite.azimuth_deg)),
                   static_cast<int>(std::lround(satellite.cn0_db_hz)));
    }
    sentences.push_back(WithChecksum(gsv));
  }
  return sentences;
}

bool NmeaChecksumValid(std::string_view sentence) {
  if (sentence.size() < 7 || sentence.front() != '$') {
    return false;
  }
  const auto marker = sentence.find('*');
  if (marker == std::string_view::npos || marker + 2 >= sentence.size()) {
    return false;
  }
  unsigned expected = 0;
  const auto parse = std::from_chars(sentence.data() + marker + 1,
                                     sentence.data() + marker + 3, expected, 16);
  if (parse.ec != std::errc{} || parse.ptr != sentence.data() + marker + 3) {
    return false;
  }
  unsigned actual = 0;
  for (std::size_t index = 1; index < marker; ++index) {
    actual ^= static_cast<unsigned char>(sentence[index]);
  }
  return actual == expected;
}

}  // namespace zygveil::location
