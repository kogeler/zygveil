// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "model.hpp"

#include <algorithm>
#include <atomic>
#include <array>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <thread>
#include <vector>

namespace {

int tests = 0;

void Check(bool condition, const char* name) {
  ++tests;
  if (!condition) {
    std::cerr << "FAIL " << name << '\n';
    std::exit(1);
  }
}

std::string Read(const char* path) {
  std::ifstream stream(path);
  Check(stream.good(), "config fixture readable");
  return {std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
}

bool Near(double left, double right, double tolerance) {
  return std::abs(left - right) <= tolerance;
}

}  // namespace

int main(int argc, char** argv) {
  using zygveil::location::ActivationInputs;
  using zygveil::location::Config;
  using zygveil::location::DecideActivation;
  using zygveil::location::FormatNmea;
  using zygveil::location::NmeaChecksumValid;
  using zygveil::location::ParseConfig;
  using zygveil::location::RawGnssMode;
  using zygveil::location::StationaryModel;
  using zygveil::location::ValidateConfig;

  Check(argc == 2, "fixture argument");
  std::string error;
  const auto parsed = ParseConfig(Read(argv[1]), &error);
  Check(parsed.has_value(), "valid config parses");
  Config config = *parsed;
  Check(!config.enabled, "example disabled");
  Check(config.raw_gnss_mode == RawGnssMode::kBlocked, "blocked mode parses");
  Check(config.config_generation == 1, "config generation parses");

  std::string enabled_text = Read(argv[1]);
  enabled_text.replace(enabled_text.find("enabled=false"), 13, "enabled=true");
  const auto enabled = ParseConfig(enabled_text, &error);
  Check(enabled.has_value() && enabled->enabled, "enabled config parses");
  config = *enabled;

  std::string invalid = enabled_text + "unknown_key=1\n";
  Check(!ParseConfig(invalid, &error).has_value(), "unknown config key rejected");
  invalid = enabled_text;
  invalid.replace(invalid.find("center_latitude_deg=0.0"), 23, "center_latitude_deg=nan");
  Check(!ParseConfig(invalid, &error).has_value(), "non-finite latitude rejected");
  Config invalid_config = config;
  invalid_config.center_latitude_deg = 91.0;
  Check(!ValidateConfig(invalid_config, &error), "latitude range enforced");
  invalid_config = config;
  invalid_config.center_longitude_deg = -181.0;
  Check(!ValidateConfig(invalid_config, &error), "longitude range enforced");
  invalid_config = config;
  invalid_config.horizontal_jitter_sigma_m = -1.0;
  Check(!ValidateConfig(invalid_config, &error), "negative jitter rejected");
  invalid_config = config;
  invalid_config.horizontal_jitter_radius_m = std::numeric_limits<double>::max();
  Check(!ValidateConfig(invalid_config, &error), "excessive jitter rejected");
  invalid_config = config;
  invalid_config.horizontal_correlation_time_s = std::numeric_limits<double>::max();
  Check(!ValidateConfig(invalid_config, &error), "excessive correlation rejected");
  invalid_config = config;
  invalid_config.speed_max_mps = std::numeric_limits<double>::max();
  Check(!ValidateConfig(invalid_config, &error), "excessive speed rejected");
  invalid_config = config;
  invalid_config.speed_deadband_mps = 0.3;
  invalid_config.bearing_min_speed_mps = 0.2;
  Check(!ValidateConfig(invalid_config, &error), "speed ordering enforced");
  invalid_config = config;
  invalid_config.raw_gnss_mode = RawGnssMode::kUnsupported;
  Check(!ValidateConfig(invalid_config, &error), "unsupported mode rejected");
  invalid_config = config;
  invalid_config.config_generation = 0;
  Check(!ValidateConfig(invalid_config, &error), "zero config generation rejected");
  invalid_config.config_generation = zygveil::location::kMaximumConfigGeneration + 1;
  Check(!ValidateConfig(invalid_config, &error), "config generation token overflow rejected");

  StationaryModel first(config);
  StationaryModel second(config);
  std::vector<zygveil::location::Sample> samples;
  for (int index = 0; index < 120; ++index) {
    const auto elapsed = 1'000'000'000LL * (index + 1);
    const auto left = first.Update("gps", 1'700'000'000'000LL + index * 1000, elapsed);
    const auto right = second.Update("gps", 1'700'000'000'000LL + index * 1000, elapsed);
    Check(left.latitude_deg == right.latitude_deg && left.longitude_deg == right.longitude_deg,
          "fixed seed deterministic");
    Check(std::hypot(left.east_m, left.north_m) <= config.horizontal_jitter_radius_m + 1e-9,
          "radial clamp");
    Check(std::isfinite(left.latitude_deg) && std::isfinite(left.longitude_deg),
          "finite coordinates");
    Check(left.horizontal_accuracy_m >= 3.0 && left.horizontal_accuracy_m <= 12.0,
          "gps accuracy range");
    Check(left.vertical_accuracy_m >= left.horizontal_accuracy_m ||
              Near(left.vertical_accuracy_m, 20.0, 1e-9),
          "vertical accuracy relationship");
    Check(left.speed_mps >= 0.0 && left.speed_mps <= config.speed_max_mps,
          "speed bounded");
    Check(left.has_bearing == (left.speed_mps >= config.bearing_min_speed_mps),
          "bearing threshold");
    Check(Near(left.altitude_ellipsoid_m - left.altitude_msl_m,
               config.altitude_ellipsoid_m - config.altitude_msl_m, 1e-9),
          "geoid separation stable");
    samples.push_back(left);
  }
  Check(samples.back().elapsed_realtime_ns == 120'000'000'000LL,
        "valid elapsed timestamp preserved");
  const auto stale = first.Update("gps", 1'700'000'120'000LL, 119'000'000'000LL);
  Check(stale.elapsed_realtime_ns > samples.back().elapsed_realtime_ns,
        "stale elapsed timestamp normalized");
  Check(stale.wall_time_ms == 1'700'000'120'000LL, "wall timestamp preserved");

  Config live = config;
  live.config_generation = 2;
  live.center_latitude_deg = -33.75;
  live.center_longitude_deg = 179.9999;
  live.altitude_ellipsoid_m = 250.0;
  live.altitude_msl_m = 210.0;
  Check(first.Reconfigure(live, 1'700'000'121'000LL, 121'000'000'000LL, &error),
        "new live generation accepted");
  const auto live_latest = first.Latest();
  Check(live_latest.config_generation == 2, "latest generation switches atomically");
  Check(live_latest.latitude_deg == live.center_latitude_deg &&
            live_latest.longitude_deg == live.center_longitude_deg,
        "latest sample resets to new center");
  Check(live_latest.altitude_ellipsoid_m == live.altitude_ellipsoid_m &&
            live_latest.altitude_msl_m == live.altitude_msl_m,
        "latest altitudes reset");
  Check(live_latest.speed_mps == 0.0 && !live_latest.has_bearing,
        "motion and bearing reset");
  const auto first_live =
      first.Update("gps", 1'700'000'121'000LL, 120'000'000'000LL);
  Check(first_live.config_generation == 2, "first post-switch event uses new generation");
  Check(first_live.elapsed_realtime_ns > live_latest.elapsed_realtime_ns,
        "post-switch elapsed timestamp remains monotonic");
  Check(std::abs(first_live.latitude_deg - live.center_latitude_deg) < 0.0001,
        "post-switch latitude uses new center");
  Check(std::abs(std::abs(first_live.longitude_deg) - 180.0) < 0.0002,
        "dateline conversion remains bounded");
  Check(Near(first_live.altitude_ellipsoid_m - first_live.altitude_msl_m, 40.0, 1e-9),
        "post-switch altitude model coherent");

  Config stale_live = live;
  Check(!first.Reconfigure(stale_live, 1'700'000'122'000LL, 122'000'000'000LL, &error) &&
            error == "stale_generation",
        "stale live generation rejected");
  Config invalid_live = live;
  invalid_live.config_generation = 3;
  invalid_live.center_latitude_deg = 91.0;
  Check(!first.Reconfigure(invalid_live, 1'700'000'122'000LL, 122'000'000'000LL, &error),
        "invalid live coordinate rejected");
  Config boot_changed = live;
  boot_changed.config_generation = 3;
  boot_changed.horizontal_jitter_radius_m += 1.0;
  Check(!first.Reconfigure(boot_changed, 1'700'000'122'000LL, 122'000'000'000LL, &error) &&
            error == "boot_field_mismatch",
        "boot-invariant live change rejected");
  Check(first.Latest().config_generation == 2, "rejection retains valid generation");

  StationaryModel reset_first(config);
  StationaryModel reset_second(config);
  for (int index = 0; index < 40; ++index) {
    reset_first.Update("gps", 1'700'000'000'000LL + index * 1000,
                       1'000'000'000LL * (index + 1));
  }
  reset_second.Update("network", 1'700'000'000'000LL, 1'000'000'000LL);
  Check(reset_first.Reconfigure(live, 1'700'000'200'000LL, 200'000'000'000LL, &error) &&
            reset_second.Reconfigure(live, 1'700'000'200'000LL, 200'000'000'000LL, &error),
        "different histories accept same generation");
  const auto reset_left =
      reset_first.Update("gps", 1'700'000'201'000LL, 201'000'000'000LL);
  const auto reset_right =
      reset_second.Update("gps", 1'700'000'201'000LL, 201'000'000'000LL);
  Check(reset_left.latitude_deg == reset_right.latitude_deg &&
            reset_left.longitude_deg == reset_right.longitude_deg &&
            reset_left.altitude_ellipsoid_m == reset_right.altitude_ellipsoid_m,
        "generation reset removes prior PRNG/model history");

  const std::array batch_updates = {
      zygveil::location::ModelUpdate{"gps", 1'700'000'202'000LL, 202'000'000'000LL},
      zygveil::location::ModelUpdate{"fused", 1'700'000'202'100LL, 202'100'000'000LL},
      zygveil::location::ModelUpdate{"network", 1'700'000'202'200LL, 202'200'000'000LL},
  };
  const auto batch = reset_first.UpdateBatch(batch_updates);
  Check(batch.size() == batch_updates.size(), "batch size preserved");
  Check(std::all_of(batch.begin(), batch.end(), [](const auto& sample) {
          return sample.config_generation == 2;
        }),
        "batch observes one generation");
  const auto snapshot = reset_first.Snapshot(batch.back().wall_time_ms);
  Check(snapshot.sample.config_generation == 2 && snapshot.satellites.size() == 16,
        "sample and satellite snapshot coherent");

  Config polar = live;
  polar.config_generation = 3;
  polar.center_latitude_deg = 90.0;
  polar.center_longitude_deg = -180.0;
  Check(reset_first.Reconfigure(polar, 1'700'000'203'000LL, 203'000'000'000LL, &error),
        "pole generation accepted");
  for (int index = 0; index < 256; ++index) {
    const auto polar_sample = reset_first.Update(
        "gps", 1'700'000'204'000LL + index * 1000,
        204'000'000'000LL + static_cast<std::int64_t>(index) * 1'000'000'000LL);
    Check(std::isfinite(polar_sample.latitude_deg) && std::isfinite(polar_sample.longitude_deg),
          "north pole output finite");
    Check(polar_sample.latitude_deg >= -90.0 && polar_sample.latitude_deg <= 90.0,
          "north pole latitude bounded");
    Check(polar_sample.longitude_deg >= -180.0 && polar_sample.longitude_deg <= 180.0,
          "north pole longitude bounded");
  }
  Config south_polar = polar;
  south_polar.config_generation = 4;
  south_polar.center_latitude_deg = -90.0;
  south_polar.center_longitude_deg = 180.0;
  Check(reset_first.Reconfigure(south_polar, 1'700'000'500'000LL, 500'000'000'000LL, &error),
        "south pole generation accepted");
  for (int index = 0; index < 256; ++index) {
    const auto polar_sample = reset_first.Update(
        "gps", 1'700'000'501'000LL + index * 1000,
        501'000'000'000LL + static_cast<std::int64_t>(index) * 1'000'000'000LL);
    Check(polar_sample.latitude_deg >= -90.0 && polar_sample.latitude_deg <= 90.0,
          "south pole latitude bounded");
    Check(polar_sample.longitude_deg >= -180.0 && polar_sample.longitude_deg <= 180.0,
          "south pole longitude bounded");
  }
  const auto polar_nmea = FormatNmea(reset_first.Latest(), reset_first.Satellites(1'700'000'800'000LL));
  Check(std::all_of(polar_nmea.begin(), polar_nmea.end(), NmeaChecksumValid),
        "polar NMEA remains valid");

  Config concurrent_config = config;
  concurrent_config.center_latitude_deg = -60.0;
  concurrent_config.altitude_ellipsoid_m = 100.0;
  concurrent_config.altitude_msl_m = 60.0;
  StationaryModel concurrent_model(concurrent_config);
  std::atomic<bool> concurrent_done = false;
  std::atomic<bool> concurrent_failed = false;
  std::thread reconfigurer([&]() {
    Config candidate = concurrent_config;
    for (std::uint64_t generation = 2; generation <= 3000; ++generation) {
      candidate.config_generation = generation;
      const bool even = generation % 2 == 0;
      candidate.center_latitude_deg = even ? 60.0 : -60.0;
      candidate.center_longitude_deg = even ? 170.0 : -170.0;
      candidate.altitude_ellipsoid_m = even ? 140.0 : 100.0;
      candidate.altitude_msl_m = 60.0;
      std::string reconfigure_error;
      if (!concurrent_model.Reconfigure(candidate, 1'700'100'000'000LL + generation,
                                        300'000'000'000LL + generation,
                                        &reconfigure_error)) {
        concurrent_failed.store(true, std::memory_order_release);
        break;
      }
    }
    concurrent_done.store(true, std::memory_order_release);
  });
  std::vector<std::thread> model_readers;
  for (int reader = 0; reader < 4; ++reader) {
    model_readers.emplace_back([&, reader]() {
      std::int64_t sequence = reader;
      while (!concurrent_done.load(std::memory_order_acquire)) {
        const auto value = concurrent_model.Update(
            "gps", 1'700'200'000'000LL + sequence, 400'000'000'000LL + sequence);
        const bool even = value.config_generation % 2 == 0;
        const double expected_geoid = even ? 80.0 : 40.0;
        if ((even && value.latitude_deg < 59.0) || (!even && value.latitude_deg > -59.0) ||
            !Near(value.altitude_ellipsoid_m - value.altitude_msl_m, expected_geoid, 1e-9)) {
          concurrent_failed.store(true, std::memory_order_release);
          return;
        }
        ++sequence;
      }
    });
  }
  reconfigurer.join();
  for (auto& reader : model_readers) {
    reader.join();
  }
  Check(!concurrent_failed.load(std::memory_order_acquire),
        "concurrent update observes complete old-or-new generation");
  Check(concurrent_model.Latest().config_generation == 3000,
        "concurrent final generation active");

  Config conversion = config;
  conversion.center_latitude_deg = 0.0;
  conversion.center_longitude_deg = 0.0;
  conversion.horizontal_jitter_sigma_m = 1.0;
  conversion.horizontal_jitter_radius_m = 5.0;
  StationaryModel conversion_model(conversion);
  const auto converted = conversion_model.Update("fused", 1'700'000'000'000LL, 1'000'000'000LL);
  Check(std::abs(converted.latitude_deg) < 0.0001 &&
            std::abs(converted.longitude_deg) < 0.0001,
        "local WGS84 conversion scale");
  Check(converted.horizontal_accuracy_m >= 4.0 && converted.horizontal_accuracy_m <= 20.0,
        "fused accuracy range");
  const auto network =
      conversion_model.Update("network", 1'700'000'001'000LL, 2'000'000'000LL);
  Check(network.horizontal_accuracy_m >= 20.0 && network.horizontal_accuracy_m <= 150.0,
        "network accuracy range");

  const auto satellites = first.Satellites(stale.wall_time_ms);
  Check(satellites.size() == 16, "satellite count");
  int used = 0;
  for (const auto& satellite : satellites) {
    Check(satellite.svid >= 1 && satellite.svid <= 32, "satellite SVID range");
    Check(satellite.constellation == 1, "satellite constellation");
    Check(satellite.azimuth_deg >= 0.0 && satellite.azimuth_deg < 360.0,
          "satellite azimuth range");
    Check(satellite.elevation_deg >= 5.0 && satellite.elevation_deg <= 85.0,
          "satellite elevation range");
    Check(satellite.cn0_db_hz >= 18.0 && satellite.cn0_db_hz <= 48.0,
          "satellite CN0 range");
    used += satellite.used_in_fix ? 1 : 0;
  }
  Check(used == 10, "satellites used in fix");

  const auto nmea = FormatNmea(stale, satellites);
  Check(nmea.size() == 7, "NMEA sentence set");
  for (const auto& sentence : nmea) {
    Check(NmeaChecksumValid(sentence), "NMEA checksum");
  }
  Check(nmea[0].starts_with("$GPGGA,"), "GGA present");
  Check(nmea[1].starts_with("$GPRMC,"), "RMC present");
  Check(nmea[2].starts_with("$GPGSA,"), "GSA present");
  Check(nmea[3].starts_with("$GPGSV,"), "GSV present");
  Check(nmea[0].find(",10,") != std::string::npos, "GGA satellite count consistent");

  ActivationInputs ready{true, true, true, true, true, true, true};
  const auto active = DecideActivation(config, ready);
  Check(active.active && active.reason == "active:blocked", "atomic activation succeeds");
  ready.navigation_hook = false;
  const auto partial = DecideActivation(config, ready);
  Check(!partial.active && partial.reason == "missing:navigation_hook",
        "partial activation rejected");
  Config disabled = config;
  disabled.enabled = false;
  Check(!DecideActivation(disabled, ActivationInputs{}).active, "disabled activation rejected");
  Config passthrough = config;
  passthrough.raw_gnss_mode = RawGnssMode::kPassthrough;
  ready.navigation_hook = true;
  const auto diagnostic = DecideActivation(passthrough, ready);
  Check(diagnostic.active && diagnostic.reason.find("physical_raw_warning") != std::string::npos,
        "passthrough warning");

  std::cout << "schema_version=1\nstatus=PASS\ntests=" << tests
            << "\ncategories=config,coordinates,jitter,timestamps,accuracy,altitude,speed,bearing,"
               "gnss,nmea,activation,reconfiguration,batch,concurrency,edges\n";
  return 0;
}
