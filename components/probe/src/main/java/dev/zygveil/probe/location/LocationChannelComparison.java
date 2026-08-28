// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.probe.location;

import android.location.Location;

final class LocationChannelComparison {
  static final double CONSISTENCY_THRESHOLD_M = 25.0;

  private Sample latestPlatform;
  private Sample latestGms;
  private int platformSamples;
  private int gmsSamples;
  private int comparisons;
  private double maximumDistanceMeters;
  private boolean consistent = true;
  private int objectComparisons;
  private double maximumObjectDistanceMeters;
  private boolean objectConsistent = true;

  synchronized void observePlatform(Location location) {
    Sample sample = Sample.from(location);
    if (sample == null) {
      return;
    }
    platformSamples++;
    latestPlatform = sample;
    compare(sample, latestGms);
  }

  synchronized void observeGms(Location location) {
    Sample sample = Sample.from(location);
    if (sample == null) {
      return;
    }
    gmsSamples++;
    latestGms = sample;
    compare(latestPlatform, sample);
  }

  synchronized int platformSamples() {
    return platformSamples;
  }

  synchronized int gmsSamples() {
    return gmsSamples;
  }

  synchronized int comparisons() {
    return comparisons;
  }

  synchronized Double maximumDistanceMeters() {
    return comparisons == 0 ? null : maximumDistanceMeters;
  }

  synchronized Boolean consistent() {
    return comparisons == 0 ? null : consistent;
  }

  synchronized int objectComparisons() {
    return objectComparisons;
  }

  synchronized Double maximumObjectDistanceMeters() {
    return objectComparisons == 0 ? null : maximumObjectDistanceMeters;
  }

  synchronized Boolean objectConsistent() {
    return objectComparisons == 0 ? null : objectConsistent;
  }

  private void compare(Sample platform, Sample gms) {
    if (platform == null || gms == null) {
      return;
    }
    double distance = distance(platform, gms);
    comparisons++;
    maximumDistanceMeters = Math.max(maximumDistanceMeters, distance);
    consistent &= distance <= CONSISTENCY_THRESHOLD_M;
    double objectDistance;
    try {
      Location anchor = new Location("comparison-anchor");
      anchor.setLatitude(platform.latitude());
      anchor.setLongitude(platform.longitude());
      objectDistance =
          Math.max(
              platform.location().distanceTo(gms.location()),
              Math.max(platform.location().distanceTo(anchor), gms.location().distanceTo(anchor)));
    } catch (RuntimeException error) {
      objectConsistent = false;
      return;
    }
    objectComparisons++;
    if (!Double.isFinite(objectDistance) || objectDistance < 0.0) {
      objectConsistent = false;
      return;
    }
    maximumObjectDistanceMeters = Math.max(maximumObjectDistanceMeters, objectDistance);
    objectConsistent &= objectDistance <= CONSISTENCY_THRESHOLD_M;
  }

  private static double distance(Sample first, Sample second) {
    double latitude1 = Math.toRadians(first.latitude());
    double latitude2 = Math.toRadians(second.latitude());
    double deltaLatitude = latitude2 - latitude1;
    double deltaLongitude = Math.toRadians(second.longitude() - first.longitude());
    double value =
        Math.sin(deltaLatitude / 2.0) * Math.sin(deltaLatitude / 2.0)
            + Math.cos(latitude1)
                * Math.cos(latitude2)
                * Math.sin(deltaLongitude / 2.0)
                * Math.sin(deltaLongitude / 2.0);
    return 2.0 * 6371008.8 * Math.asin(Math.min(1.0, Math.sqrt(value)));
  }

  private record Sample(double latitude, double longitude, Location location) {
    static Sample from(Location location) {
      double latitude = location.getLatitude();
      double longitude = location.getLongitude();
      if (!Double.isFinite(latitude)
          || !Double.isFinite(longitude)
          || latitude < -90.0
          || latitude > 90.0
          || longitude < -180.0
          || longitude > 180.0) {
        return null;
      }
      return new Sample(latitude, longitude, new Location(location));
    }
  }
}
