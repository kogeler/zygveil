// SPDX-FileCopyrightText: 2026 kogeler
// SPDX-License-Identifier: MIT

package dev.zygveil.location.controller;

import java.math.BigDecimal;
import java.util.Locale;
import java.util.Objects;

public final class CoordinateInput {
  private static final BigDecimal LATITUDE_MIN = new BigDecimal("-90");
  private static final BigDecimal LATITUDE_MAX = new BigDecimal("90");
  private static final BigDecimal LONGITUDE_MIN = new BigDecimal("-180");
  private static final BigDecimal LONGITUDE_MAX = new BigDecimal("180");
  private static final BigDecimal ALTITUDE_MIN = new BigDecimal("-12000");
  private static final BigDecimal ALTITUDE_MAX = new BigDecimal("100000");
  private static final int MAXIMUM_INPUT_LENGTH = 32;

  private CoordinateInput() {}

  public enum Field {
    LATITUDE,
    LONGITUDE,
    ALTITUDE_ELLIPSOID,
    ALTITUDE_MSL
  }

  public enum Error {
    REQUIRED,
    DECIMAL,
    PRECISION,
    RANGE
  }

  public static final class InvalidInput extends Exception {
    private static final long serialVersionUID = 1L;
    private final Field field;
    private final Error error;

    InvalidInput(Field field, Error error) {
      super(field.name().toLowerCase(Locale.ROOT) + "_" + error.name().toLowerCase(Locale.ROOT));
      this.field = field;
      this.error = error;
    }

    public Field field() {
      return field;
    }

    public Error error() {
      return error;
    }
  }

  public record Values(
      String latitude, String longitude, String altitudeEllipsoid, String altitudeMsl) {
    public Values {
      Objects.requireNonNull(latitude);
      Objects.requireNonNull(longitude);
      Objects.requireNonNull(altitudeEllipsoid);
      Objects.requireNonNull(altitudeMsl);
    }

    public String toHelperInput() {
      return "schema_version=1\n"
          + "center_latitude_deg="
          + latitude
          + "\ncenter_longitude_deg="
          + longitude
          + "\naltitude_ellipsoid_m="
          + altitudeEllipsoid
          + "\naltitude_msl_m="
          + altitudeMsl
          + "\n";
    }
  }

  public static Values parse(
      String latitude,
      String longitude,
      String altitudeEllipsoid,
      String altitudeMsl,
      char localeDecimalSeparator)
      throws InvalidInput {
    return new Values(
        normalize(latitude, localeDecimalSeparator, 8, LATITUDE_MIN, LATITUDE_MAX, Field.LATITUDE),
        normalize(
            longitude, localeDecimalSeparator, 8, LONGITUDE_MIN, LONGITUDE_MAX, Field.LONGITUDE),
        normalize(
            altitudeEllipsoid,
            localeDecimalSeparator,
            3,
            ALTITUDE_MIN,
            ALTITUDE_MAX,
            Field.ALTITUDE_ELLIPSOID),
        normalize(
            altitudeMsl,
            localeDecimalSeparator,
            3,
            ALTITUDE_MIN,
            ALTITUDE_MAX,
            Field.ALTITUDE_MSL));
  }

  private static String normalize(
      String raw,
      char localeDecimalSeparator,
      int maximumFractionDigits,
      BigDecimal minimum,
      BigDecimal maximum,
      Field field)
      throws InvalidInput {
    if (raw == null || raw.trim().isEmpty()) {
      throw new InvalidInput(field, Error.REQUIRED);
    }
    String input = raw.trim();
    if (input.length() > MAXIMUM_INPUT_LENGTH || input.charAt(0) == '+') {
      throw new InvalidInput(field, Error.DECIMAL);
    }
    int index = input.charAt(0) == '-' ? 1 : 0;
    if (index == input.length()) {
      throw new InvalidInput(field, Error.DECIMAL);
    }
    int separatorIndex = -1;
    for (; index < input.length(); index++) {
      char value = input.charAt(index);
      boolean separator =
          value == '.' || (localeDecimalSeparator != '.' && value == localeDecimalSeparator);
      if (separator) {
        if (separatorIndex >= 0 || index == 0 || index + 1 == input.length()) {
          throw new InvalidInput(field, Error.DECIMAL);
        }
        separatorIndex = index;
      } else if (value < '0' || value > '9') {
        throw new InvalidInput(field, Error.DECIMAL);
      }
    }
    int integerStart = input.charAt(0) == '-' ? 1 : 0;
    if (separatorIndex == integerStart) {
      throw new InvalidInput(field, Error.DECIMAL);
    }
    int fractionDigits = separatorIndex < 0 ? 0 : input.length() - separatorIndex - 1;
    if (fractionDigits > maximumFractionDigits) {
      throw new InvalidInput(field, Error.PRECISION);
    }
    String canonicalInput =
        separatorIndex >= 0 && input.charAt(separatorIndex) != '.'
            ? input.substring(0, separatorIndex) + '.' + input.substring(separatorIndex + 1)
            : input;
    final BigDecimal decimal;
    try {
      decimal = new BigDecimal(canonicalInput);
    } catch (NumberFormatException error) {
      throw new InvalidInput(field, Error.DECIMAL);
    }
    if (decimal.compareTo(minimum) < 0 || decimal.compareTo(maximum) > 0) {
      throw new InvalidInput(field, Error.RANGE);
    }
    if (decimal.compareTo(BigDecimal.ZERO) == 0) {
      return "0";
    }
    return decimal.stripTrailingZeros().toPlainString();
  }
}
