/* Copyright (c) 2017 OpenJAX
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * You should have received a copy of The MIT License (MIT) along with this
 * program. If not, see <http://opensource.org/licenses/MIT/>.
 */

package org.openjax.security.otp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;

import org.libj.lang.Base32;
import org.libj.lang.Hexadecimal;
import org.openjax.security.crypto.Hmac;

/**
 * Utility functions for Google Authenticator OTP (One Time Password).
 */
public final class GAuth {
  private static final SecureRandom random = new SecureRandom();

  /**
   * Returns a random 20 byte Base32 encoded secret key.
   *
   * @return A random 20 byte Base32 encoded secret key.
   */
  public static String generateRandomSecretKey() {
    final byte[] bytes = new byte[20];
    random.nextBytes(bytes);
    return Base32.encode(bytes);
  }

  /**
   * Returns the Google Authenticator barcode otpauth string.
   *
   * @param key Base32 encoded secret key (will be converted to upper-case, and
   *          allows whitespace, which will be removed).
   * @param account The user's account name (e.g. an email address or a
   *          username).
   * @param issuer The organization managing this account.
   * @return The Google Authenticator barcode otpauth string.
   * @throws UnsupportedOperationException If UTF-8 encoding is not supported.
   * @throws IllegalArgumentException If {@code key} or {@code issuer} is null.
   * @see <a href=
   *      "https://github.com/google/google-authenticator/wiki/Key-Uri-Format">Key-Uri-Format</a>
   */
  public static String getBarCode(final String key, final String account, final String issuer) {
    final String normalizedBase32Key = key.replace(" ", "").toUpperCase();
    try {
      return "otpauth://totp/" + URLEncoder.encode(issuer + ":" + account, "UTF8").replace("+", "%20") + "?secret=" + URLEncoder.encode(normalizedBase32Key, "UTF8").replace("+", "%20") + "&issuer=" + URLEncoder.encode(issuer, "UTF8").replace("+", "%20");
    }
    catch (final UnsupportedEncodingException e) {
      throw new UnsupportedOperationException(e);
    }
  }

  /**
   * Returns the TOTP code for the secret key.
   * <p>
   * The TOTP code is guaranteed to be consistent for the same key, for a
   * duration of 30 seconds. After every 30 seconds, the time component is
   * updated.
   *
   * @param key Base32 encoded secret key (will be converted to upper-case, and
   *          allows whitespace, which will be removed).
   * @return The TOTP code for the secret key.
   * @throws IllegalArgumentException If {@code key} is null.
   */
  public static String getTOTPCode(final String key) {
    final String normalizedKey = key.replace(" ", "").toUpperCase();
    final byte[] bytes = Base32.decode(normalizedKey);
    final long time = System.currentTimeMillis() / 1000 / 30;
    final String hexTime = Long.toHexString(time);
    return TOTP.generateTOTP(Hexadecimal.encode(bytes), hexTime, 6, Hmac.SHA1);
  }

  private GAuth() {
  }
}