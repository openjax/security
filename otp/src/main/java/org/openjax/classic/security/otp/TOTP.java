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

package org.openjax.classic.security.otp;

import org.openjax.classic.math.FastMath;
import org.openjax.classic.security.api.Hmac;
import org.openjax.classic.util.Hexadecimal;
import org.openjax.classic.util.Strings;

public final class TOTP {
  /**
   * Generates a TOTP for the given {@code key} and {@code time}.
   *
   * @param key The hex encoded shared secret.
   * @param time A hex encoded value that reflects a time.
   * @param length The number of digits to return.
   * @param hmac The crypto function.
   * @return A numeric String in base 10 that includes {@code length} number
   *         of digits.
   * @throws IllegalArgumentException If {@code key} is invalid.
   */
  public static String generateTOTP(final String key, String time, final int length, final Hmac hmac) {
    if (time.length() % 2 == 1)
      time = "0" + time;

    final int start;
    final byte[] data;
    final int len = time.length() / 2;
    if (len < 8) {
      start = 8 - len;
      data = new byte[8];
    }
    else {
      start = 0;
      data = new byte[len];
    }

    Hexadecimal.decode(time, data, start);
    final byte[] hash = hmac.generate(Hexadecimal.decode(key), data);

    final int offset = hash[hash.length - 1] & 0xf;
    final int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

    final String otp = Long.toString(binary % FastMath.pow(10, length));
    return otp.length() < length ? Strings.repeat("0", length - otp.length()) + otp : otp;
  }

  private TOTP() {
  }
}