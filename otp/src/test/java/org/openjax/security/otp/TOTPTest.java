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

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.junit.Test;
import org.libj.lang.Strings;
import org.openjax.security.crypto.Hmac;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TOTPTest {
  private static final Logger logger = LoggerFactory.getLogger(TOTPTest.class);

  @Test
  // FIXME: Implement asserts
  public void test() {
    // Seed for HMAC-SHA1 - 20 bytes
    final String seed = "3132333435363738393031323334353637383930";
    // Seed for HMAC-SHA256 - 32 bytes
    final String seed32 = "3132333435363738393031323334353637383930313233343536373839303132";
    // Seed for HMAC-SHA512 - 64 bytes
    final String seed64 = "31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334";

    final DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

    logger.info("+---------------+-----------------------+------------------+--------+--------+");
    logger.info("|  Time(sec)    |   Time (UTC format)   | Value of T(Hex)  |  TOTP  | Mode   |");
    logger.info("+---------------+-----------------------+------------------+--------+--------+");

    final long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
    for (int i = 0; i < times.length; i++) {
      final long time = times[i] / 30;
      String steps = Long.toHexString(time).toUpperCase();
      if (steps.length() < 16)
        steps = Strings.repeat("0", 16 - steps.length()) + steps;

      final String fmtTime = String.format("%1$-11s", times[i]);
      final String utcTime = dateFormat.format(new Date(times[i] * 1000));
      logger.info("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |" + TOTP.generateTOTP(seed, steps, 8, Hmac.SHA1) + "| SHA1   |");
      logger.info("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |" + TOTP.generateTOTP(seed32, steps, 8, Hmac.SHA256) + "| SHA256 |");
      logger.info("|  " + fmtTime + "  |  " + utcTime + "  | " + steps + " |" + TOTP.generateTOTP(seed64, steps, 8, Hmac.SHA512) + "| SHA512 |");
      logger.info("+---------------+-----------------------+------------------+--------+--------+");
    }
  }
}