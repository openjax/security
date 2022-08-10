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

import static org.junit.Assert.*;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GAuthTest {
  private static final Logger logger = LoggerFactory.getLogger(GAuthTest.class);

  private static void test(final String account, final String issuer) {
    final String secretKey = GAuth.generateRandomSecretKey();
    final String barCode = GAuth.getBarCode(secretKey, account, issuer);
    logger.info("open \"https://codepen.io/davidshimjs/pen/NdBYrg\"\n" + barCode);

    // FIXME: This test can break, because the TOTP code changes every 30
    // FIXME: seconds, and the test can by chance happen to cross this moment.
    String lastCode = null;
    for (int i = 0; i < 10; ++i) { // [N]
      final String code = GAuth.getTOTPCode(secretKey);
      if (lastCode != null && !code.equals(lastCode))
        fail(code);

      lastCode = code;
      try {
        Thread.sleep(10);
      }
      catch (final InterruptedException e) {
      }
    }
  }

  @Test
  public void test() {
    test("user@example.com", "Example Company");
  }
}