/* Copyright (c) 2020 OpenJAX
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

package org.openjax.security.nacl;

import static org.junit.Assert.*;

import org.junit.Test;

public class NaclUtilTest {
  private static void test(final NaclUtil naclUtil, final KeyPair keyPair1, final KeyPair keyPair2, final String data) {
    final byte[] encrypted = naclUtil.encrypt(keyPair1.getPublicKey(), keyPair2.getSecretKey(), data.getBytes());
    final byte[] decrypted = naclUtil.decrypt(keyPair2.getPublicKey(), keyPair1.getSecretKey(), encrypted);
    assertEquals(data, new String(decrypted));
  }

  private static void test(final NaclUtil nacl) {
    final KeyPair keyPair1 = nacl.keyPair();
    final KeyPair keyPair2 = nacl.keyPair();
    test(nacl, keyPair1, keyPair2, "test");
    test(nacl, keyPair1, keyPair2, "foo");
    test(nacl, keyPair1, keyPair2, "bar");
  }

  @Test
  public void testOriginal() {
    test(NaclUtil.ORIG);
  }

  @Test
  public void testFast() {
    test(NaclUtil.FAST);
  }
}