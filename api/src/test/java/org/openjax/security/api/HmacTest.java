/* Copyright (c) 2019 OpenJAX
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

package org.openjax.security.api;

import java.math.BigInteger;

import org.junit.Assert;
import org.junit.Test;

public class HmacTest {
  private static void assertEquals(final Hmac hmac, final byte[] data, final String key, final String expected) {
    final byte[] code = hmac.generateCode(new BigInteger(key, 16).toByteArray(), data);
    Assert.assertEquals(expected, new BigInteger(1, code).toString(16).toUpperCase());
  }

  @Test
  public void test() {
    final byte[] data = "hello world".getBytes();
    assertEquals(Hmac.SHA1, data, "D4394C7D51ED5B46D669F1783C6C715DCB7C77A9188D5A8CB6162B8E6EC23DDF279A4F1DC722B351596BE1DFFDEBAC805D617F4ED9665E0FB51866B0E7FDF7EF", "DA3A60D76972965C0F77D7A5375AFF6FE8F167B0");
    assertEquals(Hmac.SHA256, data, "D01FAA44B347FFBC5508BC8CAE3C55DC86B9E438E181DE383D7DEE8B1051D1CE", "A9DBCACB528754A34DCFC567431924BCAA794394AB884B91EF3863ED982A9C0B");
    assertEquals(Hmac.SHA512, data, "66C9F698B7FA7EF57D088B66181803A98D0FFCA68E5FCC85619F4C5433C61DD5689BDA17E4D9FB07C245E6A465CDC9A186D5D916245645F4CBF5C63980699E81", "552C862D645F6D8B87FDC75F1A5426DBC3ABEB0AE929A1DAF5A094825FF45D358626A486AEA6D556564BB10276464ECDE9635C9966FD31E8EE6F1029F7670218");
  }
}