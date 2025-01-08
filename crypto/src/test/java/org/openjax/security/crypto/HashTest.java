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

package org.openjax.security.crypto;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.zip.CRC32;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.libj.lang.Strings;
import org.libj.util.zip.CRC64;

public class HashTest {
  private static void assertEquals(final Hash hash, final byte[] data, final String expected) {
    final byte[] bytes = hash.encode(data);
    Assert.assertEquals(expected, expected.toUpperCase(), new BigInteger(1, bytes).toString(16).toUpperCase());

    final int asInt = hash.encodeAsInt(data);
    Assert.assertEquals(expected, expected.substring(Math.max(0, expected.length() - 8)).replaceAll("^0+", ""), Integer.toHexString(asInt).toUpperCase().replaceAll("^0+", ""));

    final long asLong = hash.encodeAsLong(data);
    Assert.assertEquals(expected, expected.substring(Math.max(0, expected.length() - 16)).replaceAll("^0+", ""), Long.toHexString(asLong).toUpperCase().replaceAll("^0+", ""));
  }

  private static final int numtests = 10_000;

  @Test
  public void testCRC32() {
    for (int i = 0; i < numtests; ++i) {
      final byte[] data = Strings.getRandomAlphaNumeric(i % 256).getBytes();
      final CRC32 crc = new CRC32();
      crc.update(data);
      final String str = Long.toHexString(crc.getValue()).toUpperCase();
      assertEquals(Hash.CRC32, data, str);
    }

    byte i = -128;
    do {
      final byte[] h0 = Hash.CRC32.encode(i);
      final byte[] h1 = Hash.CRC32.encode(new byte[] {i++});
      assertArrayEquals(h0, h1);
    }
    while (i != -128);
  }

  @Test
  @Ignore("With -Xcomp, java wins. Without -Xcomp, java loses.")
  public void testCRC64Performance() {
    long t0 = System.currentTimeMillis();
    for (int i = 0; i < numtests; ++i) {
      final byte[] data = String.valueOf(i).getBytes();
      final CRC64 crc = new CRC64();
      crc.update(data);
      crc.getValue();
    }

    final long java = System.currentTimeMillis() - t0;

    t0 = System.currentTimeMillis();
    for (int i = 0; i < numtests; ++i) {
      final byte[] data = String.valueOf(i).getBytes();
      Hash.CRC64.encodeAsLong(data);
    }

    final long custom = System.currentTimeMillis() - t0;
    System.err.println(java);
    System.err.println(custom);
  }

  @Test
  public void testCRC64() {
    for (int i = 0; i < numtests; ++i) {
      final byte[] data = String.valueOf(i).getBytes();
      final CRC64 crc = new CRC64();
      crc.update(data);
      final String str = Long.toHexString(crc.getValue()).toUpperCase();
      assertEquals(Hash.CRC64, data, str);
    }

    byte i = -128;
    do {
      final byte[] h0 = Hash.CRC64.encode(i);
      final byte[] h1 = Hash.CRC64.encode(new byte[] {i++});
      assertArrayEquals(h0, h1);
    }
    while (i != -128);
  }

  @Test
  public void test() {
    final byte[] data = "hello world".getBytes();
    assertEquals(Hash.CRC32, data, "D4A1185");
    assertEquals(Hash.CRC64, data, "12511F272D9BC22A");
    assertEquals(Hash.MD2, data, "D9CCE882EE690A5C1CE70BEFF3A78C77");
    assertEquals(Hash.MD5, data, "5EB63BBBE01EEED093CB22BB8F5ACDC3");
    assertEquals(Hash.SHA1, data, "2AAE6C35C94FCFB415DBE95F408B9CE91EE846ED");
    assertEquals(Hash.SHA224, data, "2F05477FC24BB4FAEFD86517156DAFDECEC45B8AD3CF2522A563582B");
    assertEquals(Hash.SHA256, data, "B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9");
    assertEquals(Hash.SHA384, data, "FDBD8E75A67F29F701A4E040385E2E23986303EA10239211AF907FCBB83578B3E417CB71CE646EFD0819DD8C088DE1BD");
    assertEquals(Hash.SHA512, data, "309ECC489C12D6EB4CC40F50C902F2B4D0ED77EE511A7C7A9BCD3CA86D4CD86F989DD35BC5FF499670DA34255B45B0CFD830E81F605DCF7DC5542E93AE9CD76F");
  }
}