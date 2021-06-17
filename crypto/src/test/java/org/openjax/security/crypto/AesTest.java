/* Copyright (c) 2021 OpenJAX
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

import java.util.Base64;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

public class AesTest {
  private static final String data = "The quick brown fox jumps over the lazy dog";
  private static final String password = "P@55w0rd!";

  // printf 'The quick brown fox jumps over the lazy dog' | openssl enc -aes-256-cbc -a -k 'P@55w0rd!' -p
  private static final String saltFromOpenSSL = "06BF16E22083D464";
  private static final String encFromOpenSSL = "U2FsdGVkX18GvxbiIIPUZKjkbVGpi/x8bJ2+oxYMDaNAX5VwWXTdFA+KA/+V7EbU\n9xaE0L8Y0lgAr79JXRE83A==";

  @Test
  public void testEncryptOpenSSL256CBC() throws Exception {
    final byte[] enc = AES.OPEN_SSL_256_CBC.encrypt(data.getBytes(), password, DatatypeConverter.parseHexBinary(saltFromOpenSSL));
    assertEquals(encFromOpenSSL.replaceAll("\\s", ""), Base64.getEncoder().encodeToString(enc));
  }

  @Test
  public void testDecryptOpenSSL256CBC() throws Exception {
    assertEquals(data, AES.OPEN_SSL_256_CBC.decryptToString(encFromOpenSSL, password));
  }
}