/* Copyright (c) 2018 OpenJAX
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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * An enum of common Hashed Message Authentication Code algorithms.
 */
public enum Hmac {
  SHA1("HmacSHA1"),
  SHA256("HmacSHA256"),
  SHA384("HmacSHA384"),
  SHA512("HmacSHA512");

  private final ThreadLocal<Mac> mac;
  private final ThreadLocal<KeyGenerator> keyGenerator;

  Hmac(final String algorithm) {
    this.mac = ThreadLocal.withInitial(() -> {
      try {
        return Mac.getInstance(algorithm);
      }
      catch (final NoSuchAlgorithmException e) {
        throw new UnsupportedOperationException(e);
      }
    });
    this.keyGenerator = ThreadLocal.withInitial(() -> {
      try {
        return KeyGenerator.getInstance(algorithm);
      }
      catch (final NoSuchAlgorithmException e) {
        throw new UnsupportedOperationException(e);
      }
    });
  }

  /**
   * Generates a secret key with this Hmac algorithm.
   *
   * @implNote This method uses JCE to provide the crypto algorithm.
   * @return A new secret key.
   */
  public SecretKey generateKey() {
    return keyGenerator.get().generateKey();
  }

  /**
   * Generate the Hashed Message Authentication Code for the given {@code key} and {@code seed}.
   *
   * @param key The HMAC key.
   * @param seed The seed to be used.
   * @return The Hashed Message Authentication Code.
   * @throws NullPointerException If {@code key} or {@code seed} is null.
   * @throws IllegalArgumentException If {@code key} is not appropriate for this HMAC.
   * @implNote This method uses JCE to provide the crypto algorithm.
   */
  public byte[] generateCode(final byte[] key, final byte[] seed) {
    Objects.requireNonNull(seed);
    try {
      final SecretKeySpec secretKey = new SecretKeySpec(key, "RAW");
      final Mac mac = this.mac.get();
      mac.init(secretKey);
      return mac.doFinal(seed);
    }
    catch (final InvalidKeyException e) {
      throw new IllegalArgumentException(e);
    }
  }
}