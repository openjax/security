/* Copyright (c) 2009 OpenJAX
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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * An enum of common hash functions.
 */
public enum Hash {
  MD2("MD2"),
  MD5("MD5"),
  SHA1("SHA-1"),
  SHA224("SHA-224"),
  SHA256("SHA-256"),
  SHA384("SHA-384"),
  SHA512("SHA-512");

  private final ThreadLocal<MessageDigest> messageDigest;

  Hash(final String algorithm) {
    this.messageDigest = new ThreadLocal<MessageDigest>() {
      @Override
      protected MessageDigest initialValue() {
        try {
          return MessageDigest.getInstance(algorithm);
        }
        catch (final NoSuchAlgorithmException e) {
          throw new UnsupportedOperationException(e);
        }
      }
    };
  }

  /**
   * Encodes the specified byte array with this hash function.
   *
   * @param bytes The byte array.
   * @return The product of applying this hash function to the specified byte
   *         array.
   * @throws NullPointerException If the specified byte array is null.
   */
  public byte[] encode(final byte[] bytes) {
    messageDigest.get().update(bytes);
    return messageDigest.get().digest();
  }

  /**
   * Encodes the specified string with this hash function.
   *
   * @param string The string.
   * @return The product of applying this hash function to the specified string.
   * @throws NullPointerException If the specified string is null.
   */
  public byte[] encode(final String string) {
    return encode(string.getBytes());
  }
}