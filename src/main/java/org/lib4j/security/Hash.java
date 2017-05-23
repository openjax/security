/* Copyright (c) 2009 lib4j
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

package org.lib4j.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public enum Hash {
  MD2("MD2"),
  MD5("MD5"),
  SHA1("SHA-1"),
  SHA224("SHA-224"),
  SHA256("SHA-256"),
  SHA384("SHA-384"),
  SHA512("SHA-512");

  private ThreadLocal<MessageDigest> messageDigest = null;

  Hash(final String algorithm) {
    messageDigest = new ThreadLocal<MessageDigest>() {
      @Override
      protected MessageDigest initialValue() {
        try {
          return MessageDigest.getInstance(algorithm);
        }
        catch (final NoSuchAlgorithmException e) {
          throw new ExceptionInInitializerError(e);
        }
      }
    };
  }

  public byte[] encode(final String string) {
    messageDigest.get().update(string.getBytes());
    return messageDigest.get().digest();
  }
}