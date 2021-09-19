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

import java.nio.charset.StandardCharsets;

public abstract class Hash {
  /** Length of hash in bytes. */
  static final int hashLength = 64;

  public static final Hash Tweet = new HashTweet();
  public static final Hash TweetFast = new HashTweetFast();

  /**
   * Returns the SHA-512 hash of the message.
   *
   * @param message The message.
   * @return The SHA-512 hash of the message.
   */
  public final byte[] sha512(final byte[] message) {
    if (!(message != null && message.length > 0))
      return null;

    final byte[] out = new byte[hashLength];
    cryptoHash(out, message);
    return out;
  }

  public final byte[] sha512(final String message) {
    return sha512(message.getBytes(StandardCharsets.UTF_8));
  }

  public abstract int cryptoHash(byte[] out, byte[] m);
}