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

public final class NaclUtil {
  public static byte[] decrypt(final byte[] publicKey, final byte[] privateKey, final byte[] ciphertextWithNonce) {
    final byte[] nonce = new byte[TweetNaclFast.Box.nonceLength];
    System.arraycopy(ciphertextWithNonce, 0, nonce, 0, nonce.length);

    final byte[] ciphertext = new byte[ciphertextWithNonce.length - nonce.length];
    System.arraycopy(ciphertextWithNonce, nonce.length, ciphertext, 0, ciphertext.length);

    final TweetNaclFast.Box box = new TweetNaclFast.Box(publicKey, privateKey);
    return box.open(ciphertext, nonce);
  }

  public static byte[] encrypt(final byte[] publicKey, final byte[] privateKey, final byte[] data) {
    final TweetNaclFast.Box box = new TweetNaclFast.Box(publicKey, privateKey);

    final byte[] nonce = TweetNaclFast.makeBoxNonce();
    final byte[] ciphertext = box.box(data, nonce);
    final byte[] ciphertextWithNonce = new byte[nonce.length + ciphertext.length];
    System.arraycopy(nonce, 0, ciphertextWithNonce, 0, nonce.length);
    System.arraycopy(ciphertext, 0, ciphertextWithNonce, nonce.length, ciphertext.length);
    return ciphertextWithNonce;
  }

  private NaclUtil() {
  }
}