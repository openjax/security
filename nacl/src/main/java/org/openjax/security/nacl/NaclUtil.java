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

public enum NaclUtil {
  ORIG(new TweetNacl()),
  FAST(new TweetNaclFast());

  private final Nacl nacl;

  private NaclUtil(final Nacl nacl) {
    this.nacl = nacl;
  }

  public KeyPair keyPairForSignature() {
    return nacl.keyPairForSignature();
  }

  public KeyPair keyPair() {
    return nacl.keyPair();
  }

  public KeyPair keyPair(final byte[] secretKey) {
    return nacl.keyPair(secretKey);
  }

  public final KeyPair keyPairFromSeed(final byte[] seed) {
    return nacl.keyPairFromSeed(seed);
  }

  public Nacl.Box newBox(final byte[] publicKey, final byte[] privateKey) {
    return nacl.newBox(publicKey, privateKey);
  }

  public Nacl.Box newBox(final byte[] publicKey, final byte[] privateKey, final long nonce) {
    return nacl.newBox(publicKey, privateKey, nonce);
  }

  public Nacl.SecretBox newSecretBox(final byte[] key) {
    return nacl.newSecretBox(key);
  }

  public Nacl.SecretBox newSecretBox(final byte[] key, final long nonce) {
    return nacl.newSecretBox(key, nonce);
  }

  public Nacl.Signature newSignature(final byte[] theirPublicKey, final byte[] mySecretKey) {
    return nacl.newSignature(theirPublicKey, mySecretKey);
  }

  public void randombytes(final byte[] theNonce, final int noncelength) {
    nacl.randombytes(theNonce, noncelength);
  }

  public byte[] decrypt(final byte[] publicKey, final byte[] privateKey, final byte[] ciphertextWithNonce) {
    final byte[] nonce = new byte[TweetNaclFast.Box.nonceLength];
    System.arraycopy(ciphertextWithNonce, 0, nonce, 0, nonce.length);

    final byte[] ciphertext = new byte[ciphertextWithNonce.length - nonce.length];
    System.arraycopy(ciphertextWithNonce, nonce.length, ciphertext, 0, ciphertext.length);

    final Nacl.Box box = newBox(publicKey, privateKey);
    return box.open(ciphertext, nonce);
  }

  public byte[] encrypt(final byte[] publicKey, final byte[] privateKey, final byte[] data) {
    final Nacl.Box box = newBox(publicKey, privateKey);

    final byte[] nonce = TweetNaclFast.makeBoxNonce();
    final byte[] ciphertext = box.box(data, nonce);
    final byte[] ciphertextWithNonce = new byte[nonce.length + ciphertext.length];
    System.arraycopy(nonce, 0, ciphertextWithNonce, 0, nonce.length);
    System.arraycopy(ciphertext, 0, ciphertextWithNonce, nonce.length, ciphertext.length);
    return ciphertextWithNonce;
  }
}