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

package org.openjax.security.nacl;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * TweetNacl.c Java Port
 */
public final class TweetNaclFast {
  /**
   * Box algorithm, Public-key authenticated encryption
   */
  public static final class Box {
    private final AtomicLong nonce;
    private final byte[] theirPublicKey;
    private final byte[] mySecretKey;
    private byte[] sharedKey;

    public Box(final byte[] theirPublicKey, final byte[] mySecretKey) {
      this(theirPublicKey, mySecretKey, 68);
    }

    public Box(final byte[] theirPublicKey, final byte[] mySecretKey, final long nonce) {
      this.theirPublicKey = theirPublicKey;
      this.mySecretKey = mySecretKey;
      this.nonce = new AtomicLong(nonce);
      before();
    }

    public void setNonce(final long nonce) {
      this.nonce.set(nonce);
    }

    public long getNonce() {
      return this.nonce.get();
    }

    public long incrNonce() {
      return this.nonce.incrementAndGet();
    }

    private byte[] generateNonce() {
      // generate nonce
      final long nonce = this.nonce.get();
      final byte[] n = new byte[nonceLength];
      for (int i = 0; i < nonceLength; i += 8) {
        n[i + 0] = (byte)(nonce >>> 0);
        n[i + 1] = (byte)(nonce >>> 8);
        n[i + 2] = (byte)(nonce >>> 16);
        n[i + 3] = (byte)(nonce >>> 24);
        n[i + 4] = (byte)(nonce >>> 32);
        n[i + 5] = (byte)(nonce >>> 40);
        n[i + 6] = (byte)(nonce >>> 48);
        n[i + 7] = (byte)(nonce >>> 56);
      }

      return n;
    }

    /**
     * Encrypt and authenticates message using peer's public key, our secret
     * key, final and the given nonce, which must be unique for each distinct
     * message for a key pair.
     *
     * @param message The message.
     * @return An encrypted and authenticated message, which is
     *         nacl.box.overheadLength longer than the original message.
     */
    public byte[] box(final byte[] message) {
      return message == null ? null : box(message, 0, message.length);
    }

    public byte[] box(final byte[] message, final int moff) {
      if (message == null || message.length <= moff)
        return null;

      return box(message, moff, message.length - moff);
    }

    public byte[] box(final byte[] message, final int moff, final int mlen) {
      if (message == null || message.length < moff + mlen)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return after(message, moff, mlen);
    }

    /**
     * Encrypt and authenticates message using peer's public key, our secret
     * key, final and the given nonce, which must be unique for each distinct
     * message for a key pair.
     *
     * @param message The message.
     * @param nonce The nonce.
     * @return An encrypted and authenticated message, which is
     *         nacl.secretbox.overheadLength longer than the original message.
     */
    public byte[] box(final byte[] message, final byte[] nonce) {
      return message == null ? null : box(message, 0, message.length, nonce);
    }

    public byte[] box(final byte[] message, final int moff, final byte[] nonce) {
      if (message == null || message.length <= moff)
        return null;

      return box(message, moff, message.length - moff, nonce);
    }

    public byte[] box(final byte[] message, final int moff, final int mlen, final byte[] nonce) {
      if (message == null || message.length < moff + mlen || nonce == null || nonce.length != nonceLength)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return after(message, moff, mlen, nonce);
    }

    /**
     * Authenticates and decrypts the given box with peer's public key, our
     * secret key, final and the given nonce.
     *
     * @param box The box.
     * @return The original message, or null if authentication fails.
     */
    public byte[] open(final byte[] box) {
      if (box == null)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return open_after(box, 0, box.length);
    }

    public byte[] open(final byte[] box, final int boxoff) {
      if (box == null || box.length <= boxoff)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return open_after(box, boxoff, box.length - boxoff);
    }

    public byte[] open(final byte[] box, final int boxoff, final int boxlen) {
      if (box == null || box.length < boxoff + boxlen)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return open_after(box, boxoff, boxlen);
    }

    /**
     * Authenticates and decrypts the given box with peer's public key, our
     * secret key, and the given nonce.
     *
     * @param box The box.
     * @param nonce The nonce.
     * @return The original message, or null if authentication fails.
     */
    public byte[] open(final byte[] box, final byte[] nonce) {
      if (box == null || nonce == null || nonce.length != nonceLength)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return open_after(box, 0, box.length, nonce);
    }

    public byte[] open(final byte[] box, final int boxoff, final byte[] nonce) {
      if (box == null || box.length <= boxoff || nonce == null || nonce.length != nonceLength)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return open_after(box, boxoff, box.length - boxoff, nonce);
    }

    public byte[] open(final byte[] box, final int boxoff, final int boxlen, final byte[] nonce) {
      if (box == null || box.length < boxoff + boxlen || nonce == null || nonce.length != nonceLength)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return open_after(box, boxoff, boxlen, nonce);
    }

    /**
     * @return A precomputed shared key which can be used in nacl.box.after and
     *         nacl.box.open.after.
     */
    public byte[] before() {
      if (this.sharedKey == null) {
        this.sharedKey = new byte[sharedKeyLength];
        cryptoBoxBeforeNm(this.sharedKey, this.theirPublicKey, this.mySecretKey);
      }

      return this.sharedKey;
    }

    /**
     * Same as nacl.box, but uses a shared key precomputed with nacl.box.before.
     *
     * @param message The message.
     * @param moff The m offset.
     * @param mlen The m length.
     * @return An encrypted and authenticated message, which is
     *         nacl.box.overheadLength longer than the original message.
     */
    public byte[] after(final byte[] message, final int moff, final int mlen) {
      return after(message, moff, mlen, generateNonce());
    }

    /**
     * Same as nacl.box, but uses a shared key precomputed with nacl.box.before,
     * and passes a nonce explicitly.
     *
     * @param message The message.
     * @param moff The m offset.
     * @param mlen The m length.
     * @param nonce The nonce.
     * @return An encrypted and authenticated message, which is
     *         nacl.box.overheadLength longer than the original message.
     */
    public byte[] after(final byte[] message, final int moff, final int mlen, final byte[] nonce) {
      // check message
      if (!(message != null && message.length >= (moff + mlen) && nonce != null && nonce.length == nonceLength))
        return null;

      // message buffer
      final byte[] m = new byte[mlen + zerobytesLength];

      // cipher buffer
      final byte[] c = new byte[m.length];

      for (int i = 0; i < mlen; ++i)
        m[i + zerobytesLength] = message[i + moff];

      if (0 != cryptoBoxAfterNm(c, m, m.length, nonce, sharedKey))
        return null;

      final byte[] ret = new byte[c.length - boxzerobytesLength];
      for (int i = 0; i < ret.length; ++i)
        ret[i] = c[i + boxzerobytesLength];

      return ret;
    }

    /**
     * Same as nacl.box.open, but uses a shared key precomputed with
     * nacl.box.before.
     *
     * @param box The box.
     * @param boxoff The box offset.
     * @param boxlen The box length.
     * @return An encrypted and authenticated message, which is
     *         nacl.box.overheadLength longer than the original message.
     */
    public byte[] open_after(final byte[] box, final int boxoff, final int boxlen) {
      return open_after(box, boxoff, boxlen, generateNonce());
    }

    public byte[] open_after(final byte[] box, final int boxoff, final int boxlen, final byte[] nonce) {
      // check message
      if (!(box != null && box.length >= (boxoff + boxlen) && boxlen >= boxzerobytesLength))
        return null;

      // cipher buffer
      final byte[] c = new byte[boxlen + boxzerobytesLength];

      // message buffer
      final byte[] m = new byte[c.length];

      for (int i = 0; i < boxlen; ++i)
        c[i + boxzerobytesLength] = box[i + boxoff];

      if (cryptoBoxOpenAfterNm(m, c, c.length, nonce, sharedKey) != 0)
        return null;

      final byte[] ret = new byte[m.length - zerobytesLength];
      for (int i = 0; i < ret.length; ++i)
        ret[i] = m[i + zerobytesLength];

      return ret;
    }

    /** Length of public key in bytes. */
    public static final int publicKeyLength = 32;

    /** Length of secret key in bytes. */
    public static final int secretKeyLength = 32;

    /** Length of precomputed shared key in bytes. */
    public static final int sharedKeyLength = 32;

    /** Length of nonce in bytes. */
    public static final int nonceLength = 24;

    /** Zero bytes in case box. */
    public static final int zerobytesLength = 32;

    /** Zero bytes in case open box. */
    public static final int boxzerobytesLength = 16;

    /** Length of overhead added to box compared to original message. */
    public static final int overheadLength = 16;

    /**
     * @return A new random key pair for box and returns it as an object with
     *         publicKey and secretKey members.
     */
    public static KeyPair keyPair() {
      final KeyPair kp = new KeyPair(publicKeyLength, secretKeyLength);
      cryptoBoxKeyPair(kp.getPublicKey(), kp.getSecretKey());
      return kp;
    }

    public static KeyPair keyPair(final byte[] secretKey) {
      final KeyPair kp = new KeyPair(publicKeyLength, secretKeyLength);
      final byte[] sk = kp.getSecretKey();
      final byte[] pk = kp.getPublicKey();

      // copy sk
      for (int i = 0; i < sk.length; ++i)
        sk[i] = secretKey[i];

      cryptoScalarMultBase(pk, sk);
      return kp;
    }
  }

  /**
   * Secret Box algorithm, secret key
   */
  public static final class SecretBox {
    private final AtomicLong nonce;

    private final byte[] key;

    public SecretBox(final byte[] key) {
      this(key, 68);
    }

    public SecretBox(final byte[] key, final long nonce) {
      this.key = key;

      this.nonce = new AtomicLong(nonce);
    }

    public void setNonce(final long nonce) {
      this.nonce.set(nonce);
    }

    public long getNonce() {
      return this.nonce.get();
    }

    public long incrNonce() {
      return this.nonce.incrementAndGet();
    }

    private byte[] generateNonce() {
      // generate nonce
      final long nonce = this.nonce.get();
      byte[] n = new byte[nonceLength];
      for (int i = 0; i < nonceLength; i += 8) {
        n[i + 0] = (byte)(nonce >>> 0);
        n[i + 1] = (byte)(nonce >>> 8);
        n[i + 2] = (byte)(nonce >>> 16);
        n[i + 3] = (byte)(nonce >>> 24);
        n[i + 4] = (byte)(nonce >>> 32);
        n[i + 5] = (byte)(nonce >>> 40);
        n[i + 6] = (byte)(nonce >>> 48);
        n[i + 7] = (byte)(nonce >>> 56);
      }

      return n;
    }

    /**
     * Encrypt and authenticates message using the key and the nonce. The nonce
     * must be unique for each distinct message for this key.
     *
     * @param message The message.
     * @return An encrypted and authenticated message, which is
     *         nacl.secretbox.overheadLength longer than the original message.
     */
    public byte[] box(final byte[] message) {
      return message == null ? null : box(message, 0, message.length);
    }

    public byte[] box(final byte[] message, final int moff) {
      if (!(message != null && message.length > moff))
        return null;

      return box(message, moff, message.length - moff);
    }

    public byte[] box(final byte[] message, final int moff, final int mlen) {
      // check message
      if (!(message != null && message.length >= (moff + mlen)))
        return null;

      return box(message, moff, message.length - moff, generateNonce());
    }

    public byte[] box(final byte[] message, final byte[] nonce) {
      if (message == null)
        return null;

      return box(message, 0, message.length, nonce);
    }

    public byte[] box(final byte[] message, final int moff, final byte[] nonce) {
      if (!(message != null && message.length > moff))
        return null;

      return box(message, moff, message.length - moff, nonce);
    }

    public byte[] box(final byte[] message, final int moff, final int mlen, final byte[] nonce) {
      // check message
      if (!(message != null && message.length >= (moff + mlen) && nonce != null && nonce.length == nonceLength))
        return null;

      // message buffer
      final byte[] m = new byte[mlen + zerobytesLength];

      // cipher buffer
      final byte[] c = new byte[m.length];

      for (int i = 0; i < mlen; ++i)
        m[i + zerobytesLength] = message[i + moff];

      if (0 != cryptoSecretBox(c, m, m.length, nonce, key))
        return null;

      // TBD optimizing ...
      final byte[] ret = new byte[c.length - boxzerobytesLength];
      for (int i = 0; i < ret.length; ++i)
        ret[i] = c[i + boxzerobytesLength];

      return ret;
    }

    /**
     * Authenticates and decrypts the given secret box using the key and the
     * nonce.
     *
     * @param box The box.
     * @return The original message, or null if authentication fails.
     */
    public byte[] open(final byte[] box) {
      return box == null ? null : open(box, 0, box.length);
    }

    public byte[] open(final byte[] box, final int boxoff) {
      if (!(box != null && box.length > boxoff))
        return null;

      return open(box, boxoff, box.length - boxoff);
    }

    public byte[] open(final byte[] box, final int boxoff, final int boxlen) {
      // check message
      if (!(box != null && box.length >= (boxoff + boxlen) && boxlen >= boxzerobytesLength))
        return null;

      return open(box, boxoff, box.length - boxoff, generateNonce());
    }

    public byte[] open(final byte[] box, final byte[] nonce) {
      if (box == null)
        return null;

      return open(box, 0, box.length, nonce);
    }

    public byte[] open(final byte[] box, final int boxoff, final byte[] nonce) {
      if (!(box != null && box.length > boxoff))
        return null;

      return open(box, boxoff, box.length - boxoff, nonce);
    }

    public byte[] open(final byte[] box, final int boxoff, final int boxlen, final byte[] nonce) {
      // check message
      if (!(box != null && box.length >= (boxoff + boxlen) && boxlen >= boxzerobytesLength && nonce != null && nonce.length == nonceLength))
        return null;

      // cipher buffer
      final byte[] c = new byte[boxlen + boxzerobytesLength];

      // message buffer
      final byte[] m = new byte[c.length];

      for (int i = 0; i < boxlen; ++i)
        c[i + boxzerobytesLength] = box[i + boxoff];

      if (0 != cryptoSecretBoxOpen(m, c, c.length, nonce, key))
        return null;

      final byte[] ret = new byte[m.length - zerobytesLength];
      for (int i = 0; i < ret.length; ++i)
        ret[i] = m[i + zerobytesLength];

      return ret;
    }

    /** Length of key in bytes. */
    public static final int keyLength = 32;

    /** Length of nonce in bytes. */
    public static final int nonceLength = 24;

    /** Length of overhead added to secret box compared to original message. */
    public static final int overheadLength = 16;

    /** Zero bytes in case box. */
    public static final int zerobytesLength = 32;

    /** Zero bytes in case open box. */
    public static final int boxzerobytesLength = 16;
  }

  /**
   * Scalar multiplication, Implements curve25519.
   */
  public static final class ScalarMult {
    /**
     * Multiplies an integer n by a group element p.
     *
     * @param n The integer.
     * @param p The group element.
     * @return The resulting group element.
     */
    public static byte[] scalseMult(final byte[] n, final byte[] p) {
      if (!(n.length == scalarLength && p.length == groupElementLength))
        return null;

      final byte[] q = new byte[scalarLength];
      cryptoScalarMult(q, n, p);
      return q;
    }

    /**
     * Multiplies an integer n by a standard group element.
     *
     * @param n The integer.
     * @return The resulting group element.
     */
    public static byte[] scalseMultBase(final byte[] n) {
      if (!(n.length == scalarLength))
        return null;

      final byte[] q = new byte[scalarLength];
      cryptoScalarMultBase(q, n);
      return q;
    }

    /**
     * Length of scalar in bytes.
     */
    public static final int scalarLength = 32;

    /**
     * Length of group element in bytes.
     */
    public static final int groupElementLength = 32;
  }

  /**
   * Signature algorithm, Implements ed25519.
   */
  public static final class Signature {
    private byte[] theirPublicKey;
    private byte[] mySecretKey;

    public Signature(final byte[] theirPublicKey, final byte[] mySecretKey) {
      this.theirPublicKey = theirPublicKey;
      this.mySecretKey = mySecretKey;
    }

    /**
     * Signs the message using the secret key.
     *
     * @param message The message.
     * @return A signed message.
     */
    public byte[] sign(final byte[] message) {
      return message == null ? null : sign(message, 0, message.length);
    }

    public byte[] sign(final byte[] message, final int moff) {
      if (!(message != null && message.length > moff))
        return null;

      return sign(message, moff, message.length - moff);
    }

    public byte[] sign(final byte[] message, final int moff, final int mlen) {
      // check message
      if (!(message != null && message.length >= (moff + mlen)))
        return null;

      // signed message
      byte[] sm = new byte[mlen + signatureLength];
      cryptoSign(sm, -1, message, moff, mlen, mySecretKey);
      return sm;
    }

    /**
     * Verifies the signed message.
     *
     * @param signedMessage The signed message.
     * @return The message without signature, or null if verification fails.
     */
    public byte[] open(final byte[] signedMessage) {
      return signedMessage == null ? null : open(signedMessage, 0, signedMessage.length);
    }

    public byte[] open(final byte[] signedMessage, final int smoff) {
      if (!(signedMessage != null && signedMessage.length > smoff))
        return null;

      return open(signedMessage, smoff, signedMessage.length - smoff);
    }

    public byte[] open(final byte[] signedMessage, final int smoff, final int smlen) {
      // check sm length
      if (!(signedMessage != null && signedMessage.length >= (smoff + smlen) && smlen >= signatureLength))
        return null;

      // temp buffer
      byte[] tmp = new byte[smlen];

      if (0 != cryptoSignOpen(tmp, -1, signedMessage, smoff, smlen, theirPublicKey))
        return null;

      // message
      byte[] msg = new byte[smlen - signatureLength];
      for (int i = 0; i < msg.length; ++i)
        msg[i] = signedMessage[smoff + i + signatureLength];

      return msg;
    }

    /**
     * Signs the message using the secret key.
     *
     * @param message The message.
     * @return The signature.
     */
    public byte[] detached(final byte[] message) {
      byte[] signedMsg = this.sign(message);
      byte[] sig = new byte[signatureLength];
      for (int i = 0; i < sig.length; ++i)
        sig[i] = signedMsg[i];

      return sig;
    }

    /**
     * Verifies the signature for the message.
     *
     * @param message The message.
     * @param signature The signature.
     * @return {@code true} if verification succeeded or {@code false} if it
     *         failed.
     */
    public boolean detached_verify(final byte[] message, final byte[] signature) {
      if (signature.length != signatureLength)
        return false;

      if (theirPublicKey.length != publicKeyLength)
        return false;

      final byte[] sm = new byte[signatureLength + message.length];
      final byte[] m = new byte[signatureLength + message.length];
      for (int i = 0; i < signatureLength; ++i)
        sm[i] = signature[i];

      for (int i = 0; i < message.length; ++i)
        sm[i + signatureLength] = message[i];

      return (cryptoSignOpen(m, -1, sm, 0, sm.length, theirPublicKey) >= 0);
    }

    /**
     * Signs the message using the secret key.
     *
     * @return A signed message.
     */
    public static KeyPair keyPair() {
      final KeyPair kp = new KeyPair(publicKeyLength, secretKeyLength);
      cryptoSignKeyPair(kp.getPublicKey(), kp.getSecretKey(), false);
      return kp;
    }

    public static KeyPair keyPair(final byte[] secretKey) {
      final KeyPair kp = new KeyPair(publicKeyLength, secretKeyLength);
      final byte[] pk = kp.getPublicKey();
      final byte[] sk = kp.getSecretKey();

      // copy sk
      for (int i = 0; i < kp.getSecretKey().length; ++i)
        sk[i] = secretKey[i];

      // copy pk from sk
      for (int i = 0; i < kp.getPublicKey().length; ++i)
        pk[i] = secretKey[32 + i]; // hard-copy

      return kp;
    }

    public static KeyPair keyPairFromSeed(final byte[] seed) {
      final KeyPair kp = new KeyPair(publicKeyLength, secretKeyLength);
      final byte[] pk = kp.getPublicKey();
      final byte[] sk = kp.getSecretKey();

      // copy sk
      for (int i = 0; i < seedLength; ++i)
        sk[i] = seed[i];

      // generate pk from sk
      cryptoSignKeyPair(pk, sk, true);

      return kp;
    }

    /** Length of signing public key in bytes. */
    public static final int publicKeyLength = 32;

    /** Length of signing secret key in bytes. */
    public static final int secretKeyLength = 64;

    /** Length of seed for nacl.sign.keyPair.fromSeed in bytes. */
    public static final int seedLength = 32;

    /** Length of signature in bytes. */
    public static final int signatureLength = 64;
  }

  /**
   * Codes below are ported tweetnacl-fast.js from TweetNacl.c/TweetNacl.h
   */

  private static final byte[] _0 = new byte[16];
  private static final byte[] _9 = new byte[32];

  static {
    _9[0] = 9;
  }

  private static final long[] gf0 = new long[16];
  private static final long[] gf1 = new long[16];
  private static final long[] _121665 = new long[16];

  static {
    gf1[0] = 1;
    _121665[0] = 0xDB41;
    _121665[1] = 1;
  }

  private static final long[] D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
  private static final long[] D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
  private static final long[] X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
  private static final long[] Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
  private static final long[] I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

  private static int vn(final byte[] x, final int xoff, final byte[] y, final int yoff, final int n) {
    int d = 0;
    for (int i = 0; i < n; ++i)
      d |= (x[i + xoff] ^ y[i + yoff]) & 0xff;

    return (1 & ((d - 1) >>> 8)) - 1;
  }

  private static int cryptoVerify16(final byte[] x, final int xoff, final byte[] y, final int yoff) {
    return vn(x, xoff, y, yoff, 16);
  }

  public static int cryptoVerify16(final byte[] x, final byte[] y) {
    return cryptoVerify16(x, 0, y, 0);
  }

  private static int cryptoVerify32(final byte[] x, final int xoff, final byte[] y, final int yoff) {
    return vn(x, xoff, y, yoff, 32);
  }

  public static int cryptoVerify32(final byte[] x, final byte[] y) {
    return cryptoVerify32(x, 0, y, 0);
  }

  private static void coreSalsa20(final byte[] o, final byte[] p, final byte[] k, final byte[] c) {
    int j0 = c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24,
        j1 = k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24,
        j2 = k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24,
        j3 = k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24,
        j4 = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24,
        j5 = c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24,
        j6 = p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24,
        j7 = p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24,
        j8 = p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24,
        j9 = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24,
        j10 = c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24,
        j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24,
        j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24,
        j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24,
        j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24,
        j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24;

    int x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;
    for (int i = 0; i < 20; i += 2) {
      u = x0 + x12 | 0;
      x4 ^= u << 7 | u >>> (32 - 7);
      u = x4 + x0 | 0;
      x8 ^= u << 9 | u >>> (32 - 9);
      u = x8 + x4 | 0;
      x12 ^= u << 13 | u >>> (32 - 13);
      u = x12 + x8 | 0;
      x0 ^= u << 18 | u >>> (32 - 18);

      u = x5 + x1 | 0;
      x9 ^= u << 7 | u >>> (32 - 7);
      u = x9 + x5 | 0;
      x13 ^= u << 9 | u >>> (32 - 9);
      u = x13 + x9 | 0;
      x1 ^= u << 13 | u >>> (32 - 13);
      u = x1 + x13 | 0;
      x5 ^= u << 18 | u >>> (32 - 18);

      u = x10 + x6 | 0;
      x14 ^= u << 7 | u >>> (32 - 7);
      u = x14 + x10 | 0;
      x2 ^= u << 9 | u >>> (32 - 9);
      u = x2 + x14 | 0;
      x6 ^= u << 13 | u >>> (32 - 13);
      u = x6 + x2 | 0;
      x10 ^= u << 18 | u >>> (32 - 18);

      u = x15 + x11 | 0;
      x3 ^= u << 7 | u >>> (32 - 7);
      u = x3 + x15 | 0;
      x7 ^= u << 9 | u >>> (32 - 9);
      u = x7 + x3 | 0;
      x11 ^= u << 13 | u >>> (32 - 13);
      u = x11 + x7 | 0;
      x15 ^= u << 18 | u >>> (32 - 18);

      u = x0 + x3 | 0;
      x1 ^= u << 7 | u >>> (32 - 7);
      u = x1 + x0 | 0;
      x2 ^= u << 9 | u >>> (32 - 9);
      u = x2 + x1 | 0;
      x3 ^= u << 13 | u >>> (32 - 13);
      u = x3 + x2 | 0;
      x0 ^= u << 18 | u >>> (32 - 18);

      u = x5 + x4 | 0;
      x6 ^= u << 7 | u >>> (32 - 7);
      u = x6 + x5 | 0;
      x7 ^= u << 9 | u >>> (32 - 9);
      u = x7 + x6 | 0;
      x4 ^= u << 13 | u >>> (32 - 13);
      u = x4 + x7 | 0;
      x5 ^= u << 18 | u >>> (32 - 18);

      u = x10 + x9 | 0;
      x11 ^= u << 7 | u >>> (32 - 7);
      u = x11 + x10 | 0;
      x8 ^= u << 9 | u >>> (32 - 9);
      u = x8 + x11 | 0;
      x9 ^= u << 13 | u >>> (32 - 13);
      u = x9 + x8 | 0;
      x10 ^= u << 18 | u >>> (32 - 18);

      u = x15 + x14 | 0;
      x12 ^= u << 7 | u >>> (32 - 7);
      u = x12 + x15 | 0;
      x13 ^= u << 9 | u >>> (32 - 9);
      u = x13 + x12 | 0;
      x14 ^= u << 13 | u >>> (32 - 13);
      u = x14 + x13 | 0;
      x15 ^= u << 18 | u >>> (32 - 18);
    }

    x0 = x0 + j0 | 0;
    x1 = x1 + j1 | 0;
    x2 = x2 + j2 | 0;
    x3 = x3 + j3 | 0;
    x4 = x4 + j4 | 0;
    x5 = x5 + j5 | 0;
    x6 = x6 + j6 | 0;
    x7 = x7 + j7 | 0;
    x8 = x8 + j8 | 0;
    x9 = x9 + j9 | 0;
    x10 = x10 + j10 | 0;
    x11 = x11 + j11 | 0;
    x12 = x12 + j12 | 0;
    x13 = x13 + j13 | 0;
    x14 = x14 + j14 | 0;
    x15 = x15 + j15 | 0;

    o[0] = (byte)(x0 >>> 0 & 0xff);
    o[1] = (byte)(x0 >>> 8 & 0xff);
    o[2] = (byte)(x0 >>> 16 & 0xff);
    o[3] = (byte)(x0 >>> 24 & 0xff);

    o[4] = (byte)(x1 >>> 0 & 0xff);
    o[5] = (byte)(x1 >>> 8 & 0xff);
    o[6] = (byte)(x1 >>> 16 & 0xff);
    o[7] = (byte)(x1 >>> 24 & 0xff);

    o[8] = (byte)(x2 >>> 0 & 0xff);
    o[9] = (byte)(x2 >>> 8 & 0xff);
    o[10] = (byte)(x2 >>> 16 & 0xff);
    o[11] = (byte)(x2 >>> 24 & 0xff);

    o[12] = (byte)(x3 >>> 0 & 0xff);
    o[13] = (byte)(x3 >>> 8 & 0xff);
    o[14] = (byte)(x3 >>> 16 & 0xff);
    o[15] = (byte)(x3 >>> 24 & 0xff);

    o[16] = (byte)(x4 >>> 0 & 0xff);
    o[17] = (byte)(x4 >>> 8 & 0xff);
    o[18] = (byte)(x4 >>> 16 & 0xff);
    o[19] = (byte)(x4 >>> 24 & 0xff);

    o[20] = (byte)(x5 >>> 0 & 0xff);
    o[21] = (byte)(x5 >>> 8 & 0xff);
    o[22] = (byte)(x5 >>> 16 & 0xff);
    o[23] = (byte)(x5 >>> 24 & 0xff);

    o[24] = (byte)(x6 >>> 0 & 0xff);
    o[25] = (byte)(x6 >>> 8 & 0xff);
    o[26] = (byte)(x6 >>> 16 & 0xff);
    o[27] = (byte)(x6 >>> 24 & 0xff);

    o[28] = (byte)(x7 >>> 0 & 0xff);
    o[29] = (byte)(x7 >>> 8 & 0xff);
    o[30] = (byte)(x7 >>> 16 & 0xff);
    o[31] = (byte)(x7 >>> 24 & 0xff);

    o[32] = (byte)(x8 >>> 0 & 0xff);
    o[33] = (byte)(x8 >>> 8 & 0xff);
    o[34] = (byte)(x8 >>> 16 & 0xff);
    o[35] = (byte)(x8 >>> 24 & 0xff);

    o[36] = (byte)(x9 >>> 0 & 0xff);
    o[37] = (byte)(x9 >>> 8 & 0xff);
    o[38] = (byte)(x9 >>> 16 & 0xff);
    o[39] = (byte)(x9 >>> 24 & 0xff);

    o[40] = (byte)(x10 >>> 0 & 0xff);
    o[41] = (byte)(x10 >>> 8 & 0xff);
    o[42] = (byte)(x10 >>> 16 & 0xff);
    o[43] = (byte)(x10 >>> 24 & 0xff);

    o[44] = (byte)(x11 >>> 0 & 0xff);
    o[45] = (byte)(x11 >>> 8 & 0xff);
    o[46] = (byte)(x11 >>> 16 & 0xff);
    o[47] = (byte)(x11 >>> 24 & 0xff);

    o[48] = (byte)(x12 >>> 0 & 0xff);
    o[49] = (byte)(x12 >>> 8 & 0xff);
    o[50] = (byte)(x12 >>> 16 & 0xff);
    o[51] = (byte)(x12 >>> 24 & 0xff);

    o[52] = (byte)(x13 >>> 0 & 0xff);
    o[53] = (byte)(x13 >>> 8 & 0xff);
    o[54] = (byte)(x13 >>> 16 & 0xff);
    o[55] = (byte)(x13 >>> 24 & 0xff);

    o[56] = (byte)(x14 >>> 0 & 0xff);
    o[57] = (byte)(x14 >>> 8 & 0xff);
    o[58] = (byte)(x14 >>> 16 & 0xff);
    o[59] = (byte)(x14 >>> 24 & 0xff);

    o[60] = (byte)(x15 >>> 0 & 0xff);
    o[61] = (byte)(x15 >>> 8 & 0xff);
    o[62] = (byte)(x15 >>> 16 & 0xff);
    o[63] = (byte)(x15 >>> 24 & 0xff);

    /*
     * String dbgt = ""; for (int dbg = 0; dbg < o.length; dbg ++) dbgt +=
     * " "+o[dbg]; Log.d(TAG, "core_salsa20 -> "+dbgt);
     */
  }

  private static void coreHsalsa20(final byte[] o, final byte[] p, final byte[] k, final byte[] c) {
    int j0 = c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24,
        j1 = k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24,
        j2 = k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24,
        j3 = k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24,
        j4 = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24,
        j5 = c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24,
        j6 = p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24,
        j7 = p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24,
        j8 = p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24,
        j9 = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24,
        j10 = c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24,
        j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24,
        j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24,
        j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24,
        j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24,
        j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24;

    int x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;

    for (int i = 0; i < 20; i += 2) {
      u = x0 + x12 | 0;
      x4 ^= u << 7 | u >>> (32 - 7);
      u = x4 + x0 | 0;
      x8 ^= u << 9 | u >>> (32 - 9);
      u = x8 + x4 | 0;
      x12 ^= u << 13 | u >>> (32 - 13);
      u = x12 + x8 | 0;
      x0 ^= u << 18 | u >>> (32 - 18);

      u = x5 + x1 | 0;
      x9 ^= u << 7 | u >>> (32 - 7);
      u = x9 + x5 | 0;
      x13 ^= u << 9 | u >>> (32 - 9);
      u = x13 + x9 | 0;
      x1 ^= u << 13 | u >>> (32 - 13);
      u = x1 + x13 | 0;
      x5 ^= u << 18 | u >>> (32 - 18);

      u = x10 + x6 | 0;
      x14 ^= u << 7 | u >>> (32 - 7);
      u = x14 + x10 | 0;
      x2 ^= u << 9 | u >>> (32 - 9);
      u = x2 + x14 | 0;
      x6 ^= u << 13 | u >>> (32 - 13);
      u = x6 + x2 | 0;
      x10 ^= u << 18 | u >>> (32 - 18);

      u = x15 + x11 | 0;
      x3 ^= u << 7 | u >>> (32 - 7);
      u = x3 + x15 | 0;
      x7 ^= u << 9 | u >>> (32 - 9);
      u = x7 + x3 | 0;
      x11 ^= u << 13 | u >>> (32 - 13);
      u = x11 + x7 | 0;
      x15 ^= u << 18 | u >>> (32 - 18);

      u = x0 + x3 | 0;
      x1 ^= u << 7 | u >>> (32 - 7);
      u = x1 + x0 | 0;
      x2 ^= u << 9 | u >>> (32 - 9);
      u = x2 + x1 | 0;
      x3 ^= u << 13 | u >>> (32 - 13);
      u = x3 + x2 | 0;
      x0 ^= u << 18 | u >>> (32 - 18);

      u = x5 + x4 | 0;
      x6 ^= u << 7 | u >>> (32 - 7);
      u = x6 + x5 | 0;
      x7 ^= u << 9 | u >>> (32 - 9);
      u = x7 + x6 | 0;
      x4 ^= u << 13 | u >>> (32 - 13);
      u = x4 + x7 | 0;
      x5 ^= u << 18 | u >>> (32 - 18);

      u = x10 + x9 | 0;
      x11 ^= u << 7 | u >>> (32 - 7);
      u = x11 + x10 | 0;
      x8 ^= u << 9 | u >>> (32 - 9);
      u = x8 + x11 | 0;
      x9 ^= u << 13 | u >>> (32 - 13);
      u = x9 + x8 | 0;
      x10 ^= u << 18 | u >>> (32 - 18);

      u = x15 + x14 | 0;
      x12 ^= u << 7 | u >>> (32 - 7);
      u = x12 + x15 | 0;
      x13 ^= u << 9 | u >>> (32 - 9);
      u = x13 + x12 | 0;
      x14 ^= u << 13 | u >>> (32 - 13);
      u = x14 + x13 | 0;
      x15 ^= u << 18 | u >>> (32 - 18);
    }

    o[0] = (byte)(x0 >>> 0 & 0xff);
    o[1] = (byte)(x0 >>> 8 & 0xff);
    o[2] = (byte)(x0 >>> 16 & 0xff);
    o[3] = (byte)(x0 >>> 24 & 0xff);

    o[4] = (byte)(x5 >>> 0 & 0xff);
    o[5] = (byte)(x5 >>> 8 & 0xff);
    o[6] = (byte)(x5 >>> 16 & 0xff);
    o[7] = (byte)(x5 >>> 24 & 0xff);

    o[8] = (byte)(x10 >>> 0 & 0xff);
    o[9] = (byte)(x10 >>> 8 & 0xff);
    o[10] = (byte)(x10 >>> 16 & 0xff);
    o[11] = (byte)(x10 >>> 24 & 0xff);

    o[12] = (byte)(x15 >>> 0 & 0xff);
    o[13] = (byte)(x15 >>> 8 & 0xff);
    o[14] = (byte)(x15 >>> 16 & 0xff);
    o[15] = (byte)(x15 >>> 24 & 0xff);

    o[16] = (byte)(x6 >>> 0 & 0xff);
    o[17] = (byte)(x6 >>> 8 & 0xff);
    o[18] = (byte)(x6 >>> 16 & 0xff);
    o[19] = (byte)(x6 >>> 24 & 0xff);

    o[20] = (byte)(x7 >>> 0 & 0xff);
    o[21] = (byte)(x7 >>> 8 & 0xff);
    o[22] = (byte)(x7 >>> 16 & 0xff);
    o[23] = (byte)(x7 >>> 24 & 0xff);

    o[24] = (byte)(x8 >>> 0 & 0xff);
    o[25] = (byte)(x8 >>> 8 & 0xff);
    o[26] = (byte)(x8 >>> 16 & 0xff);
    o[27] = (byte)(x8 >>> 24 & 0xff);

    o[28] = (byte)(x9 >>> 0 & 0xff);
    o[29] = (byte)(x9 >>> 8 & 0xff);
    o[30] = (byte)(x9 >>> 16 & 0xff);
    o[31] = (byte)(x9 >>> 24 & 0xff);

    /*
     * String dbgt = ""; for (int dbg = 0; dbg < o.length; dbg ++) dbgt +=
     * " "+o[dbg]; Log.d(TAG, "core_hsalsa20 -> "+dbgt);
     */
  }

  public static int cryptoCoreSalsa20(final byte[] out, final byte[] in, final byte[] k, final byte[] c) {
    coreSalsa20(out, in, k, c);
    return 0;
  }

  public static int cryptoCoreHsalsa20(final byte[] out, final byte[] in, final byte[] k, final byte[] c) {
    coreHsalsa20(out, in, k, c);
    return 0;
  }

  // "expand 32-byte k"
  private static final byte[] sigma = {101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107};

  private static int cryptoStreamSalsa20Xor(final byte[] c, int cpos, byte[] m, int mpos, long b, final byte[] n, final byte[] k) {
    final byte[] z = new byte[16], x = new byte[64];
    int u, i;
    for (i = 0; i < 16; ++i)
      z[i] = 0;

    for (i = 0; i < 8; ++i)
      z[i] = n[i];

    while (b >= 64) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < 64; ++i)
        c[cpos + i] = (byte)((m[mpos + i] ^ x[i]) & 0xff);

      u = 1;
      for (i = 8; i < 16; ++i) {
        u = u + (z[i] & 0xff) | 0;
        z[i] = (byte)(u & 0xff);
        u >>>= 8;
      }

      b -= 64;
      cpos += 64;
      mpos += 64;
    }

    if (b > 0) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < b; ++i)
        c[cpos + i] = (byte)((m[mpos + i] ^ x[i]) & 0xff);
    }

    return 0;
  }

  public static int cryptoStreamSalsa20(final byte[] c, int cpos, long b, final byte[] n, final byte[] k) {
    final byte[] z = new byte[16], x = new byte[64];
    int u, i;
    for (i = 0; i < 16; ++i)
      z[i] = 0;

    for (i = 0; i < 8; ++i)
      z[i] = n[i];

    while (b >= 64) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < 64; ++i)
        c[cpos + i] = x[i];

      u = 1;
      for (i = 8; i < 16; ++i) {
        u = u + (z[i] & 0xff) | 0;
        z[i] = (byte)(u & 0xff);
        u >>>= 8;
      }

      b -= 64;
      cpos += 64;
    }

    if (b > 0) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < b; ++i)
        c[cpos + i] = x[i];
    }

    return 0;
  }

  public static int cryptoStream(final byte[] c, final int cpos, final long d, final byte[] n, final byte[] k) {
    final byte[] s = new byte[32];
    cryptoCoreHsalsa20(s, n, k, sigma);
    final byte[] sn = new byte[8];
    for (int i = 0; i < 8; ++i)
      sn[i] = n[i + 16];

    return cryptoStreamSalsa20(c, cpos, d, sn, s);
  }

  public static int cryptoStreamXor(final byte[] c, final int cpos, final byte[] m, final int mpos, final long d, final byte[] n, final byte[] k) {
    final byte[] s = new byte[32];

    cryptoCoreHsalsa20(s, n, k, sigma);
    byte[] sn = new byte[8];
    for (int i = 0; i < 8; ++i)
      sn[i] = n[i + 16];
    return cryptoStreamSalsa20Xor(c, cpos, m, mpos, d, sn, s);
  }

  private static int cryptoOneTimeAuth(final byte[] out, final int outpos, final byte[] m, final int mpos, final int n, final byte[] k) {
    final Poly1305 s = new Poly1305(k);
    s.update(m, mpos, n);
    s.finish(out, outpos);
    return 0;
  }

  public static int cryptoOneTimeAuth(final byte[] out, final byte[] m, int /* long */ n, byte[] k) {
    return cryptoOneTimeAuth(out, 0, m, 0, n, k);
  }

  private static int cryptoOneTimeAuthVerify(final byte[] h, final int hoff, final byte[] m, final int moff, int /*long*/ n, final byte[] k) {
    final byte[] x = new byte[16];
    cryptoOneTimeAuth(x, 0, m, moff, n, k);
    return cryptoVerify16(h, hoff, x, 0);
  }

  public static int cryptoOneTimeAuthVerify(final byte[] h, final byte[] m, int /* long */ n, byte[] k) {
    return cryptoOneTimeAuthVerify(h, 0, m, 0, n, k);
  }

  public static int cryptoOneTimeAuthVerify(final byte[] h, final byte[] m, final byte[] k) {
    return cryptoOneTimeAuthVerify(h, m, m != null ? m.length : 0, k);
  }

  public static int cryptoSecretBox(final byte[] c, final byte[] m, int /* long */ d, final byte[] n, byte[] k) {
    if (d < 32)
      return -1;

    cryptoStreamXor(c, 0, m, 0, d, n, k);
    cryptoOneTimeAuth(c, 16, c, 32, d - 32, c);
    return 0;
  }

  public static int cryptoSecretBoxOpen(final byte[] m, final byte[] c, int /* long */ d, final byte[] n, byte[] k) {
    final byte[] x = new byte[32];
    if (d < 32)
      return -1;

    cryptoStream(x, 0, 32, n, k);
    if (cryptoOneTimeAuthVerify(c, 16, c, 32, d - 32, x) != 0)
      return -1;

    cryptoStreamXor(m, 0, c, 0, d, n, k);
    return 0;
  }

  private static void set25519(final long[] r, final long[] a) {
    for (int i = 0; i < 16; ++i)
      r[i] = a[i];
  }

  private static void car25519(final long[] o) {
    long v, c = 1;
    for (int i = 0; i < 16; ++i) {
      v = o[i] + c + 65535;
      c = v >> 16;
      o[i] = v - c * 65536;
    }

    o[0] += c - 1 + 37 * (c - 1);
  }

  private static void sel25519(final long[] p, final long[] q, final int b) {
    sel25519(p, 0, q, 0, b);
  }

  private static void sel25519(final long[] p, final int poff, final long[] q, final int qoff, final int b) {
    long t, c = ~(b - 1);
    for (int i = 0; i < 16; ++i) {
      t = c & (p[i + poff] ^ q[i + qoff]);
      p[i + poff] ^= t;
      q[i + qoff] ^= t;
    }
  }

  private static void pack25519(final byte[] o, final long[] n, final int noff) {
    int i, j, b;
    final long[] m = new long[16], t = new long[16];
    for (i = 0; i < 16; ++i)
      t[i] = n[i + noff];

    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; j++) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; ++i) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }

      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (int)((m[15] >> 16) & 1);
      m[14] &= 0xffff;
      sel25519(t, 0, m, 0, 1 - b);
    }

    for (i = 0; i < 16; ++i) {
      o[2 * i] = (byte)(t[i] & 0xff);
      o[2 * i + 1] = (byte)(t[i] >> 8);
    }
  }

  private static int neq25519(final long[] a, final long[] b) {
    return neq25519(a, 0, b, 0);
  }

  private static int neq25519(final long[] a, final int aoff, final long[] b, final int boff) {
    byte[] c = new byte[32], d = new byte[32];
    pack25519(c, a, aoff);
    pack25519(d, b, boff);
    return cryptoVerify32(c, 0, d, 0);
  }

  private static byte par25519(final long[] a) {
    return par25519(a, 0);
  }

  private static byte par25519(final long[] a, final int aoff) {
    byte[] d = new byte[32];
    pack25519(d, a, aoff);
    return (byte)(d[0] & 1);
  }

  private static void unpack25519(final long[] o, final byte[] n) {
    for (int i = 0; i < 16; ++i)
      o[i] = (n[2 * i] & 0xff) + ((long)((n[2 * i + 1] << 8) & 0xffff));

    o[15] &= 0x7fff;
  }

  private static void A(final long[] o, final long[] a, final long[] b) {
    A(o, 0, a, 0, b, 0);
  }

  private static void A(final long[] o, final int ooff, final long[] a, final int aoff, final long[] b, final int boff) {
    for (int i = 0; i < 16; ++i)
      o[i + ooff] = a[i + aoff] + b[i + boff];
  }

  private static void Z(final long[] o, final long[] a, final long[] b) {
    Z(o, 0, a, 0, b, 0);
  }

  private static void Z(final long[] o, final int ooff, final long[] a, final int aoff, final long[] b, final int boff) {
    for (int i = 0; i < 16; ++i)
      o[i + ooff] = a[i + aoff] - b[i + boff];
  }

  private static void M(final long[] o, final long[] a, final long[] b) {
    M(o, 0, a, 0, b, 0);
  }

  private static void M(final long[] o, final int ooff, final long[] a, final int aoff, final long[] b, final int boff) {
    long v, c, t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0, t16 = 0,
        t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0, t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0, b0 = b[0 + boff],
        b1 = b[1 + boff], b2 = b[2 + boff], b3 = b[3 + boff], b4 = b[4 + boff], b5 = b[5 + boff], b6 = b[6 + boff], b7 = b[7 + boff], b8 = b[8 + boff],
        b9 = b[9 + boff], b10 = b[10 + boff], b11 = b[11 + boff], b12 = b[12 + boff], b13 = b[13 + boff], b14 = b[14 + boff], b15 = b[15 + boff];

    v = a[0 + aoff];
    t0 += v * b0;
    t1 += v * b1;
    t2 += v * b2;
    t3 += v * b3;
    t4 += v * b4;
    t5 += v * b5;
    t6 += v * b6;
    t7 += v * b7;
    t8 += v * b8;
    t9 += v * b9;
    t10 += v * b10;
    t11 += v * b11;
    t12 += v * b12;
    t13 += v * b13;
    t14 += v * b14;
    t15 += v * b15;
    v = a[1 + aoff];
    t1 += v * b0;
    t2 += v * b1;
    t3 += v * b2;
    t4 += v * b3;
    t5 += v * b4;
    t6 += v * b5;
    t7 += v * b6;
    t8 += v * b7;
    t9 += v * b8;
    t10 += v * b9;
    t11 += v * b10;
    t12 += v * b11;
    t13 += v * b12;
    t14 += v * b13;
    t15 += v * b14;
    t16 += v * b15;
    v = a[2 + aoff];
    t2 += v * b0;
    t3 += v * b1;
    t4 += v * b2;
    t5 += v * b3;
    t6 += v * b4;
    t7 += v * b5;
    t8 += v * b6;
    t9 += v * b7;
    t10 += v * b8;
    t11 += v * b9;
    t12 += v * b10;
    t13 += v * b11;
    t14 += v * b12;
    t15 += v * b13;
    t16 += v * b14;
    t17 += v * b15;
    v = a[3 + aoff];
    t3 += v * b0;
    t4 += v * b1;
    t5 += v * b2;
    t6 += v * b3;
    t7 += v * b4;
    t8 += v * b5;
    t9 += v * b6;
    t10 += v * b7;
    t11 += v * b8;
    t12 += v * b9;
    t13 += v * b10;
    t14 += v * b11;
    t15 += v * b12;
    t16 += v * b13;
    t17 += v * b14;
    t18 += v * b15;
    v = a[4 + aoff];
    t4 += v * b0;
    t5 += v * b1;
    t6 += v * b2;
    t7 += v * b3;
    t8 += v * b4;
    t9 += v * b5;
    t10 += v * b6;
    t11 += v * b7;
    t12 += v * b8;
    t13 += v * b9;
    t14 += v * b10;
    t15 += v * b11;
    t16 += v * b12;
    t17 += v * b13;
    t18 += v * b14;
    t19 += v * b15;
    v = a[5 + aoff];
    t5 += v * b0;
    t6 += v * b1;
    t7 += v * b2;
    t8 += v * b3;
    t9 += v * b4;
    t10 += v * b5;
    t11 += v * b6;
    t12 += v * b7;
    t13 += v * b8;
    t14 += v * b9;
    t15 += v * b10;
    t16 += v * b11;
    t17 += v * b12;
    t18 += v * b13;
    t19 += v * b14;
    t20 += v * b15;
    v = a[6 + aoff];
    t6 += v * b0;
    t7 += v * b1;
    t8 += v * b2;
    t9 += v * b3;
    t10 += v * b4;
    t11 += v * b5;
    t12 += v * b6;
    t13 += v * b7;
    t14 += v * b8;
    t15 += v * b9;
    t16 += v * b10;
    t17 += v * b11;
    t18 += v * b12;
    t19 += v * b13;
    t20 += v * b14;
    t21 += v * b15;
    v = a[7 + aoff];
    t7 += v * b0;
    t8 += v * b1;
    t9 += v * b2;
    t10 += v * b3;
    t11 += v * b4;
    t12 += v * b5;
    t13 += v * b6;
    t14 += v * b7;
    t15 += v * b8;
    t16 += v * b9;
    t17 += v * b10;
    t18 += v * b11;
    t19 += v * b12;
    t20 += v * b13;
    t21 += v * b14;
    t22 += v * b15;
    v = a[8 + aoff];
    t8 += v * b0;
    t9 += v * b1;
    t10 += v * b2;
    t11 += v * b3;
    t12 += v * b4;
    t13 += v * b5;
    t14 += v * b6;
    t15 += v * b7;
    t16 += v * b8;
    t17 += v * b9;
    t18 += v * b10;
    t19 += v * b11;
    t20 += v * b12;
    t21 += v * b13;
    t22 += v * b14;
    t23 += v * b15;
    v = a[9 + aoff];
    t9 += v * b0;
    t10 += v * b1;
    t11 += v * b2;
    t12 += v * b3;
    t13 += v * b4;
    t14 += v * b5;
    t15 += v * b6;
    t16 += v * b7;
    t17 += v * b8;
    t18 += v * b9;
    t19 += v * b10;
    t20 += v * b11;
    t21 += v * b12;
    t22 += v * b13;
    t23 += v * b14;
    t24 += v * b15;
    v = a[10 + aoff];
    t10 += v * b0;
    t11 += v * b1;
    t12 += v * b2;
    t13 += v * b3;
    t14 += v * b4;
    t15 += v * b5;
    t16 += v * b6;
    t17 += v * b7;
    t18 += v * b8;
    t19 += v * b9;
    t20 += v * b10;
    t21 += v * b11;
    t22 += v * b12;
    t23 += v * b13;
    t24 += v * b14;
    t25 += v * b15;
    v = a[11 + aoff];
    t11 += v * b0;
    t12 += v * b1;
    t13 += v * b2;
    t14 += v * b3;
    t15 += v * b4;
    t16 += v * b5;
    t17 += v * b6;
    t18 += v * b7;
    t19 += v * b8;
    t20 += v * b9;
    t21 += v * b10;
    t22 += v * b11;
    t23 += v * b12;
    t24 += v * b13;
    t25 += v * b14;
    t26 += v * b15;
    v = a[12 + aoff];
    t12 += v * b0;
    t13 += v * b1;
    t14 += v * b2;
    t15 += v * b3;
    t16 += v * b4;
    t17 += v * b5;
    t18 += v * b6;
    t19 += v * b7;
    t20 += v * b8;
    t21 += v * b9;
    t22 += v * b10;
    t23 += v * b11;
    t24 += v * b12;
    t25 += v * b13;
    t26 += v * b14;
    t27 += v * b15;
    v = a[13 + aoff];
    t13 += v * b0;
    t14 += v * b1;
    t15 += v * b2;
    t16 += v * b3;
    t17 += v * b4;
    t18 += v * b5;
    t19 += v * b6;
    t20 += v * b7;
    t21 += v * b8;
    t22 += v * b9;
    t23 += v * b10;
    t24 += v * b11;
    t25 += v * b12;
    t26 += v * b13;
    t27 += v * b14;
    t28 += v * b15;
    v = a[14 + aoff];
    t14 += v * b0;
    t15 += v * b1;
    t16 += v * b2;
    t17 += v * b3;
    t18 += v * b4;
    t19 += v * b5;
    t20 += v * b6;
    t21 += v * b7;
    t22 += v * b8;
    t23 += v * b9;
    t24 += v * b10;
    t25 += v * b11;
    t26 += v * b12;
    t27 += v * b13;
    t28 += v * b14;
    t29 += v * b15;
    v = a[15 + aoff];
    t15 += v * b0;
    t16 += v * b1;
    t17 += v * b2;
    t18 += v * b3;
    t19 += v * b4;
    t20 += v * b5;
    t21 += v * b6;
    t22 += v * b7;
    t23 += v * b8;
    t24 += v * b9;
    t25 += v * b10;
    t26 += v * b11;
    t27 += v * b12;
    t28 += v * b13;
    t29 += v * b14;
    t30 += v * b15;

    t0 += 38 * t16;
    t1 += 38 * t17;
    t2 += 38 * t18;
    t3 += 38 * t19;
    t4 += 38 * t20;
    t5 += 38 * t21;
    t6 += 38 * t22;
    t7 += 38 * t23;
    t8 += 38 * t24;
    t9 += 38 * t25;
    t10 += 38 * t26;
    t11 += 38 * t27;
    t12 += 38 * t28;
    t13 += 38 * t29;
    t14 += 38 * t30;
    // t15 left as is

    // first car
    c = 1;
    v = t0 + c + 65535;
    c = v >> 16;
    t0 = v - c * 65536;
    v = t1 + c + 65535;
    c = v >> 16;
    t1 = v - c * 65536;
    v = t2 + c + 65535;
    c = v >> 16;
    t2 = v - c * 65536;
    v = t3 + c + 65535;
    c = v >> 16;
    t3 = v - c * 65536;
    v = t4 + c + 65535;
    c = v >> 16;
    t4 = v - c * 65536;
    v = t5 + c + 65535;
    c = v >> 16;
    t5 = v - c * 65536;
    v = t6 + c + 65535;
    c = v >> 16;
    t6 = v - c * 65536;
    v = t7 + c + 65535;
    c = v >> 16;
    t7 = v - c * 65536;
    v = t8 + c + 65535;
    c = v >> 16;
    t8 = v - c * 65536;
    v = t9 + c + 65535;
    c = v >> 16;
    t9 = v - c * 65536;
    v = t10 + c + 65535;
    c = v >> 16;
    t10 = v - c * 65536;
    v = t11 + c + 65535;
    c = v >> 16;
    t11 = v - c * 65536;
    v = t12 + c + 65535;
    c = v >> 16;
    t12 = v - c * 65536;
    v = t13 + c + 65535;
    c = v >> 16;
    t13 = v - c * 65536;
    v = t14 + c + 65535;
    c = v >> 16;
    t14 = v - c * 65536;
    v = t15 + c + 65535;
    c = v >> 16;
    t15 = v - c * 65536;
    t0 += c - 1 + 37 * (c - 1);

    // second car
    c = 1;
    v = t0 + c + 65535;
    c = v >> 16;
    t0 = v - c * 65536;
    v = t1 + c + 65535;
    c = v >> 16;
    t1 = v - c * 65536;
    v = t2 + c + 65535;
    c = v >> 16;
    t2 = v - c * 65536;
    v = t3 + c + 65535;
    c = v >> 16;
    t3 = v - c * 65536;
    v = t4 + c + 65535;
    c = v >> 16;
    t4 = v - c * 65536;
    v = t5 + c + 65535;
    c = v >> 16;
    t5 = v - c * 65536;
    v = t6 + c + 65535;
    c = v >> 16;
    t6 = v - c * 65536;
    v = t7 + c + 65535;
    c = v >> 16;
    t7 = v - c * 65536;
    v = t8 + c + 65535;
    c = v >> 16;
    t8 = v - c * 65536;
    v = t9 + c + 65535;
    c = v >> 16;
    t9 = v - c * 65536;
    v = t10 + c + 65535;
    c = v >> 16;
    t10 = v - c * 65536;
    v = t11 + c + 65535;
    c = v >> 16;
    t11 = v - c * 65536;
    v = t12 + c + 65535;
    c = v >> 16;
    t12 = v - c * 65536;
    v = t13 + c + 65535;
    c = v >> 16;
    t13 = v - c * 65536;
    v = t14 + c + 65535;
    c = v >> 16;
    t14 = v - c * 65536;
    v = t15 + c + 65535;
    c = v >> 16;
    t15 = v - c * 65536;
    t0 += c - 1 + 37 * (c - 1);

    o[0 + ooff] = t0;
    o[1 + ooff] = t1;
    o[2 + ooff] = t2;
    o[3 + ooff] = t3;
    o[4 + ooff] = t4;
    o[5 + ooff] = t5;
    o[6 + ooff] = t6;
    o[7 + ooff] = t7;
    o[8 + ooff] = t8;
    o[9 + ooff] = t9;
    o[10 + ooff] = t10;
    o[11 + ooff] = t11;
    o[12 + ooff] = t12;
    o[13 + ooff] = t13;
    o[14 + ooff] = t14;
    o[15 + ooff] = t15;
  }

  private static void S(final long[] o, final long[] a) {
    S(o, 0, a, 0);
  }

  private static void S(final long[] o, final int ooff, final long[] a, final int aoff) {
    M(o, ooff, a, aoff, a, aoff);
  }

  private static void inv25519(final long[] o, final int ooff, final long[] i, final int ioff) {
    final long[] c = new long[16];
    int a;
    for (a = 0; a < 16; a++)
      c[a] = i[a + ioff];

    for (a = 253; a >= 0; --a) {
      S(c, 0, c, 0);
      if (a != 2 && a != 4)
        M(c, 0, c, 0, i, ioff);
    }

    for (a = 0; a < 16; a++)
      o[a + ooff] = c[a];
  }

  private static void pow2523(final long[] o, final long[] i) {
    final long[] c = new long[16];
    int a;
    for (a = 0; a < 16; a++)
      c[a] = i[a];

    for (a = 250; a >= 0; --a) {
      S(c, 0, c, 0);
      if (a != 1)
        M(c, 0, c, 0, i, 0);
    }

    for (a = 0; a < 16; a++)
      o[a] = c[a];
  }

  public static int cryptoScalarMult(final byte[] q, final byte[] n, final byte[] p) {
    final byte[] z = new byte[32];
    final long[] x = new long[80];
    int r, i;
    long[] a = new long[16], b = new long[16], c = new long[16], d = new long[16], e = new long[16], f = new long[16];
    for (i = 0; i < 31; ++i)
      z[i] = n[i];

    z[31] = (byte)(((n[31] & 127) | 64) & 0xff);
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; ++i) {
      b[i] = x[i];
      d[i] = a[i] = c[i] = 0;
    }

    a[0] = d[0] = 1;
    for (i = 254; i >= 0; --i) {
      r = (z[i >>> 3] >>> (i & 7)) & 1;
      sel25519(a, b, r);
      sel25519(c, d, r);
      A(e, a, c);
      Z(a, a, c);
      A(c, b, d);
      Z(b, b, d);
      S(d, e);
      S(f, a);
      M(a, c, a);
      M(c, b, e);
      A(e, a, c);
      Z(a, a, c);
      S(b, a);
      Z(c, d, f);
      M(a, c, _121665);
      A(a, a, d);
      M(c, c, a);
      M(a, d, f);
      M(d, b, x);
      S(b, e);
      sel25519(a, b, r);
      sel25519(c, d, r);
    }

    for (i = 0; i < 16; ++i) {
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }

    inv25519(x, 32, x, 32);
    M(x, 16, x, 16, x, 32);
    pack25519(q, x, 16);

    return 0;
  }

  public static int cryptoScalarMultBase(final byte[] q, final byte[] n) {
    return cryptoScalarMult(q, n, _9);
  }

  public static int cryptoBoxKeyPair(final byte[] y, final byte[] x) {
    randombytes(x, 32);
    return cryptoScalarMultBase(y, x);
  }

  public static int cryptoBoxBeforeNm(final byte[] k, final byte[] y, final byte[] x) {
    final byte[] s = new byte[32];
    cryptoScalarMult(s, x, y);

    /*
     * String dbgt = ""; for (int dbg = 0; dbg < s.length; dbg ++) dbgt +=
     * " "+s[dbg]; Log.d(TAG, "crypto_box_beforenm -> "+dbgt); dbgt = ""; for
     * (final int dbg = 0; dbg < x.length; dbg ++) dbgt += " "+x[dbg]; Log.d(TAG,
     * "crypto_box_beforenm, x -> "+dbgt); dbgt = ""; for (int dbg = 0; dbg <
     * y.length; dbg ++) dbgt += " "+y[dbg]; Log.d(TAG,
     * "crypto_box_beforenm, y -> "+dbgt);
     */

    return cryptoCoreHsalsa20(k, _0, s, sigma);
  }

  public static int cryptoBoxAfterNm(final byte[] c, final byte[] m, int /* long */ d, final byte[] n, byte[] k) {
    return cryptoSecretBox(c, m, d, n, k);
  }

  public static int cryptoBoxOpenAfterNm(final byte[] m, final byte[] c, int /* long */ d, final byte[] n, byte[] k) {
    return cryptoSecretBoxOpen(m, c, d, n, k);
  }

  public static int cryptoBox(final byte[] c, final byte[] m, int /* long */ d, final byte[] n, final byte[] y, byte[] x) {
    final byte[] k = new byte[32];
    cryptoBoxBeforeNm(k, y, x);
    return cryptoBoxAfterNm(c, m, d, n, k);
  }

  public static int cryptoBoxOpen(final byte[] m, final byte[] c, int /* long */ d, final byte[] n, final byte[] y, byte[] x) {
    final byte[] k = new byte[32];
    cryptoBoxBeforeNm(k, y, x);
    return cryptoBoxOpenAfterNm(m, c, d, n, k);
  }

  private static void add(final long[] p[], final long[] q[]) {
    final long[] a = new long[16];
    final long[] b = new long[16];
    final long[] c = new long[16];
    final long[] d = new long[16];
    final long[] t = new long[16];
    final long[] e = new long[16];
    final long[] f = new long[16];
    final long[] g = new long[16];
    final long[] h = new long[16];

    final long[] p0 = p[0];
    final long[] p1 = p[1];
    final long[] p2 = p[2];
    final long[] p3 = p[3];

    final long[] q0 = q[0];
    final long[] q1 = q[1];
    final long[] q2 = q[2];
    final long[] q3 = q[3];

    Z(a, 0, p1, 0, p0, 0);
    Z(t, 0, q1, 0, q0, 0);
    M(a, 0, a, 0, t, 0);
    A(b, 0, p0, 0, p1, 0);
    A(t, 0, q0, 0, q1, 0);
    M(b, 0, b, 0, t, 0);
    M(c, 0, p3, 0, q3, 0);
    M(c, 0, c, 0, D2, 0);
    M(d, 0, p2, 0, q2, 0);

    A(d, 0, d, 0, d, 0);
    Z(e, 0, b, 0, a, 0);
    Z(f, 0, d, 0, c, 0);
    A(g, 0, d, 0, c, 0);
    A(h, 0, b, 0, a, 0);

    M(p0, 0, e, 0, f, 0);
    M(p1, 0, h, 0, g, 0);
    M(p2, 0, g, 0, f, 0);
    M(p3, 0, e, 0, h, 0);
  }

  private static void cswap(final long[] p[], final long[] q[], final byte b) {
    for (int i = 0; i < 4; ++i)
      sel25519(p[i], 0, q[i], 0, b);
  }

  private static void pack(final byte[] r, final long[] p[]) {
    final long[] tx = new long[16];
    final long[] ty = new long[16];
    final long[] zi = new long[16];

    inv25519(zi, 0, p[2], 0);

    M(tx, 0, p[0], 0, zi, 0);
    M(ty, 0, p[1], 0, zi, 0);

    pack25519(r, ty, 0);

    r[31] ^= par25519(tx, 0) << 7;
  }

  private static void scalarmult(final long[] p[], final long[] q[], final byte[] s, final int soff) {
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);

    for (int i = 255; i >= 0; --i) {
      byte b = (byte)((s[i / 8 + soff] >>> (i & 7)) & 1);

      cswap(p, q, b);
      add(q, p);
      add(p, p);
      cswap(p, q, b);
    }
  }

  private static void scalarbase(final long[] p[], final byte[] s, final int soff) {
    final long[][] q = new long[4][];

    q[0] = new long[16];
    q[1] = new long[16];
    q[2] = new long[16];
    q[3] = new long[16];

    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], 0, X, 0, Y, 0);
    scalarmult(p, q, s, soff);
  }

  public static int cryptoSignKeyPair(final byte[] pk, final byte[] sk, final boolean seeded) {
    final byte[] d = new byte[64];
    final long[][] p = new long[4][];

    p[0] = new long[16];
    p[1] = new long[16];
    p[2] = new long[16];
    p[3] = new long[16];

    if (!seeded)
      randombytes(sk, 32);

    HashFast.cryptoHash(d, sk, 0, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d, 0);
    pack(pk, p);

    for (int i = 0; i < 32; ++i)
      sk[i + 32] = pk[i];

    return 0;
  }

  private static final long L[] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

  private static void modL(final byte[] r, final int roff, final long x[]) {
    long carry;
    int i, j;
    for (i = 63; i >= 32; --i) {
      carry = 0;
      for (j = i - 32; j < i - 12; ++j) {
        x[j] += carry - 16 * x[i] * L[j - (i - 32)];
        carry = (x[j] + 128) >> 8;
        x[j] -= carry << 8;
      }
      x[j] += carry;
      x[i] = 0;
    }
    carry = 0;

    for (j = 0; j < 32; j++) {
      x[j] += carry - (x[31] >> 4) * L[j];
      carry = x[j] >> 8;
      x[j] &= 255;
    }

    for (j = 0; j < 32; j++)
      x[j] -= carry * L[j];

    for (i = 0; i < 32; ++i) {
      x[i + 1] += x[i] >> 8;
      r[i + roff] = (byte)(x[i] & 255);
    }
  }

  private static void reduce(final byte[] r) {
    final long[] x = new long[64];
    int i;
    for (i = 0; i < 64; ++i)
      x[i] = r[i] & 0xff;

    for (i = 0; i < 64; ++i)
      r[i] = 0;

    modL(r, 0, x);
  }

  // TBD... 64bits of n
  public static int cryptoSign(final byte[] sm, final long dummy /*smlen not used*/, final byte[] m, final int moff, int/*long*/ n, final byte[] sk) {
    final byte[] d = new byte[64], h = new byte[64], r = new byte[64];
    final long[] x = new long[64];

    final long[][] p = new long[4][];
    p[0] = new long[16];
    p[1] = new long[16];
    p[2] = new long[16];
    p[3] = new long[16];

    HashFast.cryptoHash(d, sk, 0, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    int i;
    for (i = 0; i < n; ++i)
      sm[64 + i] = m[i + moff];

    for (i = 0; i < 32; ++i)
      sm[32 + i] = d[32 + i];

    HashFast.cryptoHash(r, sm, 32, n + 32);
    reduce(r);
    scalarbase(p, r, 0);
    pack(sm, p);

    for (i = 0; i < 32; ++i)
      sm[i + 32] = sk[i + 32];

    HashFast.cryptoHash(h, sm, 0, n + 64);
    reduce(h);
    for (i = 0; i < 64; ++i)
      x[i] = 0;

    for (i = 0; i < 32; ++i)
      x[i] = r[i] & 0xff;

    for (i = 0; i < 32; ++i)
      for (int j = 0; j < 32; j++)
        x[i + j] += (h[i] & 0xff) * (long)(d[j] & 0xff);

    modL(sm, 32, x);
    return 0;
  }

  private static int unpackneg(final long[] r[], final byte p[]) {
    final long[] t = new long[16];
    final long[] chk = new long[16];
    final long[] num = new long[16];
    final long[] den = new long[16];
    final long[] den2 = new long[16];
    final long[] den4 = new long[16];
    final long[] den6 = new long[16];

    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, r[1]);
    M(den, num, D);
    Z(num, num, r[2]);
    A(den, r[2], den);

    S(den2, den);
    S(den4, den2);
    M(den6, den4, den2);
    M(t, den6, num);
    M(t, t, den);

    pow2523(t, t);
    M(t, t, num);
    M(t, t, den);
    M(t, t, den);
    M(r[0], t, den);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num) != 0)
      M(r[0], r[0], I);

    S(chk, r[0]);
    M(chk, chk, den);
    if (neq25519(chk, num) != 0)
      return -1;

    if (par25519(r[0]) == ((p[31] & 0xFF) >>> 7))
      Z(r[0], gf0, r[0]);

    M(r[3], r[0], r[1]);

    return 0;
  }

  // TBD 64bits of mlen
  public static int cryptoSignOpen(final byte[] m, final long dummy /*mlen not used*/, final byte[] sm, final int smoff, int/*long*/ n, final byte[] pk) {
    final byte[] t = new byte[32], h = new byte[64];

    final long[][] p = new long[4][];
    p[0] = new long[16];
    p[1] = new long[16];
    p[2] = new long[16];
    p[3] = new long[16];

    final long[][] q = new long[4][];
    q[0] = new long[16];
    q[1] = new long[16];
    q[2] = new long[16];
    q[3] = new long[16];

    if (n < 64)
      return -1;

    if (unpackneg(q, pk) != 0)
      return -1;

    int i;
    for (i = 0; i < n; ++i)
      m[i] = sm[i + smoff];

    for (i = 0; i < 32; ++i)
      m[i + 32] = pk[i];

    HashFast.cryptoHash(h, m, 0, n);

    reduce(h);
    scalarmult(p, q, h, 0);

    scalarbase(q, sm, 32 + smoff);
    add(p, q);
    pack(t, p);

    n -= 64;
    if (cryptoVerify32(sm, smoff, t, 0) != 0)
      return -1;

    // TBD optimizing ...
    return 0;
  }

  /**
   * Java SecureRandom generator
   */
  private static final SecureRandom jrandom = new SecureRandom();

  public static byte[] randombytes(final byte[] x) {
    jrandom.nextBytes(x);
    return x;
  }

  public static byte[] randombytes(final int len) {
    return randombytes(new byte[len]);
  }

  public static byte[] randombytes(final byte[] x, final int len) {
    final byte[] b = randombytes(len);
    System.arraycopy(b, 0, x, 0, len);
    return x;
  }

  /*
   * public static byte[] randombytes(byte [] x, int len) { int ret = len % 8;
   * long rnd; for (int i = 0; i < len-ret; i += 8) { rnd = jrandom.nextLong();
   * x[i+0] = (byte) (rnd >>> 0); x[i+1] = (byte) (rnd >>> 8); x[i+2] = (byte)
   * (rnd >>> 16); x[i+3] = (byte) (rnd >>> 24); x[i+4] = (byte) (rnd >>> 32);
   * x[i+5] = (byte) (rnd >>> 40); x[i+6] = (byte) (rnd >>> 48); x[i+7] = (byte)
   * (rnd >>> 56); } if (ret > 0) { rnd = jrandom.nextLong(); for (int i =
   * len-ret; i < len; i ++) x[i] = (byte) (rnd >>> 8*i); } return x; }
   */

  public static byte[] makeBoxNonce() {
    return randombytes(Box.nonceLength);
  }

  public static byte[] makeSecretBoxNonce() {
    return randombytes(SecretBox.nonceLength);
  }

  public static String hexEncodeToString(final byte[] raw) {
    final String HEXES = "0123456789ABCDEF";
    final StringBuilder hex = new StringBuilder(2 * raw.length);
    for (final byte b : raw)
      hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));

    return hex.toString();
  }

  public static byte[] hexDecode(final String s) {
    byte[] b = new byte[s.length() / 2];
    for (int i = 0; i < s.length(); i += 2)
      b[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));

    return b;
  }
}