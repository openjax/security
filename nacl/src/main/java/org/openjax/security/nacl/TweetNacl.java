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
@SuppressWarnings("unused")
public final class TweetNacl {
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

      // generate precomputed shared key
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
        n[i + 0] = (byte)(nonce);
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
     * key, and the given nonce, which must be unique for each distinct
     * message for a key pair.
     *
     * @param message The message.
     * @return An encrypted and authenticated message, which is
     *         nacl.box.overheadLength longer than the original message.
     */
    public byte[] box(final byte[] message) {
      return box(message, generateNonce());
    }

    /**
     * Encrypt and authenticates message using peer's public key, our secret
     * key, and the explicitly provided nonce. Caller is responsible for
     * ensuring that nonce is unique for each distinct message for a key pair.
     *
     * @param message The message.
     * @param nonce The nonce.
     * @return An encrypted and authenticated message, which is
     *         nacl.box.overheadLength longer than the original message.
     */
    public byte[] box(final byte[] message, final byte[] nonce) {
      // check message
      if (!(message != null && message.length > 0 && nonce != null && nonce.length == nonceLength))
        return null;

      // message buffer
      final byte[] m = new byte[message.length + zerobytesLength];

      // cipher buffer
      final byte[] c = new byte[m.length];
      System.arraycopy(message, 0, m, 32, message.length);
      if (cryptoBox(c, m, m.length, nonce, theirPublicKey, mySecretKey) != 0)
        return null;

      final byte[] ret = new byte[c.length - boxzerobytesLength];
      System.arraycopy(c, 16, ret, 0, ret.length);

      return ret;
    }

    /**
     * Authenticates and decrypts the given box with peer's public key, our
     * secret key, and the given nonce.
     *
     * @param box The box.
     * @return The original message, or {@code null} if authentication fails.
     */
    public byte[] open(final byte[] box) {
      return open(box, generateNonce());
    }

    /**
     * Authenticates and decrypts the given box with peer's public key, our
     * secret key, and the explicitly provided nonce.
     *
     * @param box The box.
     * @param nonce The nonce.
     * @return The original message, or {@code null} if authentication fails.
     */
    public byte[] open(final byte[] box, final byte[] nonce) {
      // check message
      if (!(box != null && box.length > boxzerobytesLength && nonce != null && nonce.length == nonceLength))
        return null;

      // cipher buffer
      final byte[] c = new byte[box.length + boxzerobytesLength];

      // message buffer
      final byte[] m = new byte[c.length];
      System.arraycopy(box, 0, c, 16, box.length);

      if (cryptoBoxOpen(m, c, c.length, nonce, theirPublicKey, mySecretKey) != 0)
        return null;

      final byte[] ret = new byte[m.length - zerobytesLength];
      System.arraycopy(m, 32, ret, 0, ret.length);

      return ret;
    }

    /**
     * Returns a precomputed shared key which can be used in nacl.box.after and
     * nacl.box.open.after.
     *
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
     * @return An encrypted and authenticated message, which is
     *         nacl.box.overheadLength longer than the original message.
     */
    public byte[] after(final byte[] message) {
      return after(message, generateNonce());
    }

    /**
     * Same as nacl.box, but uses a shared key precomputed with nacl.box.before
     * and explicitly provided nonce
     *
     * @param message The message.
     * @param nonce The nonce.
     * @return An encrypted and authenticated message, which is
     *         nacl.box.overheadLength longer than the original message.
     */
    public byte[] after(final byte[] message, final byte[] nonce) {
      // check message
      if (!(message != null && message.length > 0 && nonce != null && nonce.length == nonceLength))
        return null;

      // message buffer
      final byte[] m = new byte[message.length + zerobytesLength];

      // cipher buffer
      final byte[] c = new byte[m.length];
      System.arraycopy(message, 0, m, 32, message.length);

      if (cryptoBoxAfterNm(c, m, m.length, nonce, sharedKey) != 0)
        return null;

      final byte[] ret = new byte[c.length - boxzerobytesLength];
      System.arraycopy(c, 16, ret, 0, ret.length);

      return ret;
    }

    /**
     * Same as nacl.box.open, but uses a shared key precomputed with
     * nacl.box.before.
     *
     * @param box The box.
     * @return The original message, or {@code null} if authentication fails.
     */
    public byte[] openAfter(final byte[] box) {
      return openAfter(box, generateNonce());
    }

    /**
     * Same as nacl.box.open, but uses a shared key precomputed with
     * nacl.box.before, and explicitly passed nonce
     *
     * @param box The box.
     * @param nonce The nonce.
     * @return The original message, or {@code null} if authentication fails.
     */
    public byte[] openAfter(final byte[] box, final byte[] nonce) {
      // check message
      if (!(box != null && box.length > boxzerobytesLength && nonce != null && nonce.length == nonceLength))
        return null;

      // cipher buffer
      final byte[] c = new byte[box.length + boxzerobytesLength];

      // message buffer
      final byte[] m = new byte[c.length];
      System.arraycopy(box, 0, c, 16, box.length);

      if (cryptoBoxOpenAfterNm(m, c, c.length, nonce, sharedKey) != 0)
        return null;

      final byte[] ret = new byte[m.length - zerobytesLength];
      System.arraycopy(m, 32, ret, 0, ret.length);

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
     * Returns a new random key pair for box and returns it as an object with
     * publicKey and secretKey members.
     *
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
      System.arraycopy(secretKey, 0, sk, 0, sk.length);

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

    public long incNonce() {
      return this.nonce.incrementAndGet();
    }

    private byte[] generateNonce() {
      // generate nonce
      final long nonce = this.nonce.get();
      final byte[] n = new byte[nonceLength];
      for (int i = 0; i < nonceLength; i += 8) {
        n[i + 0] = (byte)(nonce);
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
      return box(message, generateNonce());
    }

    /**
     * Encrypt and authenticates message using the key and the explicitly passed
     * nonce. The nonce must be unique for each distinct message for this key.
     *
     * @param message The message.
     * @param nonce The nonce.
     * @return An encrypted and authenticated message, which is
     *         nacl.secretbox.overheadLength longer than the original message.
     */
    public byte[] box(final byte[] message, final byte[] nonce) {
      // check message
      if (!(message != null && message.length > 0 && nonce != null && nonce.length == nonceLength))
        return null;

      // message buffer
      final byte[] m = new byte[message.length + zerobytesLength];

      // cipher buffer
      final byte[] c = new byte[m.length];
      System.arraycopy(message, 0, m, 32, message.length);

      if (cryptoSecretBox(c, m, m.length, nonce, key) != 0)
        return null;

      final byte[] ret = new byte[c.length - boxzerobytesLength];
      System.arraycopy(c, 16, ret, 0, ret.length);

      return ret;
    }

    /**
     * Authenticates and decrypts the given secret box using the key and the
     * nonce.
     *
     * @param box The box.
     * @return The original message, or {@code null} if authentication fails.
     */
    public byte[] open(final byte[] box) {
      return open(box, generateNonce());
    }

    /**
     * Authenticates and decrypts the given secret box using the key and the
     * explicitly passed nonce.
     *
     * @param box The box.
     * @param nonce The nonce.
     * @return The original message, or {@code null} if authentication fails.
     */
    public byte[] open(final byte[] box, final byte[] nonce) {
      // check message
      if (!(box != null && box.length > boxzerobytesLength && nonce != null && nonce.length == nonceLength))
        return null;

      // cipher buffer
      final byte[] c = new byte[box.length + boxzerobytesLength];

      // message buffer
      final byte[] m = new byte[c.length];
      System.arraycopy(box, 0, c, 16, box.length);

      if (cryptoSecretBoxOpen(m, c, c.length, nonce, key) != 0)
        return null;

      final byte[] ret = new byte[m.length - zerobytesLength];
      System.arraycopy(m, 32, ret, 0, ret.length);

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

    /** Zero bytes in case open box.*/
    public static final int boxzerobytesLength = 16;
  }

  /**
   * Scalar multiplication, Implements curve25519.
   */
  public static final class ScalarMult {
    private ScalarMult() {
    }

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
    public static byte[] scalseMult(final byte[] n) {
      if (n.length != scalarLength)
        return null;

      final byte[] q = new byte[scalarLength];
      cryptoScalarMultBase(q, n);
      return q;
    }

    /** Length of scalar in bytes. */
    public static final int scalarLength = 32;

    /** Length of group element in bytes. */
    public static final int groupElementLength = 32;
  }

  /**
   * Signature algorithm, Implements ed25519.
   */
  public static final class Signature {
    private final byte[] theirPublicKey;
    private final byte[] mySecretKey;

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
      // signed message
      final byte[] sm = new byte[message.length + signatureLength];
      cryptoSign(sm, -1, message, message.length, mySecretKey);
      return sm;
    }

    /**
     * Verifies the signed message.
     *
     * @param signedMessage The signed message.
     * @return The message without signature, or {@code null} if verification
     *         fails.
     */
    public byte[] open(final byte[] signedMessage) {
      // check sm length
      if (!(signedMessage != null && signedMessage.length > signatureLength))
        return null;

      // temp buffer
      final byte[] tmp = new byte[signedMessage.length];
      if (cryptoSignOpen(tmp, -1, signedMessage, signedMessage.length, theirPublicKey) != 0)
        return null;

      // message
      final byte[] msg = new byte[signedMessage.length - signatureLength];
      System.arraycopy(signedMessage, 64, msg, 0, msg.length);

      return msg;
    }

    /**
     * Signs the message using the secret key.
     *
     * @param message The message.
     * @return A signature.
     */
    public byte[] detached(final byte[] message) {
      final byte[] signedMsg = this.sign(message);
      final byte[] sig = new byte[signatureLength];
      System.arraycopy(signedMsg, 0, sig, 0, sig.length);

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
    public boolean detachedVerify(final byte[] message, final byte[] signature) {
      if (signature.length != signatureLength)
        return false;

      if (theirPublicKey.length != publicKeyLength)
        return false;

      final byte[] sm = new byte[signatureLength + message.length];
      final byte[] m = new byte[signatureLength + message.length];
      System.arraycopy(signature, 0, sm, 0, signatureLength);

      System.arraycopy(message, 0, sm, 64, message.length);

      return cryptoSignOpen(m, -1, sm, sm.length, theirPublicKey) >= 0;
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
      System.arraycopy(secretKey, 0, sk, 0, kp.getSecretKey().length);

      // copy pk from sk
      // hard-copy
      System.arraycopy(secretKey, 32, pk, 0, kp.getPublicKey().length);

      return kp;
    }

    public static KeyPair keyPairFromSeed(final byte[] seed) {
      final KeyPair kp = new KeyPair(publicKeyLength, secretKeyLength);
      final byte[] pk = kp.getPublicKey();
      final byte[] sk = kp.getSecretKey();

      // copy sk
      System.arraycopy(seed, 0, sk, 0, seedLength);

      // generate pk from sk
      cryptoSignKeyPair(pk, sk, true);
      return kp;
    }

    /**
     * Length of signing public key in bytes.
     */
    public static final int publicKeyLength = 32;

    /**
     * Length of signing secret key in bytes.
     */
    public static final int secretKeyLength = 64;

    /**
     * Length of seed for nacl.sign.keyPair.fromSeed in bytes.
     */
    public static final int seedLength = 32;

    /**
     * Length of signature in bytes.
     */
    public static final int signatureLength = 64;
  }

  private static final byte[] _0 = new byte[16];
  private static final byte[] _9 = new byte[32];

  static {
    for (int i = 0; i < _0.length; ++i)
      _0[i] = 0;

    for (int i = 0; i < _9.length; ++i)
      _9[i] = 0;

    _9[0] = 9;
  }

  private static final long[] gf0 = new long[16];
  private static final long[] gf1 = new long[16];
  private static final long[] _121665 = new long[16];

  static {
    for (int i = 0; i < gf0.length; ++i)
      gf0[i] = 0;

    for (int i = 0; i < gf1.length; ++i)
      gf1[i] = 0;

    gf1[0] = 1;
    for (int i = 0; i < _121665.length; ++i)
      _121665[i] = 0;

    _121665[0] = 0xDB41;
    _121665[1] = 1;
  }

  private static final long[] D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
  private static final long[] D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
  private static final long[] X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
  private static final long[] Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
  private static final long[] I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

  private static int L32(final int x, final int c) {
    return (x << c) | (x >>> (32 - c));
  }

  private static int ld32(final byte[] x, final int xoff, final int xlen) {
    int u = (x[3 + xoff] & 0xff);
    u = (u << 8) | (x[2 + xoff] & 0xff);
    u = (u << 8) | (x[1 + xoff] & 0xff);
    u = (u << 8) | (x[0 + xoff] & 0xff);
    return u;
  }

  private static void st32(final byte[] x, final int xoff, final int xlen, int u) {
    for (int i = 0; i < 4; ++i) {
      x[i + xoff] = (byte)(u & 0xff);
      u >>>= 8;
    }
  }

  private static int vn(final byte[] x, final int xoff, final int xlen, final byte[] y, final int yoff, final int ylen, final int n) {
    int d = 0;
    for (int i = 0; i < n; ++i)
      d |= (x[i + xoff] ^ y[i + yoff]) & 0xff;

    return (1 & ((d - 1) >>> 8)) - 1;
  }

  private static int cryptoVerify16(final byte[] x, final int xoff, final int xlen, final byte[] y, final int yoff, final int ylen) {
    return vn(x, xoff, xlen, y, yoff, ylen, 16);
  }

  public static int cryptoVerify16(final byte[] x, final byte[] y) {
    return cryptoVerify16(x, 0, x.length, y, 0, y.length);
  }

  private static int cryptoVerify32(final byte[] x, final int xoff, final int xlen, final byte[] y, final int yoff, final int ylen) {
    return vn(x, xoff, xlen, y, yoff, ylen, 32);
  }

  public static int cryptoVerify32(final byte[] x, final byte[] y) {
    return cryptoVerify32(x, 0, x.length, y, 0, y.length);
  }

  private static void core(final byte[] out, final byte[] in, final byte[] k, final byte[] c, final int h) {
    final int[] w = new int[16], x = new int[16], y = new int[16], t = new int[4];
    int i, j, m;
    for (i = 0; i < 4; ++i) {
      x[5 * i] = ld32(c, 4 * i, 4);
      x[1 + i] = ld32(k, 4 * i, 4);
      x[6 + i] = ld32(in, 4 * i, 4);
      x[11 + i] = ld32(k, 16 + 4 * i, 4);
    }

    for (i = 0; i < 16; ++i)
      y[i] = x[i];

    for (i = 0; i < 20; ++i) {
      for (j = 0; j < 4; ++j) {
        for (m = 0; m < 4; ++m)
          t[m] = x[(5 * j + 4 * m) % 16];

        t[1] ^= L32(t[0] + t[3], 7);
        t[2] ^= L32(t[1] + t[0], 9);
        t[3] ^= L32(t[2] + t[1], 13);
        t[0] ^= L32(t[3] + t[2], 18);
        for (m = 0; m < 4; ++m)
          w[4 * j + (j + m) % 4] = t[m];
      }

      for (m = 0; m < 16; ++m)
        x[m] = w[m];
    }

    if (h != 0) {
      for (i = 0; i < 16; ++i)
        x[i] += y[i];

      for (i = 0; i < 4; ++i) {
        x[5 * i] -= ld32(c, 4 * i, 4);
        x[6 + i] -= ld32(in, 4 * i, 4);
      }
      for (i = 0; i < 4; ++i) {
        st32(out, 4 * i, 4, x[5 * i]);
        st32(out, 16 + 4 * i, 4, x[6 + i]);
      }
    }
    else {
      for (i = 0; i < 16; ++i)
        st32(out, 4 * i, 4, x[i] + y[i]);
    }
  }

  public static int cryptoCoreSalsa20(final byte[] out, final byte[] in, final byte[] k, final byte[] c) {
    core(out, in, k, c, 0);
    return 0;
  }

  public static int cryptoCoreHsalsa20(final byte[] out, final byte[] in, final byte[] k, final byte[] c) {
    core(out, in, k, c, 1);
    return 0;
  }

  private static final byte[] sigma = {101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107};

  private static int cryptoStreamSalsa20Xor(final byte[] c, final byte[] m, long b, final byte[] n, final int noff, final int nlen, final byte[] k) {
    if (0 == b)
      return 0;

    final byte[] z = new byte[16];
    final byte[] x = new byte[64];
    int u, i;
    for (i = 0; i < 16; ++i)
      z[i] = 0;
    for (i = 0; i < 8; ++i)
      z[i] = n[i + noff];

    int coffset = 0;
    int moffset = 0;
    while (b >= 64) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < 64; ++i)
        c[i + coffset] = (byte)(((m != null ? m[i + moffset] : 0) ^ x[i]) & 0xff);

      u = 1;
      for (i = 8; i < 16; ++i) {
        u += z[i] & 0xff;
        z[i] = (byte)(u & 0xff);
        u >>>= 8;
      }

      b -= 64;
      coffset += 64;
      if (m != null)
        moffset += 64;
    }

    if (b != 0) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < b; ++i)
        c[i + coffset] = (byte)(((m != null ? m[i + moffset] : 0) ^ x[i]) & 0xff);
    }

    return 0;
  }

  public static int cryptoStreamSalsa20Xor(final byte[] c, final byte[] m, final long b, final byte[] n, final byte[] k) {
    return cryptoStreamSalsa20Xor(c, m, b, n, 0, n.length, k);
  }

  private static int cryptoStreamSalsa20(final byte[] c, final long d, final byte[] n, final int noff, final int nlen, final byte[] k) {
    return cryptoStreamSalsa20Xor(c, null, d, n, noff, nlen, k);
  }

  public static int cryptoStreamSalsa20(final byte[] c, final long d, final byte[] n, final byte[] k) {
    return cryptoStreamSalsa20(c, d, n, 0, n.length, k);
  }

  public static int cryptoStream(final byte[] c, final long d, final byte[] n, final byte[] k) {
    final byte[] s = new byte[32];
    cryptoCoreHsalsa20(s, n, k, sigma);
    return cryptoStreamSalsa20(c, d, n, 16, n.length - 16, s);
  }

  public static int cryptoStreamXor(final byte[] c, final byte[] m, final long d, final byte[] n, final byte[] k) {
    final byte[] s = new byte[32];
    cryptoCoreHsalsa20(s, n, k, sigma);
    return cryptoStreamSalsa20Xor(c, m, d, n, 16, n.length - 16, s);
  }

  /*
   * !!! Use TweetNaclFast.java onetimeauth function private static void
   * add1305(int [] h,int [] c) { int j; int u = 0; for (j = 0; j < 17; j ++) {
   * u = (u + ((h[j] + c[j]) | 0)) | 0; h[j] = u & 255; u >>>= 8; } } private
   * static final int minusp[] = { 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
   * 0, 252 }; private static int crypto_onetimeauth( byte[] out,final int
   * outoff,final int outlen, byte[] m,final int moff,final int mlen, long n,
   * byte [] k) { int i,j; int s,u; int [] x = new int[17], r = new int [17], h
   * = new int[17], c = new int [17], g = new int[17]; for (j = 0; j < 17; j ++)
   * r[j] = h[j] = 0; for (j = 0; j < 16; j ++) r[j] = k[j] & 0xff; r[3]&=15;
   * r[4]&=252; r[7]&=15; r[8]&=252; r[11]&=15; r[12]&=252; r[15]&=15; int
   * moffset = moff; while (n > 0) { for (j = 0; j < 17; j ++) c[j] = 0; for (j
   * = 0;(j < 16) && (j < n);++j) c[j] = m[j+moffset] & 0xff; c[j] = 1; moffset
   * += j; n -= j; add1305(h,c); for (i = 0; i < 17; i ++) { x[i] = 0; for (j =
   * 0; j < 17; j ++) x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 -
   * j]); for (j = 0; j < 17; j++) x[i] = (x[i] + (h[j] * ((j <= i) ? r[i - j] :
   * ((320 * r[i + 17 - j])|0))) | 0) | 0; } for (i = 0; i < 17; i ++) h[i] =
   * x[i]; u = 0; for (j = 0; j < 16; j ++) { u = (u + h[j]) | 0; h[j] = u &
   * 255; u >>>= 8; } u = (u + h[16]) | 0; h[16] = u & 3; u = (5 * (u >>> 2)) |
   * 0; for (j = 0; j < 16; j ++) { u = (u + h[j]) | 0; h[j] = u & 255; u >>>=
   * 8; } u = (u + h[16]) | 0; h[16] = u; } for (j = 0; j < 17; j ++) g[j] =
   * h[j]; add1305(h,minusp); s = (-(h[16] >>> 7) | 0); for (j = 0; j < 17; j
   * ++) h[j] ^= s & (g[j] ^ h[j]); for (j = 0; j < 16; j ++) c[j] = k[j + 16] &
   * 0xff; c[16] = 0; add1305(h,c); for (j = 0; j < 16; j ++) out[j+outoff] =
   * (byte) (h[j]&0xff); return 0; }
   */

  /**
   * Port of Andrew Moon's Poly1305-donna-16. Public domain.
   * https://github.com/floodyberry/poly1305-donna
   */
  private static int cryptoOneTimeAuth(final byte[] out, final int outpos, final int outlen, final byte[] m, final int mpos, final int mlen, final int n, final byte[] k) {
    final Poly1305 s = new Poly1305(k);
    s.update(m, mpos, n);
    s.finish(out, outpos);
    return 0;
  }

  public static int cryptoOneTimeAuth(final byte[] out, final byte[] m, final int n, final byte[] k) {
    return cryptoOneTimeAuth(out, 0, out.length, m, 0, m.length, n, k);
  }

  private static int cryptoOneTimeAuthVerify(final byte[] h, final int hoff, final int hlen, final byte[] m, final int moff, final int mlen, final int n, final byte[] k) {
    final byte[] x = new byte[16];
    cryptoOneTimeAuth(x, 0, x.length, m, moff, mlen, n, k);
    return cryptoVerify16(h, hoff, hlen, x, 0, x.length);
  }

  public static int cryptoOneTimeAuthVerify(final byte[] h, final byte[] m, final int n, final byte[] k) {
    return cryptoOneTimeAuthVerify(h, 0, h.length, m, 0, m.length, n, k);
  }

  public static int cryptoOneTimeAuthVerify(final byte[] h, final byte[] m, final byte[] k) {
    return cryptoOneTimeAuthVerify(h, m, m != null ? m.length : 0, k);
  }

  public static int cryptoSecretBox(final byte[] c, final byte[] m, final int d, final byte[] n, final byte[] k) {
    if (d < 32)
      return -1;

    cryptoStreamXor(c, m, d, n, k);
    cryptoOneTimeAuth(c, 16, c.length - 16, c, 32, c.length - 32, d - 32, c);
    return 0;
  }

  public static int cryptoSecretBoxOpen(final byte[] m, final byte[] c, final int d, final byte[] n, final byte[] k) {
    final byte[] x = new byte[32];
    if (d < 32)
      return -1;

    cryptoStream(x, 32, n, k);
    if (cryptoOneTimeAuthVerify(c, 16, 16, c, 32, c.length - 32, d - 32, x) != 0)
      return -1;

    cryptoStreamXor(m, c, d, n, k);
    return 0;
  }

  private static void set25519(final long[] r, final long[] a) {
    System.arraycopy(a, 0, r, 0, 16);
  }

  private static void car25519(final long[] o, final int ooff, final int olen) {
    long c;
    for (int i = 0; i < 16; ++i) {
      o[i + ooff] += (1L << 16);
      c = o[i + ooff] >> 16;
      o[(i + 1) * ((i < 15) ? 1 : 0) + ooff] += c - 1 + 37 * (c - 1) * ((i == 15) ? 1 : 0);
      o[i + ooff] -= (c << 16);
    }
  }

  private static void sel25519(final long[] p, final int poff, final int plen, final long[] q, final int qoff, final int qlen, final int b) {
    long t;
    final long c = -b;
    for (int i = 0; i < 16; ++i) {
      t = c & (p[i + poff] ^ q[i + qoff]);
      p[i + poff] ^= t;
      q[i + qoff] ^= t;
    }
  }

  private static void pack25519(final byte[] o, final long[] n, final int noff, final int nlen) {
    int i, j, b;
    final long[] m = new long[16];
    final long[] t = new long[16];
    for (i = 0; i < 16; ++i)
      t[i] = n[i + noff];

    car25519(t, 0, t.length);
    car25519(t, 0, t.length);
    car25519(t, 0, t.length);
    for (j = 0; j < 2; ++j) {
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; ++i) {
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }

      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (int)((m[15] >> 16) & 1);
      m[14] &= 0xffff;
      sel25519(t, 0, t.length, m, 0, m.length, 1 - b);
    }

    for (i = 0; i < 16; ++i) {
      o[2 * i] = (byte)(t[i] & 0xff);
      o[2 * i + 1] = (byte)(t[i] >> 8);
    }
  }

  private static int neq25519(final long[] a, final long[] b) {
    final byte[] c = new byte[32];
    final byte[] d = new byte[32];
    pack25519(c, a, 0, a.length);
    pack25519(d, b, 0, b.length);
    return cryptoVerify32(c, 0, c.length, d, 0, d.length);
  }

  private static byte par25519(final long[] a) {
    final byte[] d = new byte[32];
    pack25519(d, a, 0, a.length);
    return (byte)(d[0] & 1);
  }

  private static void unpack25519(final long[] o, final byte[] n) {
    for (int i = 0; i < 16; ++i)
      o[i] = (n[2 * i] & 0xff) + ((long)((n[2 * i + 1] << 8) & 0xffff));

    o[15] &= 0x7fff;
  }

  private static void A(final long[] o, final int ooff, final int olen, final long[] a, final int aoff, final int alen, final long[] b, final int boff, final int blen) {
    for (int i = 0; i < 16; ++i)
      o[i + ooff] = a[i + aoff] + b[i + boff];
  }

  private static void Z(final long[] o, final int ooff, final int olen, final long[] a, final int aoff, final int alen, final long[] b, final int boff, final int blen) {
    for (int i = 0; i < 16; ++i)
      o[i + ooff] = a[i + aoff] - b[i + boff];
  }

  private static void M(final long[] o, final int ooff, final int olen, final long[] a, final int aoff, final int alen, final long[] b, final int boff, final int blen) {
    int i, j;
    final long[] t = new long[31];
    for (i = 0; i < 31; ++i)
      t[i] = 0;

    for (i = 0; i < 16; ++i)
      for (j = 0; j < 16; ++j)
        t[i + j] += a[i + aoff] * b[j + boff];

    for (i = 0; i < 15; ++i)
      t[i] += 38 * t[i + 16];

    for (i = 0; i < 16; ++i)
      o[i + ooff] = t[i];

    car25519(o, ooff, olen);
    car25519(o, ooff, olen);
  }

  private static void S(final long[] o, final int ooff, final int olen, final long[] a, final int aoff, final int alen) {
    M(o, ooff, olen, a, aoff, alen, a, aoff, alen);
  }

  private static void inv25519(final long[] o, final int ooff, final int olen, final long[] i, final int ioff, final int ilen) {
    final long[] c = new long[16];
    int a;
    for (a = 0; a < 16; ++a)
      c[a] = i[a + ioff];

    for (a = 253; a >= 0; --a) {
      S(c, 0, c.length, c, 0, c.length);
      if (a != 2 && a != 4)
        M(c, 0, c.length, c, 0, c.length, i, ioff, ilen);
    }

    for (a = 0; a < 16; ++a)
      o[a + ooff] = c[a];
  }

  private static void pow2523(final long[] o, final long[] i) {
    final long[] c = new long[16];
    int a;
    for (a = 0; a < 16; ++a)
      c[a] = i[a];

    for (a = 250; a >= 0; --a) {
      S(c, 0, c.length, c, 0, c.length);
      if (a != 1)
        M(c, 0, c.length, c, 0, c.length, i, 0, i.length);
    }

    for (a = 0; a < 16; ++a)
      o[a] = c[a];
  }

  public static int cryptoScalarMult(final byte[] q, final byte[] n, final byte[] p) {
    final byte[] z = new byte[32];
    final long[] x = new long[80];
    int i;
    final long[] a = new long[16], b = new long[16], c = new long[16], d = new long[16], e = new long[16], f = new long[16];
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
    i = 254;
    for (int r; i >= 0; --i) {
      r = (z[i >>> 3] >>> (i & 7)) & 1;
      sel25519(a, 0, a.length, b, 0, b.length, r);
      sel25519(c, 0, c.length, d, 0, d.length, r);
      A(e, 0, e.length, a, 0, a.length, c, 0, c.length);
      Z(a, 0, a.length, a, 0, a.length, c, 0, c.length);
      A(c, 0, c.length, b, 0, b.length, d, 0, d.length);
      Z(b, 0, b.length, b, 0, b.length, d, 0, d.length);
      S(d, 0, d.length, e, 0, e.length);
      S(f, 0, f.length, a, 0, a.length);
      M(a, 0, a.length, c, 0, c.length, a, 0, a.length);
      M(c, 0, c.length, b, 0, b.length, e, 0, e.length);
      A(e, 0, e.length, a, 0, a.length, c, 0, c.length);
      Z(a, 0, a.length, a, 0, a.length, c, 0, c.length);
      S(b, 0, b.length, a, 0, a.length);
      Z(c, 0, c.length, d, 0, d.length, f, 0, f.length);
      M(a, 0, a.length, c, 0, c.length, _121665, 0, _121665.length);
      A(a, 0, a.length, a, 0, a.length, d, 0, d.length);
      M(c, 0, c.length, c, 0, c.length, a, 0, a.length);
      M(a, 0, a.length, d, 0, d.length, f, 0, f.length);
      M(d, 0, d.length, b, 0, b.length, x, 0, x.length);
      S(b, 0, b.length, e, 0, e.length);
      sel25519(a, 0, a.length, b, 0, b.length, r);
      sel25519(c, 0, c.length, d, 0, d.length, r);
    }

    for (i = 0; i < 16; ++i) {
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }

    inv25519(x, 32, x.length - 32, x, 32, x.length - 32);
    M(x, 16, x.length - 16, x, 16, x.length - 16, x, 32, x.length - 32);
    pack25519(q, x, 16, x.length - 16);
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
    return cryptoCoreHsalsa20(k, _0, s, sigma);
  }

  public static int cryptoBoxAfterNm(final byte[] c, final byte[] m, final int d, final byte[] n, final byte[] k) {
    return cryptoSecretBox(c, m, d, n, k);
  }

  public static int cryptoBoxOpenAfterNm(final byte[] m, final byte[] c, final int d, final byte[] n, final byte[] k) {
    return cryptoSecretBoxOpen(m, c, d, n, k);
  }

  public static int cryptoBox(final byte[] c, final byte[] m, final int d, final byte[] n, final byte[] y, final byte[] x) {
    final byte[] k = new byte[32];
    cryptoBoxBeforeNm(k, y, x);
    return cryptoBoxAfterNm(c, m, d, n, k);
  }

  public static int cryptoBoxOpen(final byte[] m, final byte[] c, final int d, final byte[] n, final byte[] y, final byte[] x) {
    final byte[] k = new byte[32];
    cryptoBoxBeforeNm(k, y, x);
    return cryptoBoxOpenAfterNm(m, c, d, n, k);
  }

  private static void add(final long[][] p, final long[][] q) {
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

    Z(a, 0, a.length, p1, 0, p1.length, p0, 0, p0.length);
    Z(t, 0, t.length, q1, 0, q1.length, q0, 0, q0.length);
    M(a, 0, a.length, a, 0, a.length, t, 0, t.length);
    A(b, 0, b.length, p0, 0, p0.length, p1, 0, p1.length);
    A(t, 0, t.length, q0, 0, q0.length, q1, 0, q1.length);
    M(b, 0, b.length, b, 0, b.length, t, 0, t.length);
    M(c, 0, c.length, p3, 0, p3.length, q3, 0, q3.length);
    M(c, 0, c.length, c, 0, c.length, D2, 0, D2.length);
    M(d, 0, d.length, p2, 0, p2.length, q2, 0, q2.length);

    A(d, 0, d.length, d, 0, d.length, d, 0, d.length);
    Z(e, 0, e.length, b, 0, b.length, a, 0, a.length);
    Z(f, 0, f.length, d, 0, d.length, c, 0, c.length);
    A(g, 0, g.length, d, 0, d.length, c, 0, c.length);
    A(h, 0, h.length, b, 0, b.length, a, 0, a.length);

    M(p0, 0, p0.length, e, 0, e.length, f, 0, f.length);
    M(p1, 0, p1.length, h, 0, h.length, g, 0, g.length);
    M(p2, 0, p2.length, g, 0, g.length, f, 0, f.length);
    M(p3, 0, p3.length, e, 0, e.length, h, 0, h.length);
  }

  private static void cswap(final long[][] p, final long[][] q, final byte b) {
    for (int i = 0; i < 4; ++i)
      sel25519(p[i], 0, p[i].length, q[i], 0, q[i].length, b);
  }

  private static void pack(final byte[] r, final long[][] p) {
    final long[] tx = new long[16];
    final long[] ty = new long[16];
    final long[] zi = new long[16];

    inv25519(zi, 0, zi.length, p[2], 0, p[2].length);

    M(tx, 0, tx.length, p[0], 0, p[0].length, zi, 0, zi.length);
    M(ty, 0, ty.length, p[1], 0, p[1].length, zi, 0, zi.length);

    pack25519(r, ty, 0, ty.length);

    r[31] ^= par25519(tx) << 7;
  }

  private static void scalarmult(final long[][] p, final long[][] q, final byte[] s, final int soff, final int slen) {
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);

    for (int i = 255; i >= 0; --i) {
      final byte b = (byte)((s[i / 8 + soff] >> (i & 7)) & 1);

      cswap(p, q, b);
      add(q, p);
      add(p, p);
      cswap(p, q, b);
    }
  }

  private static void scalarbase(final long[][] p, final byte[] s, final int soff, final int slen) {
    final long[][] q = new long[4][];

    q[0] = new long[16];
    q[1] = new long[16];
    q[2] = new long[16];
    q[3] = new long[16];

    set25519(q[0], X);
    set25519(q[1], Y);
    set25519(q[2], gf1);
    M(q[3], 0, q[3].length, X, 0, X.length, Y, 0, Y.length);
    scalarmult(p, q, s, soff, slen);
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

    Hash.cryptoHash(d, sk, 0, sk.length, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d, 0, d.length);
    pack(pk, p);
    System.arraycopy(pk, 0, sk, 32, 32);

    return 0;
  }

  private static final long[] L = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

  private static void modL(final byte[] r, final int roff, final int rlen, final long[] x) {
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

    for (j = 0; j < 32; ++j) {
      x[j] += carry - (x[31] >> 4) * L[j];
      carry = x[j] >> 8;
      x[j] &= 255;
    }

    for (j = 0; j < 32; ++j)
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

    modL(r, 0, r.length, x);
  }

  // TBD... 64bits of n
  public static int cryptoSign(final byte[] sm, final long dummy /*smlen not used*/, final byte[] m, final int/* long*/ n, final byte[] sk) {
    final byte[] d = new byte[64];
    final byte[] h = new byte[64];
    final byte[] r = new byte[64];

    final long[] x = new long[64];

    final long[][] p = new long[4][];
    p[0] = new long[16];
    p[1] = new long[16];
    p[2] = new long[16];
    p[3] = new long[16];

    Hash.cryptoHash(d, sk, 0, sk.length, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    int i;
    for (i = 0; i < n; ++i)
      sm[64 + i] = m[i];

    for (i = 0; i < 32; ++i)
      sm[32 + i] = d[32 + i];

    Hash.cryptoHash(r, sm, 32, sm.length - 32, n + 32);
    reduce(r);
    scalarbase(p, r, 0, r.length);
    pack(sm, p);

    for (i = 0; i < 32; ++i)
      sm[i + 32] = sk[i + 32];

    Hash.cryptoHash(h, sm, 0, sm.length, n + 64);
    reduce(h);

    for (i = 0; i < 64; ++i)
      x[i] = 0;

    for (i = 0; i < 32; ++i)
      x[i] = r[i] & 0xff;

    for (i = 0; i < 32; ++i)
      for (int j = 0; j < 32; ++j)
        x[i + j] += (h[i] & 0xff) * (long)(d[j] & 0xff);

    modL(sm, 32, sm.length - 32, x);
    return 0;
  }

  private static int unpackneg(final long[][] r, final byte[] p) {
    final long[] t = new long[16];
    final long[] chk = new long[16];
    final long[] num = new long[16];
    final long[] den = new long[16];
    final long[] den2 = new long[16];
    final long[] den4 = new long[16];
    final long[] den6 = new long[16];

    set25519(r[2], gf1);
    unpack25519(r[1], p);
    S(num, 0, num.length, r[1], 0, r[1].length);
    M(den, 0, den.length, num, 0, num.length, D, 0, D.length);
    Z(num, 0, num.length, num, 0, num.length, r[2], 0, r[2].length);
    A(den, 0, den.length, r[2], 0, r[2].length, den, 0, den.length);

    S(den2, 0, den2.length, den, 0, den.length);
    S(den4, 0, den4.length, den2, 0, den2.length);
    M(den6, 0, den6.length, den4, 0, den4.length, den2, 0, den2.length);
    M(t, 0, t.length, den6, 0, den6.length, num, 0, num.length);
    M(t, 0, t.length, t, 0, t.length, den, 0, den.length);

    pow2523(t, t);
    M(t, 0, t.length, t, 0, t.length, num, 0, num.length);
    M(t, 0, t.length, t, 0, t.length, den, 0, den.length);
    M(t, 0, t.length, t, 0, t.length, den, 0, den.length);
    M(r[0], 0, r[0].length, t, 0, t.length, den, 0, den.length);

    S(chk, 0, chk.length, r[0], 0, r[0].length);
    M(chk, 0, chk.length, chk, 0, chk.length, den, 0, den.length);
    if (neq25519(chk, num) != 0)
      M(r[0], 0, r[0].length, r[0], 0, r[0].length, I, 0, I.length);

    S(chk, 0, chk.length, r[0], 0, r[0].length);
    M(chk, 0, chk.length, chk, 0, chk.length, den, 0, den.length);
    if (neq25519(chk, num) != 0)
      return -1;

    if (par25519(r[0]) == ((p[31] & 0xFF) >> 7))
      Z(r[0], 0, r[0].length, gf0, 0, gf0.length, r[0], 0, r[0].length);

    M(r[3], 0, r[3].length, r[0], 0, r[0].length, r[1], 0, r[1].length);
    return 0;
  }

  public static int cryptoSignOpen(final byte[] m, final long dummy /*mlen not used*/, final byte[] sm, int/*long*/ n, final byte[] pk) {
    int i;
    final byte[] t = new byte[32];
    final byte[] h = new byte[64];

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

    for (i = 0; i < n; ++i)
      m[i] = sm[i];

    for (i = 0; i < 32; ++i)
      m[i + 32] = pk[i];

    Hash.cryptoHash(h, m, 0, m.length, n);

    reduce(h);
    scalarmult(p, q, h, 0, h.length);

    scalarbase(q, sm, 32, sm.length - 32);
    add(p, q);
    pack(t, p);

    n -= 64;
    if (cryptoVerify32(sm, 0, sm.length, t, 0, t.length) != 0)
      return -1;

    // TBD optimizing ...
    return 0;
  }

  /** Java SecureRandom generator. */
  private static final SecureRandom random = new SecureRandom();

  public static void randombytes(final byte[] x, final int len) {
    final int ret = len % 8;
    long rnd;
    for (int i = 0; i < len - ret; i += 8) {
      rnd = random.nextLong();

      x[i + 0] = (byte)(rnd);
      x[i + 1] = (byte)(rnd >>> 8);
      x[i + 2] = (byte)(rnd >>> 16);
      x[i + 3] = (byte)(rnd >>> 24);
      x[i + 4] = (byte)(rnd >>> 32);
      x[i + 5] = (byte)(rnd >>> 40);
      x[i + 6] = (byte)(rnd >>> 48);
      x[i + 7] = (byte)(rnd >>> 56);
    }

    if (ret > 0) {
      rnd = random.nextLong();
      for (int i = len - ret; i < len; ++i)
        x[i] = (byte)(rnd >>> 8 * i);
    }
  }

  private TweetNacl() {
  }
}