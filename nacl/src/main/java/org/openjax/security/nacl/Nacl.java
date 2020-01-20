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

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicLong;

public abstract class Nacl {
  /** Length of public key in bytes. */
  public static final int publicKeyLength = 32;

  /** Length of secret key in bytes. */
  public static final int secretKeyLength = 32;

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

  /** Length of seed for nacl.sign.keyPair.fromSeed in bytes. */
  public static final int seedLength = 32;

  /**
   * Codes below are ported tweetnacl-fast.js from TweetNacl.c/TweetNacl.h
   */

  /** Java SecureRandom generator */
  static final SecureRandom random = new SecureRandom();

  static final byte[] _0 = new byte[16];
  static final byte[] _9 = new byte[32];

  static final long[] gf0 = new long[16];
  static final long[] gf1 = new long[16];
  static final long[] _121665 = new long[16];

  // "expand 32-byte k"
  static final byte[] sigma = {101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107};

  static {
    _9[0] = 9;

    gf1[0] = 1;
    _121665[0] = 0xDB41;
    _121665[1] = 1;
  }

  /**
   * Box algorithm, Public-key authenticated encryption
   */
  public abstract class Box {
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

    final AtomicLong nonce;
    final byte[] theirPublicKey;
    final byte[] mySecretKey;
    byte[] sharedKey;

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

    public final void setNonce(final long nonce) {
      this.nonce.set(nonce);
    }

    public final long getNonce() {
      return this.nonce.get();
    }

    public final long incrNonce() {
      return this.nonce.incrementAndGet();
    }

    final byte[] generateNonce() {
      // generate nonce
      final long nonce = this.nonce.get();
      final byte[] n = new byte[nonceLength];
      for (int i = 0; i < nonceLength;) {
        n[i++] = (byte)(nonce);
        n[i++] = (byte)(nonce >>> 8);
        n[i++] = (byte)(nonce >>> 16);
        n[i++] = (byte)(nonce >>> 24);
        n[i++] = (byte)(nonce >>> 32);
        n[i++] = (byte)(nonce >>> 40);
        n[i++] = (byte)(nonce >>> 48);
        n[i++] = (byte)(nonce >>> 56);
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
    public abstract byte[] box(final byte[] message);

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
    public abstract byte[] box(final byte[] message, final byte[] nonce);

    /**
     * Authenticates and decrypts the given box with peer's public key, our
     * secret key, and the given nonce.
     *
     * @param box The box.
     * @return The original message, or {@code null} if authentication fails.
     */
    public abstract byte[] open(final byte[] box);

    /**
     * Authenticates and decrypts the given box with peer's public key, our
     * secret key, and the explicitly provided nonce.
     *
     * @param box The box.
     * @param nonce The nonce.
     * @return The original message, or {@code null} if authentication fails.
     */
    public abstract byte[] open(final byte[] box, final byte[] nonce);

    /**
     * Returns a precomputed shared key which can be used in nacl.box.after and
     * nacl.box.open.after.
     *
     * @return A precomputed shared key which can be used in nacl.box.after and
     *         nacl.box.open.after.
     */
    public final byte[] before() {
      if (this.sharedKey == null) {
        this.sharedKey = new byte[sharedKeyLength];
        cryptoBoxBeforeNm(this.sharedKey, this.theirPublicKey, this.mySecretKey);
      }

      return this.sharedKey;
    }
  }

  /**
   * Secret Box algorithm, secret key
   */
  public abstract class SecretBox {
    final AtomicLong nonce;
    final byte[] key;

    public SecretBox(final byte[] key) {
      this(key, 68);
    }

    public SecretBox(final byte[] key, final long nonce) {
      this.key = key;

      this.nonce = new AtomicLong(nonce);
    }

    public final void setNonce(final long nonce) {
      this.nonce.set(nonce);
    }

    public final long getNonce() {
      return this.nonce.get();
    }

    public final long incNonce() {
      return this.nonce.incrementAndGet();
    }

    final byte[] generateNonce() {
      // generate nonce
      final long nonce = this.nonce.get();
      final byte[] n = new byte[nonceLength];
      for (int i = 0; i < nonceLength;) {
        n[i++] = (byte)(nonce);
        n[i++] = (byte)(nonce >>> 8);
        n[i++] = (byte)(nonce >>> 16);
        n[i++] = (byte)(nonce >>> 24);
        n[i++] = (byte)(nonce >>> 32);
        n[i++] = (byte)(nonce >>> 40);
        n[i++] = (byte)(nonce >>> 48);
        n[i++] = (byte)(nonce >>> 56);
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
    public abstract byte[] box(final byte[] message);

    /**
     * Authenticates and decrypts the given secret box using the key and the
     * nonce.
     *
     * @param box The box.
     * @return The original message, or {@code null} if authentication fails.
     */
    public abstract byte[] open(byte[] box);

    /**
     * Encrypt and authenticates message using the key and the explicitly passed
     * nonce. The nonce must be unique for each distinct message for this key.
     *
     * @param message The message.
     * @param nonce The nonce.
     * @return An encrypted and authenticated message, which is
     *         nacl.secretbox.overheadLength longer than the original message.
     */
    public abstract byte[] box(byte[] message, byte[] nonce);

    /**
     * Authenticates and decrypts the given secret box using the key and the
     * explicitly passed nonce.
     *
     * @param box The box.
     * @param nonce The nonce.
     * @return The original message, or {@code null} if authentication fails.
     */
    public abstract byte[] open(byte[] box, byte[] nonce);
  }

  /**
   * Signature algorithm, Implements ed25519.
   */
  public abstract class Signature {
    /** Length of signature in bytes. */
    public static final int signatureLength = 64;

    /** Length of public key in bytes. */
    public static final int publicKeyLength = 32;

    /** Length of signing secret key in bytes. */
    public static final int secretKeyLength = 64;

    final byte[] theirPublicKey;
    final byte[] mySecretKey;

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
    public abstract byte[] sign(final byte[] message);

    /**
     * Signs the message using the secret key.
     *
     * @param message The message.
     * @return The signature.
     */
    public final byte[] detached(final byte[] message) {
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
    public final boolean detachedVerify(final byte[] message, final byte[] signature) {
      if (signature.length != signatureLength)
        return false;

      if (theirPublicKey.length != publicKeyLength)
        return false;

      final byte[] sm = new byte[signatureLength + message.length];
      final byte[] m = new byte[signatureLength + message.length];
      System.arraycopy(signature, 0, sm, 0, signatureLength);

      System.arraycopy(message, 0, sm, 64, message.length);

      return cryptoSignOpen(m, -1, sm, 0, sm.length, theirPublicKey) >= 0;
    }

    /**
     * Verifies the signed message.
     *
     * @param signedMessage The signed message.
     * @return The message without signature, or {@code null} if verification
     *         fails.
     */
    public abstract byte[] open(byte[] signedMessage);
  }

  public class ScalarMult {
    /** Length of scalar in bytes. */
    public static final int scalarLength = 32;

    /** Length of group element in bytes. */
    public static final int groupElementLength = 32;

    /**
     * Multiplies an integer n by a group element p.
     *
     * @param n The integer.
     * @param p The group element.
     * @return The resulting group element.
     */
    public byte[] scalseMult(final byte[] n, final byte[] p) {
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
    public byte[] scalseMult(final byte[] n) {
      if (n.length != scalarLength)
        return null;

      final byte[] q = new byte[scalarLength];
      cryptoScalarMultBase(q, n);
      return q;
    }

    private ScalarMult() {
    }
  }

  public final KeyPair keyPairFromSeed(final byte[] seed) {
    final KeyPair kp = new KeyPair(Signature.publicKeyLength, Signature.secretKeyLength);
    final byte[] pk = kp.getPublicKey();
    final byte[] sk = kp.getSecretKey();

    // copy sk
    System.arraycopy(seed, 0, sk, 0, seedLength);

    // generate pk from sk
    cryptoSignKeyPair(pk, sk, true);
    return kp;
  }

  /**
   * Returns a new random key pair for box and returns it as an object with
   * publicKey and secretKey members.
   *
   * @return A new random key pair for box and returns it as an object with
   *         publicKey and secretKey members.
   */
  public final KeyPair keyPair() {
    final KeyPair kp = new KeyPair(publicKeyLength, secretKeyLength);
    cryptoBoxKeyPair(kp.getPublicKey(), kp.getSecretKey());
    return kp;
  }

  public final KeyPair keyPair(final byte[] secretKey) {
    final KeyPair kp = new KeyPair(publicKeyLength, secretKeyLength);
    final byte[] sk = kp.getSecretKey();
    final byte[] pk = kp.getPublicKey();

    // copy sk
    System.arraycopy(secretKey, 0, sk, 0, sk.length);

    cryptoScalarMultBase(pk, sk);
    return kp;
  }

  /**
   * Signs the message using the secret key.
   *
   * @return A signed message.
   */
  public final KeyPair keyPairForSignature() {
    final KeyPair kp = new KeyPair(Signature.publicKeyLength, Signature.secretKeyLength);
    cryptoSignKeyPair(kp.getPublicKey(), kp.getSecretKey(), false);
    return kp;
  }

  public static KeyPair keyPairForSignature(final byte[] secretKey) {
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

  public final void cryptoScalarMultBase(final byte[] q, final byte[] n) {
    cryptoScalarMult(q, n, _9);
  }

  public final void cryptoBoxKeyPair(final byte[] y, final byte[] x) {
    randombytes(x, 32);
    cryptoScalarMultBase(y, x);
  }

  public final void cryptoBoxBeforeNm(final byte[] k, final byte[] y, final byte[] x) {
    final byte[] s = new byte[32];
    cryptoScalarMult(s, x, y);

    /*
     * String dbgt = ""; for (int dbg = 0; dbg < s.length; dbg ++) dbgt +=
     * " "+s[dbg]; Log.d(TAG, "crypto_box_beforenm -> "+dbgt); dbgt = ""; for
     * (int dbg = 0; dbg < x.length; dbg ++) dbgt += " "+x[dbg]; Log.d(TAG,
     * "crypto_box_beforenm, x -> "+dbgt); dbgt = ""; for (int dbg = 0; dbg <
     * y.length; dbg ++) dbgt += " "+y[dbg]; Log.d(TAG,
     * "crypto_box_beforenm, y -> "+dbgt);
     */

    cryptoCoreHsalsa20(k, _0, s, sigma);
  }

  public final int cryptoBoxAfterNm(final byte[] c, final byte[] m, final int d, final byte[] n, final byte[] k) {
    return cryptoSecretBox(c, m, d, n, k);
  }

  public final int cryptoBoxOpenAfterNm(final byte[] m, final byte[] c, final int d, final byte[] n, final byte[] k) {
    return cryptoSecretBoxOpen(m, c, d, n, k);
  }

  public final int cryptoBox(final byte[] c, final byte[] m, final int d, final byte[] n, final byte[] y, final byte[] x) {
    final byte[] k = new byte[32];
    cryptoBoxBeforeNm(k, y, x);
    return cryptoBoxAfterNm(c, m, d, n, k);
  }

  public final int cryptoBoxOpen(final byte[] m, final byte[] c, final int d, final byte[] n, final byte[] y, final byte[] x) {
    final byte[] k = new byte[32];
    cryptoBoxBeforeNm(k, y, x);
    return cryptoBoxOpenAfterNm(m, c, d, n, k);
  }

  /**
   * Port of Andrew Moon's Poly1305-donna-16. Public domain.
   * https://github.com/floodyberry/poly1305-donna
   */
  static int cryptoOneTimeAuth(final byte[] out, final int outpos, final byte[] m, final int mpos, final int n, final byte[] k) {
    final Poly1305 s = new Poly1305(k);
    s.update(m, mpos, n);
    s.finish(out, outpos);
    return 0;
  }

  public final static int cryptoOneTimeAuth(final byte[] out, final byte[] m, final int n, final byte[] k) {
    return cryptoOneTimeAuth(out, 0, m, 0, n, k);
  }

  static void unpack25519(final long[] o, final byte[] n) {
    for (int i = 0; i < 16; ++i)
      o[i] = (n[2 * i] & 0xff) + ((long)((n[2 * i + 1] << 8) & 0xffff));

    o[15] &= 0x7fff;
  }

  static void reduce(final byte[] r) {
    final long[] x = new long[64];
    int i;
    for (i = 0; i < 64; ++i)
      x[i] = r[i] & 0xff;

    for (i = 0; i < 64; ++i)
      r[i] = 0;

    modL(r, 0, x);
  }

  static void modL(final byte[] r, final int roff, final long[] x) {
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

  static final long[] D = {0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203};
  static final long[] D2 = {0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406};
  static final long[] X = {0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169};
  static final long[] Y = {0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666};
  static final long[] I = {0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83};

  static final long[] L = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};

  static void set25519(final long[] r, final long[] a) {
    System.arraycopy(a, 0, r, 0, 16);
  }

  static byte[] hexDecode(final String s) {
    final byte[] b = new byte[s.length() / 2];
    for (int i = 0; i < s.length(); i += 2)
      b[i / 2] = (byte)((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));

    return b;
  }

  static void sel25519(final long[] p, final int poff, final long[] q, final int qoff, final int b) {
    long t;
    final long c = -b;
    for (int i = 0; i < 16; ++i) {
      t = c & (p[i + poff] ^ q[i + qoff]);
      p[i + poff] ^= t;
      q[i + qoff] ^= t;
    }
  }

  static int vn(final byte[] x, final int xoff, final byte[] y, final int yoff, final int n) {
    int d = 0;
    for (int i = 0; i < n; ++i)
      d |= (x[i + xoff] ^ y[i + yoff]) & 0xff;

    return (1 & ((d - 1) >>> 8)) - 1;
  }

  static void cswap(final long[][] p, final long[][] q, final byte b) {
    for (int i = 0; i < 4; ++i)
      sel25519(p[i], 0, q[i], 0, b);
  }

  abstract Box newBox(byte[] publicKey, byte[] privateKey);
  abstract Box newBox(byte[] publicKey, byte[] privateKey, long nonce);
  abstract SecretBox newSecretBox(byte[] key);
  abstract SecretBox newSecretBox(byte[] key, long nonce);
  abstract Signature newSignature(byte[] theirPublicKey, byte[] mySecretKey);
  abstract byte[] randombytes(byte[] x, int len);
  abstract void cryptoScalarMult(byte[] q, byte[] n, byte[] p);
  abstract int cryptoSecretBox(byte[] c, byte[] m, int d, byte[] n, byte[] k);
  abstract int cryptoSecretBoxOpen(byte[] m, byte[] c, int d, byte[] n, byte[] k);
  abstract int cryptoSignOpen(byte[] m, long dummy, byte[] sm, int smoff, int/*long*/ n, byte[] pk);
  public abstract void cryptoCoreHsalsa20(byte[] out, byte[] in, byte[] k, byte[] c);
  public abstract int cryptoSignKeyPair(byte[] pk, byte[] sk, boolean seeded);
}