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

/**
 * TweetNacl.c Java Port
 */
@SuppressWarnings("unused")
public final class NaclTweetFast extends Nacl {
  /**
   * Box algorithm, Public-key authenticated encryption
   */
  static final class Box extends Nacl.Box {
    Box(final Nacl nacl, final byte[] theirPublicKey, final byte[] mySecretKey) {
      super(nacl, theirPublicKey, mySecretKey, 68);
    }

    Box(final Nacl nacl, final byte[] theirPublicKey, final byte[] mySecretKey, final long nonce) {
      super(nacl, theirPublicKey, mySecretKey, nonce);
    }

    @Override
    public byte[] box(final byte[] message) {
      return message == null ? null : box(message, 0, message.length);
    }

    private byte[] box(final byte[] message, final int moff) {
      if (message == null || message.length <= moff)
        return null;

      return box(message, moff, message.length - moff);
    }

    private byte[] box(final byte[] message, final int moff, final int mlen) {
      if (message == null || message.length < moff + mlen)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return after(message, moff, mlen);
    }

    /**
     * Encrypt and authenticates message using peer's public key, our secret key, and the given nonce, which must be unique for each
     * distinct // [A] message for a key pair. // [A]
     *
     * @param message The message.
     * @param nonce The nonce.
     * @return An encrypted and authenticated message, which is nacl.secretbox.overheadLength longer than the original message.
     */
    @Override
    public byte[] box(final byte[] message, final byte[] nonce) {
      return message == null ? null : box(message, 0, message.length, nonce);
    }

    private byte[] box(final byte[] message, final int moff, final byte[] nonce) {
      if (message == null || message.length <= moff)
        return null;

      return box(message, moff, message.length - moff, nonce);
    }

    private byte[] box(final byte[] message, final int moff, final int mlen, final byte[] nonce) {
      if (message == null || message.length < moff + mlen || nonce == null || nonce.length != nonceLength)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return after(message, moff, mlen, nonce);
    }

    @Override
    public byte[] open(final byte[] box) {
      if (box == null)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return openAfter(box, 0, box.length);
    }

    private byte[] open(final byte[] box, final int boxoff) {
      if (box == null || box.length <= boxoff)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return openAfter(box, boxoff, box.length - boxoff);
    }

    private byte[] open(final byte[] box, final int boxoff, final int boxlen) {
      if (box == null || box.length < boxoff + boxlen)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return openAfter(box, boxoff, boxlen);
    }

    @Override
    public byte[] open(final byte[] box, final byte[] nonce) {
      // check message
      if (box == null || nonce == null || nonce.length != nonceLength)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return openAfter(box, 0, box.length, nonce);
    }

    private byte[] open(final byte[] box, final int boxoff, final byte[] nonce) {
      if (box == null || box.length <= boxoff || nonce == null || nonce.length != nonceLength)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return openAfter(box, boxoff, box.length - boxoff, nonce);
    }

    private byte[] open(final byte[] box, final int boxoff, final int boxlen, final byte[] nonce) {
      if (box == null || box.length < boxoff + boxlen || nonce == null || nonce.length != nonceLength)
        return null;

      // prepare shared key
      if (this.sharedKey == null)
        before();

      return openAfter(box, boxoff, boxlen, nonce);
    }

    /**
     * Same as nacl.box, but uses a shared key precomputed with nacl.box.before.
     *
     * @param message The message.
     * @param moff The m offset.
     * @param mlen The m length.
     * @return An encrypted and authenticated message, which is nacl.box.overheadLength longer than the original message.
     */
    private byte[] after(final byte[] message, final int moff, final int mlen) {
      return after(message, moff, mlen, generateNonce());
    }

    /**
     * Same as nacl.box, but uses a shared key precomputed with nacl.box.before, and passes a nonce explicitly.
     *
     * @param message The message.
     * @param moff The m offset.
     * @param mlen The m length.
     * @param nonce The nonce.
     * @return An encrypted and authenticated message, which is nacl.box.overheadLength longer than the original message.
     */
    private byte[] after(final byte[] message, final int moff, final int mlen, final byte[] nonce) {
      // check message
      if (!(message != null && message.length >= (moff + mlen) && nonce != null && nonce.length == nonceLength))
        return null;

      // message buffer
      final byte[] m = new byte[mlen + zerobytesLength];

      // cipher buffer
      final byte[] c = new byte[m.length];

      if (mlen >= 0)
        System.arraycopy(message, 0 + moff, m, 32, mlen);

      if (0 != nacl.cryptoBoxAfterNm(c, m, m.length, nonce, sharedKey))
        return null;

      final byte[] ret = new byte[c.length - boxzerobytesLength];
      System.arraycopy(c, 16, ret, 0, ret.length);

      return ret;
    }

    /**
     * Same as nacl.box.open, but uses a shared key precomputed with nacl.box.before.
     *
     * @param box The box.
     * @param boxoff The box offset.
     * @param boxlen The box length.
     * @return An encrypted and authenticated message, which is nacl.box.overheadLength longer than the original message.
     */
    private byte[] openAfter(final byte[] box, final int boxoff, final int boxlen) {
      return openAfter(box, boxoff, boxlen, generateNonce());
    }

    /**
     * Same as nacl.box.open, but uses a shared key precomputed with nacl.box.before, and explicitly passed nonce
     *
     * @param box The box.
     * @param nonce The nonce.
     * @return The original message, or {@code null} if authentication fails.
     */
    private byte[] openAfter(final byte[] box, final int boxoff, final int boxlen, final byte[] nonce) {
      // check message
      if (!(box != null && box.length >= (boxoff + boxlen) && boxlen >= boxzerobytesLength))
        return null;

      // cipher buffer
      final byte[] c = new byte[boxlen + boxzerobytesLength];

      // message buffer
      final byte[] m = new byte[c.length];

      System.arraycopy(box, 0 + boxoff, c, 16, boxlen);

      if (nacl.cryptoBoxOpenAfterNm(m, c, c.length, nonce, sharedKey) != 0)
        return null;

      final byte[] ret = new byte[m.length - zerobytesLength];
      System.arraycopy(m, 32, ret, 0, ret.length);

      return ret;
    }
  }

  @Override
  public Box newBox(final byte[] publicKey, final byte[] privateKey) {
    return new Box(this, publicKey, privateKey);
  }

  @Override
  public Box newBox(final byte[] publicKey, final byte[] privateKey, final long nonce) {
    return new Box(this, publicKey, privateKey, nonce);
  }

  @Override
  public SecretBox newSecretBox(final byte[] key) {
    return new SecretBox(key);
  }

  @Override
  public SecretBox newSecretBox(final byte[] key, final long nonce) {
    return new SecretBox(key, nonce);
  }

  @Override
  public Signature newSignature(final byte[] theirPublicKey, final byte[] mySecretKey) {
    return new Signature(theirPublicKey, mySecretKey);
  }

  /**
   * Secret Box algorithm, secret key
   */
  final class SecretBox extends Nacl.SecretBox {
    SecretBox(final byte[] key) {
      super(key, 68);
    }

    SecretBox(final byte[] key, final long nonce) {
      super(key, nonce);
    }

    private byte[] box(final byte[] message, final int moff) {
      if (!(message != null && message.length > moff))
        return null;

      return box(message, moff, message.length - moff);
    }

    private byte[] box(final byte[] message, final int moff, final int mlen) {
      // check message
      if (!(message != null && message.length >= (moff + mlen)))
        return null;

      return box(message, moff, message.length - moff, generateNonce());
    }

    @Override
    public byte[] box(final byte[] message) {
      return message == null ? null : box(message, 0, message.length);
    }

    @Override
    public byte[] box(final byte[] message, final byte[] nonce) {
      if (message == null)
        return null;

      return box(message, 0, message.length, nonce);
    }

    private byte[] box(final byte[] message, final int moff, final byte[] nonce) {
      if (!(message != null && message.length > moff))
        return null;

      return box(message, moff, message.length - moff, nonce);
    }

    private byte[] box(final byte[] message, final int moff, final int mlen, final byte[] nonce) {
      // check message
      if (!(message != null && message.length >= (moff + mlen) && nonce != null && nonce.length == nonceLength))
        return null;

      // message buffer
      final byte[] m = new byte[mlen + Box.zerobytesLength];

      // cipher buffer
      final byte[] c = new byte[m.length];

      if (mlen >= 0)
        System.arraycopy(message, 0 + moff, m, 32, mlen);

      if (0 != cryptoSecretBox(c, m, m.length, nonce, key))
        return null;

      // TBD optimizing ...
      final byte[] ret = new byte[c.length - Box.boxzerobytesLength];
      System.arraycopy(c, 16, ret, 0, ret.length);

      return ret;
    }

    private byte[] open(final byte[] box, final int boxoff) {
      if (!(box != null && box.length > boxoff))
        return null;

      return open(box, boxoff, box.length - boxoff);
    }

    private byte[] open(final byte[] box, final int boxoff, final int boxlen) {
      // check message
      if (!(box != null && box.length >= (boxoff + boxlen) && boxlen >= Box.boxzerobytesLength))
        return null;

      return open(box, boxoff, box.length - boxoff, generateNonce());
    }

    @Override
    public byte[] open(final byte[] box) {
      return box == null ? null : open(box, 0, box.length);
    }

    @Override
    public byte[] open(final byte[] box, final byte[] nonce) {
      if (box == null)
        return null;

      return open(box, 0, box.length, nonce);
    }

    private byte[] open(final byte[] box, final int boxoff, final byte[] nonce) {
      if (!(box != null && box.length > boxoff))
        return null;

      return open(box, boxoff, box.length - boxoff, nonce);
    }

    private byte[] open(final byte[] box, final int boxoff, final int boxlen, final byte[] nonce) {
      // check message
      if (!(box != null && box.length >= (boxoff + boxlen) && boxlen >= Box.boxzerobytesLength && nonce != null && nonce.length == nonceLength))
        return null;

      // cipher buffer
      final byte[] c = new byte[boxlen + Box.boxzerobytesLength];

      // message buffer
      final byte[] m = new byte[c.length];
      System.arraycopy(box, 0 + boxoff, c, 16, boxlen);

      if (cryptoSecretBoxOpen(m, c, c.length, nonce, key) != 0)
        return null;

      final byte[] ret = new byte[m.length - Box.zerobytesLength];
      System.arraycopy(m, 32, ret, 0, ret.length);

      return ret;
    }
  }

  /**
   * Signature algorithm, Implements ed25519.
   */
  public final class Signature extends Nacl.Signature {
    Signature(final byte[] theirPublicKey, final byte[] mySecretKey) {
      super(theirPublicKey, mySecretKey);
    }

    @Override
    public byte[] sign(final byte[] message) {
      return message == null ? null : sign(message, 0, message.length);
    }

    private byte[] sign(final byte[] message, final int moff) {
      if (!(message != null && message.length > moff))
        return null;

      return sign(message, moff, message.length - moff);
    }

    private byte[] sign(final byte[] message, final int moff, final int mlen) {
      // check message
      if (!(message != null && message.length >= (moff + mlen)))
        return null;

      // signed message
      final byte[] sm = new byte[mlen + signatureLength];
      cryptoSign(sm, -1, message, moff, mlen, mySecretKey);
      return sm;
    }

    @Override
    public byte[] open(final byte[] signedMessage) {
      return signedMessage == null ? null : open(signedMessage, 0, signedMessage.length);
    }

    private byte[] open(final byte[] signedMessage, final int smoff) {
      if (!(signedMessage != null && signedMessage.length > smoff))
        return null;

      return open(signedMessage, smoff, signedMessage.length - smoff);
    }

    private byte[] open(final byte[] signedMessage, final int smoff, final int smlen) {
      // check sm length
      if (!(signedMessage != null && signedMessage.length >= (smoff + smlen) && smlen >= signatureLength))
        return null;

      // temp buffer
      final byte[] tmp = new byte[smlen];
      if (0 != cryptoSignOpen(tmp, -1, signedMessage, smoff, smlen, theirPublicKey))
        return null;

      // message
      final byte[] msg = new byte[smlen - signatureLength];
      for (int i = 0, i$ = msg.length; i < i$; ++i) // [A]
        msg[i] = signedMessage[smoff + i + signatureLength];

      return msg;
    }
  }

  private static int cryptoVerify16(final byte[] x, final int xoff, final byte[] y, final int yoff) {
    return vn(x, xoff, y, yoff, 16);
  }

  @Override
  public int cryptoVerify16(final byte[] x, final byte[] y) {
    return cryptoVerify16(x, 0, y, 0);
  }

  private static int cryptoVerify32(final byte[] x, final int xoff, final byte[] y, final int yoff) {
    return vn(x, xoff, y, yoff, 32);
  }

  @Override
  public int cryptoVerify32(final byte[] x, final byte[] y) {
    return cryptoVerify32(x, 0, y, 0);
  }

  private static void coreSalsa20(final byte[] o, final byte[] p, final byte[] k, final byte[] c) {
    final int j0 = c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24;
    final int j1 = k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24;
    final int j2 = k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24;
    final int j3 = k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24;
    final int j4 = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24;
    final int j5 = c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24;
    final int j6 = p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24;
    final int j7 = p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24;
    final int j8 = p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24;
    final int j9 = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24;
    final int j10 = c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24;
    final int j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24;
    final int j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24;
    final int j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24;
    final int j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24;
    final int j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24;

    int x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;
    for (int i = 0; i < 20; i += 2) { // [A]
      u = x0 + x12;
      x4 ^= u << 7 | u >>> (32 - 7);
      u = x4 + x0;
      x8 ^= u << 9 | u >>> (32 - 9);
      u = x8 + x4;
      x12 ^= u << 13 | u >>> (32 - 13);
      u = x12 + x8;
      x0 ^= u << 18 | u >>> (32 - 18);

      u = x5 + x1;
      x9 ^= u << 7 | u >>> (32 - 7);
      u = x9 + x5;
      x13 ^= u << 9 | u >>> (32 - 9);
      u = x13 + x9;
      x1 ^= u << 13 | u >>> (32 - 13);
      u = x1 + x13;
      x5 ^= u << 18 | u >>> (32 - 18);

      u = x10 + x6;
      x14 ^= u << 7 | u >>> (32 - 7);
      u = x14 + x10;
      x2 ^= u << 9 | u >>> (32 - 9);
      u = x2 + x14;
      x6 ^= u << 13 | u >>> (32 - 13);
      u = x6 + x2;
      x10 ^= u << 18 | u >>> (32 - 18);

      u = x15 + x11;
      x3 ^= u << 7 | u >>> (32 - 7);
      u = x3 + x15;
      x7 ^= u << 9 | u >>> (32 - 9);
      u = x7 + x3;
      x11 ^= u << 13 | u >>> (32 - 13);
      u = x11 + x7;
      x15 ^= u << 18 | u >>> (32 - 18);

      u = x0 + x3;
      x1 ^= u << 7 | u >>> (32 - 7);
      u = x1 + x0;
      x2 ^= u << 9 | u >>> (32 - 9);
      u = x2 + x1;
      x3 ^= u << 13 | u >>> (32 - 13);
      u = x3 + x2;
      x0 ^= u << 18 | u >>> (32 - 18);

      u = x5 + x4;
      x6 ^= u << 7 | u >>> (32 - 7);
      u = x6 + x5;
      x7 ^= u << 9 | u >>> (32 - 9);
      u = x7 + x6;
      x4 ^= u << 13 | u >>> (32 - 13);
      u = x4 + x7;
      x5 ^= u << 18 | u >>> (32 - 18);

      u = x10 + x9;
      x11 ^= u << 7 | u >>> (32 - 7);
      u = x11 + x10;
      x8 ^= u << 9 | u >>> (32 - 9);
      u = x8 + x11;
      x9 ^= u << 13 | u >>> (32 - 13);
      u = x9 + x8;
      x10 ^= u << 18 | u >>> (32 - 18);

      u = x15 + x14;
      x12 ^= u << 7 | u >>> (32 - 7);
      u = x12 + x15;
      x13 ^= u << 9 | u >>> (32 - 9);
      u = x13 + x12;
      x14 ^= u << 13 | u >>> (32 - 13);
      u = x14 + x13;
      x15 ^= u << 18 | u >>> (32 - 18);
    }

    x0 += j0;
    x1 += j1;
    x2 += j2;
    x3 += j3;
    x4 += j4;
    x5 += j5;
    x6 += j6;
    x7 += j7;
    x8 += j8;
    x9 += j9;
    x10 += j10;
    x11 += j11;
    x12 += j12;
    x13 += j13;
    x14 += j14;
    x15 += j15;

    o[0] = (byte)(x0 & 0xff);
    o[1] = (byte)(x0 >>> 8 & 0xff);
    o[2] = (byte)(x0 >>> 16 & 0xff);
    o[3] = (byte)(x0 >>> 24 & 0xff);

    o[4] = (byte)(x1 & 0xff);
    o[5] = (byte)(x1 >>> 8 & 0xff);
    o[6] = (byte)(x1 >>> 16 & 0xff);
    o[7] = (byte)(x1 >>> 24 & 0xff);

    o[8] = (byte)(x2 & 0xff);
    o[9] = (byte)(x2 >>> 8 & 0xff);
    o[10] = (byte)(x2 >>> 16 & 0xff);
    o[11] = (byte)(x2 >>> 24 & 0xff);

    o[12] = (byte)(x3 & 0xff);
    o[13] = (byte)(x3 >>> 8 & 0xff);
    o[14] = (byte)(x3 >>> 16 & 0xff);
    o[15] = (byte)(x3 >>> 24 & 0xff);

    o[16] = (byte)(x4 & 0xff);
    o[17] = (byte)(x4 >>> 8 & 0xff);
    o[18] = (byte)(x4 >>> 16 & 0xff);
    o[19] = (byte)(x4 >>> 24 & 0xff);

    o[20] = (byte)(x5 & 0xff);
    o[21] = (byte)(x5 >>> 8 & 0xff);
    o[22] = (byte)(x5 >>> 16 & 0xff);
    o[23] = (byte)(x5 >>> 24 & 0xff);

    o[24] = (byte)(x6 & 0xff);
    o[25] = (byte)(x6 >>> 8 & 0xff);
    o[26] = (byte)(x6 >>> 16 & 0xff);
    o[27] = (byte)(x6 >>> 24 & 0xff);

    o[28] = (byte)(x7 & 0xff);
    o[29] = (byte)(x7 >>> 8 & 0xff);
    o[30] = (byte)(x7 >>> 16 & 0xff);
    o[31] = (byte)(x7 >>> 24 & 0xff);

    o[32] = (byte)(x8 & 0xff);
    o[33] = (byte)(x8 >>> 8 & 0xff);
    o[34] = (byte)(x8 >>> 16 & 0xff);
    o[35] = (byte)(x8 >>> 24 & 0xff);

    o[36] = (byte)(x9 & 0xff);
    o[37] = (byte)(x9 >>> 8 & 0xff);
    o[38] = (byte)(x9 >>> 16 & 0xff);
    o[39] = (byte)(x9 >>> 24 & 0xff);

    o[40] = (byte)(x10 & 0xff);
    o[41] = (byte)(x10 >>> 8 & 0xff);
    o[42] = (byte)(x10 >>> 16 & 0xff);
    o[43] = (byte)(x10 >>> 24 & 0xff);

    o[44] = (byte)(x11 & 0xff);
    o[45] = (byte)(x11 >>> 8 & 0xff);
    o[46] = (byte)(x11 >>> 16 & 0xff);
    o[47] = (byte)(x11 >>> 24 & 0xff);

    o[48] = (byte)(x12 & 0xff);
    o[49] = (byte)(x12 >>> 8 & 0xff);
    o[50] = (byte)(x12 >>> 16 & 0xff);
    o[51] = (byte)(x12 >>> 24 & 0xff);

    o[52] = (byte)(x13 & 0xff);
    o[53] = (byte)(x13 >>> 8 & 0xff);
    o[54] = (byte)(x13 >>> 16 & 0xff);
    o[55] = (byte)(x13 >>> 24 & 0xff);

    o[56] = (byte)(x14 & 0xff);
    o[57] = (byte)(x14 >>> 8 & 0xff);
    o[58] = (byte)(x14 >>> 16 & 0xff);
    o[59] = (byte)(x14 >>> 24 & 0xff);

    o[60] = (byte)(x15 & 0xff);
    o[61] = (byte)(x15 >>> 8 & 0xff);
    o[62] = (byte)(x15 >>> 16 & 0xff);
    o[63] = (byte)(x15 >>> 24 & 0xff);

    /*
     * String dbgt = ""; for (int dbg = 0; dbg < o.length; dbg ++) dbgt += " "+o[dbg]; Log.d(TAG, "core_salsa20 -> "+dbgt);
     */
  }

  private static void coreHsalsa20(final byte[] o, final byte[] p, final byte[] k, final byte[] c) {
    int j0 = c[0] & 0xff | (c[1] & 0xff) << 8 | (c[2] & 0xff) << 16 | (c[3] & 0xff) << 24;
    final int j1 = k[0] & 0xff | (k[1] & 0xff) << 8 | (k[2] & 0xff) << 16 | (k[3] & 0xff) << 24;
    final int j2 = k[4] & 0xff | (k[5] & 0xff) << 8 | (k[6] & 0xff) << 16 | (k[7] & 0xff) << 24;
    final int j3 = k[8] & 0xff | (k[9] & 0xff) << 8 | (k[10] & 0xff) << 16 | (k[11] & 0xff) << 24;
    final int j4 = k[12] & 0xff | (k[13] & 0xff) << 8 | (k[14] & 0xff) << 16 | (k[15] & 0xff) << 24;
    final int j5 = c[4] & 0xff | (c[5] & 0xff) << 8 | (c[6] & 0xff) << 16 | (c[7] & 0xff) << 24;
    final int j6 = p[0] & 0xff | (p[1] & 0xff) << 8 | (p[2] & 0xff) << 16 | (p[3] & 0xff) << 24;
    final int j7 = p[4] & 0xff | (p[5] & 0xff) << 8 | (p[6] & 0xff) << 16 | (p[7] & 0xff) << 24;
    final int j8 = p[8] & 0xff | (p[9] & 0xff) << 8 | (p[10] & 0xff) << 16 | (p[11] & 0xff) << 24;
    final int j9 = p[12] & 0xff | (p[13] & 0xff) << 8 | (p[14] & 0xff) << 16 | (p[15] & 0xff) << 24;
    final int j10 = c[8] & 0xff | (c[9] & 0xff) << 8 | (c[10] & 0xff) << 16 | (c[11] & 0xff) << 24;
    final int j11 = k[16] & 0xff | (k[17] & 0xff) << 8 | (k[18] & 0xff) << 16 | (k[19] & 0xff) << 24;
    final int j12 = k[20] & 0xff | (k[21] & 0xff) << 8 | (k[22] & 0xff) << 16 | (k[23] & 0xff) << 24;
    final int j13 = k[24] & 0xff | (k[25] & 0xff) << 8 | (k[26] & 0xff) << 16 | (k[27] & 0xff) << 24;
    final int j14 = k[28] & 0xff | (k[29] & 0xff) << 8 | (k[30] & 0xff) << 16 | (k[31] & 0xff) << 24;
    final int j15 = c[12] & 0xff | (c[13] & 0xff) << 8 | (c[14] & 0xff) << 16 | (c[15] & 0xff) << 24;

    int x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;

    for (int i = 0; i < 20; i += 2) { // [A]
      u = x0 + x12;
      x4 ^= u << 7 | u >>> (32 - 7);
      u = x4 + x0;
      x8 ^= u << 9 | u >>> (32 - 9);
      u = x8 + x4;
      x12 ^= u << 13 | u >>> (32 - 13);
      u = x12 + x8;
      x0 ^= u << 18 | u >>> (32 - 18);

      u = x5 + x1;
      x9 ^= u << 7 | u >>> (32 - 7);
      u = x9 + x5;
      x13 ^= u << 9 | u >>> (32 - 9);
      u = x13 + x9;
      x1 ^= u << 13 | u >>> (32 - 13);
      u = x1 + x13;
      x5 ^= u << 18 | u >>> (32 - 18);

      u = x10 + x6;
      x14 ^= u << 7 | u >>> (32 - 7);
      u = x14 + x10;
      x2 ^= u << 9 | u >>> (32 - 9);
      u = x2 + x14;
      x6 ^= u << 13 | u >>> (32 - 13);
      u = x6 + x2;
      x10 ^= u << 18 | u >>> (32 - 18);

      u = x15 + x11;
      x3 ^= u << 7 | u >>> (32 - 7);
      u = x3 + x15;
      x7 ^= u << 9 | u >>> (32 - 9);
      u = x7 + x3;
      x11 ^= u << 13 | u >>> (32 - 13);
      u = x11 + x7;
      x15 ^= u << 18 | u >>> (32 - 18);

      u = x0 + x3;
      x1 ^= u << 7 | u >>> (32 - 7);
      u = x1 + x0;
      x2 ^= u << 9 | u >>> (32 - 9);
      u = x2 + x1;
      x3 ^= u << 13 | u >>> (32 - 13);
      u = x3 + x2;
      x0 ^= u << 18 | u >>> (32 - 18);

      u = x5 + x4;
      x6 ^= u << 7 | u >>> (32 - 7);
      u = x6 + x5;
      x7 ^= u << 9 | u >>> (32 - 9);
      u = x7 + x6;
      x4 ^= u << 13 | u >>> (32 - 13);
      u = x4 + x7;
      x5 ^= u << 18 | u >>> (32 - 18);

      u = x10 + x9;
      x11 ^= u << 7 | u >>> (32 - 7);
      u = x11 + x10;
      x8 ^= u << 9 | u >>> (32 - 9);
      u = x8 + x11;
      x9 ^= u << 13 | u >>> (32 - 13);
      u = x9 + x8;
      x10 ^= u << 18 | u >>> (32 - 18);

      u = x15 + x14;
      x12 ^= u << 7 | u >>> (32 - 7);
      u = x12 + x15;
      x13 ^= u << 9 | u >>> (32 - 9);
      u = x13 + x12;
      x14 ^= u << 13 | u >>> (32 - 13);
      u = x14 + x13;
      x15 ^= u << 18 | u >>> (32 - 18);
    }

    o[0] = (byte)(x0 & 0xff);
    o[1] = (byte)(x0 >>> 8 & 0xff);
    o[2] = (byte)(x0 >>> 16 & 0xff);
    o[3] = (byte)(x0 >>> 24 & 0xff);

    o[4] = (byte)(x5 & 0xff);
    o[5] = (byte)(x5 >>> 8 & 0xff);
    o[6] = (byte)(x5 >>> 16 & 0xff);
    o[7] = (byte)(x5 >>> 24 & 0xff);

    o[8] = (byte)(x10 & 0xff);
    o[9] = (byte)(x10 >>> 8 & 0xff);
    o[10] = (byte)(x10 >>> 16 & 0xff);
    o[11] = (byte)(x10 >>> 24 & 0xff);

    o[12] = (byte)(x15 & 0xff);
    o[13] = (byte)(x15 >>> 8 & 0xff);
    o[14] = (byte)(x15 >>> 16 & 0xff);
    o[15] = (byte)(x15 >>> 24 & 0xff);

    o[16] = (byte)(x6 & 0xff);
    o[17] = (byte)(x6 >>> 8 & 0xff);
    o[18] = (byte)(x6 >>> 16 & 0xff);
    o[19] = (byte)(x6 >>> 24 & 0xff);

    o[20] = (byte)(x7 & 0xff);
    o[21] = (byte)(x7 >>> 8 & 0xff);
    o[22] = (byte)(x7 >>> 16 & 0xff);
    o[23] = (byte)(x7 >>> 24 & 0xff);

    o[24] = (byte)(x8 & 0xff);
    o[25] = (byte)(x8 >>> 8 & 0xff);
    o[26] = (byte)(x8 >>> 16 & 0xff);
    o[27] = (byte)(x8 >>> 24 & 0xff);

    o[28] = (byte)(x9 & 0xff);
    o[29] = (byte)(x9 >>> 8 & 0xff);
    o[30] = (byte)(x9 >>> 16 & 0xff);
    o[31] = (byte)(x9 >>> 24 & 0xff);

    /*
     * String dbgt = ""; for (int dbg = 0; dbg < o.length; dbg ++) dbgt += " "+o[dbg]; Log.d(TAG, "core_hsalsa20 -> "+dbgt);
     */
  }

  @Override
  public void cryptoCoreSalsa20(final byte[] out, final byte[] in, final byte[] k, final byte[] c) {
    coreSalsa20(out, in, k, c);
  }

  @Override
  public void cryptoCoreHsalsa20(final byte[] out, final byte[] in, final byte[] k, final byte[] c) {
    coreHsalsa20(out, in, k, c);
  }

  private void cryptoStreamSalsa20Xor(final byte[] c, int cpos, final byte[] m, int mpos, long b, final byte[] n, final byte[] k) {
    final byte[] z = new byte[16];
    final byte[] x = new byte[64];
    int u, i;
    for (i = 0; i < 16; ++i) // [A]
      z[i] = 0;

    for (i = 0; i < 8; ++i) // [A]
      z[i] = n[i];

    while (b >= 64) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < 64; ++i) // [A]
        c[cpos + i] = (byte)((m[mpos + i] ^ x[i]) & 0xff);

      u = 1;
      for (i = 8; i < 16; ++i) { // [A]
        u += (z[i] & 0xff);
        z[i] = (byte)(u & 0xff);
        u >>>= 8;
      }

      b -= 64;
      cpos += 64;
      mpos += 64;
    }

    if (b > 0) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < b; ++i) // [A]
        c[cpos + i] = (byte)((m[mpos + i] ^ x[i]) & 0xff);
    }
  }

  private void cryptoStreamSalsa20(final byte[] c, int cpos, long b, final byte[] n, final byte[] k) {
    final byte[] z = new byte[16];
    final byte[] x = new byte[64];
    int u, i;
    for (i = 0; i < 16; ++i) // [A]
      z[i] = 0;

    for (i = 0; i < 8; ++i) // [A]
      z[i] = n[i];

    while (b >= 64) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < 64; ++i) // [A]
        c[cpos + i] = x[i];

      u = 1;
      for (i = 8; i < 16; ++i) { // [A]
        u += (z[i] & 0xff);
        z[i] = (byte)(u & 0xff);
        u >>>= 8;
      }

      b -= 64;
      cpos += 64;
    }

    if (b > 0) {
      cryptoCoreSalsa20(x, z, k, sigma);
      for (i = 0; i < b; ++i) // [A]
        c[cpos + i] = x[i];
    }
  }

  private void cryptoStream(final byte[] c, final int cpos, final long d, final byte[] n, final byte[] k) {
    final byte[] s = new byte[32];
    cryptoCoreHsalsa20(s, n, k, sigma);
    final byte[] sn = new byte[8];
    System.arraycopy(n, 16, sn, 0, 8);

    cryptoStreamSalsa20(c, cpos, d, sn, s);
  }

  private void cryptoStreamXor(final byte[] c, final int cpos, final byte[] m, final int mpos, final long d, final byte[] n, final byte[] k) {
    final byte[] s = new byte[32];
    cryptoCoreHsalsa20(s, n, k, sigma);
    final byte[] sn = new byte[8];
    System.arraycopy(n, 16, sn, 0, 8);

    cryptoStreamSalsa20Xor(c, cpos, m, mpos, d, sn, s);
  }

  private static int cryptoOneTimeAuthVerify(final byte[] h, final int hoff, final byte[] m, final int moff, final int /* long */ n, final byte[] k) {
    final byte[] x = new byte[16];
    cryptoOneTimeAuth(x, 0, m, moff, n, k);
    return cryptoVerify16(h, hoff, x, 0);
  }

  @Override
  public int cryptoOneTimeAuthVerify(final byte[] h, final byte[] m, final int n, final byte[] k) {
    return cryptoOneTimeAuthVerify(h, 0, m, 0, n, k);
  }

  @Override
  public int cryptoSecretBox(final byte[] c, final byte[] m, final int /* long */ d, final byte[] n, final byte[] k) {
    if (d < 32)
      return -1;

    cryptoStreamXor(c, 0, m, 0, d, n, k);
    cryptoOneTimeAuth(c, 16, c, 32, d - 32, c);
    return 0;
  }

  @Override
  public int cryptoSecretBoxOpen(final byte[] m, final byte[] c, final int /* long */ d, final byte[] n, final byte[] k) {
    final byte[] x = new byte[32];
    if (d < 32)
      return -1;

    cryptoStream(x, 0, 32, n, k);
    if (cryptoOneTimeAuthVerify(c, 16, c, 32, d - 32, x) != 0)
      return -1;

    cryptoStreamXor(m, 0, c, 0, d, n, k);
    return 0;
  }

  private static void car25519(final long[] o) {
    long v, c = 1;
    for (int i = 0; i < 16; ++i) { // [A]
      v = o[i] + c + 65535;
      c = v >> 16;
      o[i] = v - c * 65536;
    }

    o[0] += c - 1 + 37 * (c - 1);
  }

  private static void sel25519(final long[] p, final long[] q, final int b) {
    sel25519(p, 0, q, 0, b);
  }

  private static void pack25519(final byte[] o, final long[] n, final int noff) {
    int i, j, b;
    final long[] m = new long[16];
    final long[] t = new long[16];
    for (i = 0; i < 16; ++i) // [A]
      t[i] = n[i + noff];

    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; ++j) { // [A]
      m[0] = t[0] - 0xffed;
      for (i = 1; i < 15; ++i) { // [A]
        m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
        m[i - 1] &= 0xffff;
      }

      m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
      b = (int)((m[15] >> 16) & 1);
      m[14] &= 0xffff;
      sel25519(t, 0, m, 0, 1 - b);
    }

    for (i = 0; i < 16; ++i) { // [A]
      o[2 * i] = (byte)(t[i] & 0xff);
      o[2 * i + 1] = (byte)(t[i] >> 8);
    }
  }

  @Override
  int neq25519(final long[] a, final long[] b) {
    return neq25519(a, 0, b, 0);
  }

  private static int neq25519(final long[] a, final int aoff, final long[] b, final int boff) {
    final byte[] c = new byte[32], d = new byte[32];
    pack25519(c, a, aoff);
    pack25519(d, b, boff);
    return cryptoVerify32(c, 0, d, 0);
  }

  @Override
  byte par25519(final long[] a) {
    return par25519(a, 0);
  }

  private static byte par25519(final long[] a, final int aoff) {
    final byte[] d = new byte[32];
    pack25519(d, a, aoff);
    return (byte)(d[0] & 1);
  }

  private static void A(final long[] o, final long[] a, final long[] b) {
    A(o, 0, a, 0, b, 0);
  }

  private static void A(final long[] o, final int ooff, final long[] a, final int aoff, final long[] b, final int boff) {
    for (int i = 0; i < 16; ++i) // [A]
      o[i + ooff] = a[i + aoff] + b[i + boff];
  }

  private static void Z(final long[] o, final long[] a, final long[] b) {
    Z(o, 0, a, 0, b, 0);
  }

  private static void Z(final long[] o, final int ooff, final long[] a, final int aoff, final long[] b, final int boff) {
    for (int i = 0; i < 16; ++i) // [A]
      o[i + ooff] = a[i + aoff] - b[i + boff];
  }

  private static void M(final long[] o, final long[] a, final long[] b) {
    M(o, 0, a, 0, b, 0);
  }

  private static void M(final long[] o, final int ooff, final long[] a, final int aoff, final long[] b, final int boff) {
    long v;
    long c;
    long t0 = 0;
    long t1 = 0;
    long t2 = 0;
    long t3 = 0;
    long t4 = 0;
    long t5 = 0;
    long t6 = 0;
    long t7 = 0;
    long t8 = 0;
    long t9 = 0;
    long t10 = 0;
    long t11 = 0;
    long t12 = 0;
    long t13 = 0;
    long t14 = 0;
    long t15 = 0;
    long t16 = 0;
    long t17 = 0;
    long t18 = 0;
    long t19 = 0;
    long t20 = 0;
    long t21 = 0;
    long t22 = 0;
    long t23 = 0;
    long t24 = 0;
    long t25 = 0;
    long t26 = 0;
    long t27 = 0;
    long t28 = 0;
    long t29 = 0;
    long t30 = 0;
    final long b0 = b[0 + boff];
    final long b1 = b[1 + boff];
    final long b2 = b[2 + boff];
    final long b3 = b[3 + boff];
    final long b4 = b[4 + boff];
    final long b5 = b[5 + boff];
    final long b6 = b[6 + boff];
    final long b7 = b[7 + boff];
    final long b8 = b[8 + boff];
    final long b9 = b[9 + boff];
    final long b10 = b[10 + boff];
    final long b11 = b[11 + boff];
    final long b12 = b[12 + boff];
    final long b13 = b[13 + boff];
    final long b14 = b[14 + boff];
    final long b15 = b[15 + boff];

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
    for (a = 0; a < 16; ++a) // [A]
      c[a] = i[a + ioff];

    for (a = 253; a >= 0; --a) { // [A]
      S(c, 0, c, 0);
      if (a != 2 && a != 4)
        M(c, 0, c, 0, i, ioff);
    }

    for (a = 0; a < 16; ++a) // [A]
      o[a + ooff] = c[a];
  }

  @Override
  void pow2523(final long[] o, final long[] i) {
    final long[] c = new long[16];
    int a;
    for (a = 0; a < 16; ++a) // [A]
      c[a] = i[a];

    for (a = 250; a >= 0; --a) { // [A]
      S(c, 0, c, 0);
      if (a != 1)
        M(c, 0, c, 0, i, 0);
    }

    for (a = 0; a < 16; ++a) // [A]
      o[a] = c[a];
  }

  @Override
  public void cryptoScalarMult(final byte[] q, final byte[] n, final byte[] p) {
    final byte[] z = new byte[32];
    final long[] x = new long[80];
    int i;
    final long[] a = new long[16], b = new long[16], c = new long[16], d = new long[16], e = new long[16], f = new long[16];
    for (i = 0; i < 31; ++i) // [A]
      z[i] = n[i];

    z[31] = (byte)(((n[31] & 127) | 64) & 0xff);
    z[0] &= 248;
    unpack25519(x, p);
    for (i = 0; i < 16; ++i) { // [A]
      b[i] = x[i];
      d[i] = a[i] = c[i] = 0;
    }

    a[0] = d[0] = 1;
    i = 254;
    for (int r; i >= 0; --i) { // [A]
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

    for (i = 0; i < 16; ++i) { // [A]
      x[i + 16] = a[i];
      x[i + 32] = c[i];
      x[i + 48] = b[i];
      x[i + 64] = d[i];
    }

    inv25519(x, 32, x, 32);
    M(x, 16, x, 16, x, 32);
    pack25519(q, x, 16);
  }

  @Override
  void add(final long[][] p, final long[][] q) {
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

  @Override
  void pack(final byte[] r, final long[][] p) {
    final long[] tx = new long[16];
    final long[] ty = new long[16];
    final long[] zi = new long[16];

    inv25519(zi, 0, p[2], 0);

    M(tx, 0, p[0], 0, zi, 0);
    M(ty, 0, p[1], 0, zi, 0);

    pack25519(r, ty, 0);

    r[31] ^= par25519(tx, 0) << 7;
  }

  private void scalarmult(final long[][] p, final long[][] q, final byte[] s, final int soff) {
    set25519(p[0], gf0);
    set25519(p[1], gf1);
    set25519(p[2], gf1);
    set25519(p[3], gf0);

    for (int i = 255; i >= 0; --i) { // [A]
      final byte b = (byte)((s[i / 8 + soff] >>> (i & 7)) & 1);

      cswap(p, q, b);
      add(q, p);
      add(p, p);
      cswap(p, q, b);
    }
  }

  private void scalarbase(final long[][] p, final byte[] s, final int soff) {
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

  @Override
  public void cryptoSignKeyPair(final byte[] pk, final byte[] sk, final boolean seeded) {
    final byte[] d = new byte[64];
    final long[][] p = new long[4][];

    p[0] = new long[16];
    p[1] = new long[16];
    p[2] = new long[16];
    p[3] = new long[16];

    if (!seeded)
      randombytes(sk, 32);

    HashTweetFast.cryptoHash(d, sk, 0, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    scalarbase(p, d, 0);
    pack(pk, p);
    System.arraycopy(pk, 0, sk, 32, 32);
  }

  // TBD... 64bits of n
  private void cryptoSign(final byte[] sm, final long dummy /* smlen not used */, final byte[] m, final int moff, final int/* long */ n, final byte[] sk) {
    final byte[] d = new byte[64];
    final byte[] h = new byte[64];
    final byte[] r = new byte[64];
    final long[] x = new long[64];

    final long[][] p = new long[4][];
    p[0] = new long[16];
    p[1] = new long[16];
    p[2] = new long[16];
    p[3] = new long[16];

    HashTweetFast.cryptoHash(d, sk, 0, 32);
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;

    int i;
    for (i = 0; i < n; ++i) // [A]
      sm[64 + i] = m[i + moff];

    for (i = 0; i < 32; ++i) // [A]
      sm[32 + i] = d[32 + i];

    HashTweetFast.cryptoHash(r, sm, 32, n + 32);
    reduce(r);
    scalarbase(p, r, 0);
    pack(sm, p);

    for (i = 0; i < 32; ++i) // [A]
      sm[i + 32] = sk[i + 32];

    HashTweetFast.cryptoHash(h, sm, 0, n + 64);
    reduce(h);
    for (i = 0; i < 64; ++i) // [A]
      x[i] = 0;

    for (i = 0; i < 32; ++i) // [A]
      x[i] = r[i] & 0xff;

    for (i = 0; i < 32; ++i) // [A]
      for (int j = 0; j < 32; ++j) // [A]
        x[i + j] += (h[i] & 0xff) * (long)(d[j] & 0xff);

    modL(sm, 32, x);
  }

  @Override
  int unpackneg(final long[][] r, final byte[] p) {
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
  @Override
  int cryptoSignOpen(final byte[] m, final long dummy /* mlen not used */, final byte[] sm, final int smoff, int/* long */ n, final byte[] pk) {
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

    int i;
    for (i = 0; i < n; ++i) // [A]
      m[i] = sm[i + smoff];

    for (i = 0; i < 32; ++i) // [A]
      m[i + 32] = pk[i];

    HashTweetFast.cryptoHash(h, m, 0, n);

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

  @Override
  public byte[] randombytes(final byte[] x, final int len) {
    final byte[] b = randombytes(len);
    System.arraycopy(b, 0, x, 0, len);
    return x;
  }

  NaclTweetFast() {
  }
}