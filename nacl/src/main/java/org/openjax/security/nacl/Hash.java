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

import java.io.UnsupportedEncodingException;

/**
 * Hash algorithm, Implements SHA-512.
 */
@SuppressWarnings("unused")
public class Hash {
  /** Length of hash in bytes. */
  public static final int hashLength = 64;
  private static final byte[] iv = {0x6a, 0x09, (byte)0xe6, 0x67, (byte)0xf3, (byte)0xbc, (byte)0xc9, 0x08, (byte)0xbb, 0x67, (byte)0xae, (byte)0x85, (byte)0x84, (byte)0xca, (byte)0xa7, 0x3b, 0x3c, 0x6e, (byte)0xf3, 0x72, (byte)0xfe, (byte)0x94, (byte)0xf8, 0x2b, (byte)0xa5, 0x4f, (byte)0xf5, 0x3a, 0x5f, 0x1d, 0x36, (byte)0xf1, 0x51, 0x0e, 0x52, 0x7f, (byte)0xad, (byte)0xe6, (byte)0x82, (byte)0xd1, (byte)0x9b, 0x05, 0x68, (byte)0x8c, 0x2b, 0x3e, 0x6c, 0x1f, 0x1f, (byte)0x83, (byte)0xd9, (byte)0xab, (byte)0xfb, 0x41, (byte)0xbd, 0x6b, 0x5b, (byte)0xe0, (byte)0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79};

  // TBD 64bits of n
  static int cryptoHash(final byte[] out, final byte[] m, final int moff, final int mlen, int n) {
    final byte[] h = new byte[64], x = new byte[256];
    final long b = n;
    int i;

    for (i = 0; i < 64; ++i)
      h[i] = iv[i];

    cryptoHashBlocks(h, m, moff, mlen, n);
    // m += n;
    n &= 127;
    // m -= n;

    for (i = 0; i < 256; ++i)
      x[i] = 0;

    for (i = 0; i < n; ++i)
      x[i] = m[i + moff];

    x[n] = (byte)128;
    n = 256 - 128 * (n < 112 ? 1 : 0);
    x[n - 9] = (byte)(b >>> 61);
    ts64(x, n - 8, x.length - (n - 8), b << 3);
    cryptoHashBlocks(h, x, 0, x.length, n);

    for (i = 0; i < 64; ++i)
      out[i] = h[i];

    return 0;
  }

  public static int cryptoHash(final byte[] out, final byte[] m, final int n) {
    return cryptoHash(out, m, 0, m.length, n);
  }

  public static int cryptoHash(final byte[] out, final byte[] m) {
    return cryptoHash(out, m, m != null ? m.length : 0);
  }

  // TBD... long length n
  private static int cryptoHashBlocks(final byte[] x, final byte[] m, final int moff, final int mlen, int n) {
    final long[] z = new long[8], b = new long[8], a = new long[8], w = new long[16];
    long t;
    int i;

    for (i = 0; i < 8; ++i)
      z[i] = a[i] = dl64(x, 8 * i, x.length - 8 * i);

    int moffset = moff;
    while (n >= 128) {
      for (i = 0; i < 16; ++i)
        w[i] = dl64(m, 8 * i + moffset, mlen - 8 * i);

      i = 0;
      for (int j; i < 80; ++i) {
        for (j = 0; j < 8; j++)
          b[j] = a[j];

        t = a[7] + Sigma1(a[4]) + Ch(a[4], a[5], a[6]) + K[i] + w[i % 16];
        b[7] = t + Sigma0(a[0]) + Maj(a[0], a[1], a[2]);
        b[3] += t;

        for (j = 0; j < 8; j++)
          a[(j + 1) % 8] = b[j];

        if (i % 16 == 15)
          for (j = 0; j < 16; j++)
            w[j] += w[(j + 9) % 16] + sigma0(w[(j + 1) % 16]) + sigma1(w[(j + 14) % 16]);
      }

      for (i = 0; i < 8; ++i) {
        a[i] += z[i];
        z[i] = a[i];
      }

      moffset += 128;
      n -= 128;
    }

    for (i = 0; i < 8; ++i)
      ts64(x, 8 * i, x.length - 8 * i, z[i]);

    return n;
  }

  public static int cryptoHashBlocks(final byte[] x, final byte[] m, final int n) {
    return cryptoHashBlocks(x, m, 0, m.length, n);
  }

  private static long R(final long x, final int c) {
    return (x >>> c) | (x << (64 - c));
  }

  private static long Ch(final long x, final long y, final long z) {
    return (x & y) ^ (~x & z);
  }

  private static long Maj(final long x, final long y, final long z) {
    return (x & y) ^ (x & z) ^ (y & z);
  }

  private static long Sigma0(final long x) {
    return R(x, 28) ^ R(x, 34) ^ R(x, 39);
  }

  private static long Sigma1(final long x) {
    return R(x, 14) ^ R(x, 18) ^ R(x, 41);
  }

  private static long sigma0(final long x) {
    return R(x, 1) ^ R(x, 8) ^ (x >>> 7);
  }

  private static long sigma1(final long x) {
    return R(x, 19) ^ R(x, 61) ^ (x >>> 6);
  }

  private static final long[] K = {0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L, 0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L, 0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL, 0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL, 0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L, 0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL, 0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL, 0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL, 0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L};

  private static long dl64(final byte[] x, final int xoff, final int xlen) {
    long u = 0;
    for (int i = 0; i < 8; ++i)
      u = (u << 8) | (x[i + xoff] & 0xff);

    return u;
  }

  private static void ts64(final byte[] x, final int xoff, final int xlen, long u) {
    for (int i = 7; i >= 0; --i) {
      x[i + xoff] = (byte)(u & 0xff);
      u >>>= 8;
    }
  }

  /**
   * Returns the SHA-512 hash of the message.
   *
   * @param message The message.
   * @return The SHA-512 hash of the message.
   */
  public static byte[] sha512(final byte[] message) {
    if (!(message != null && message.length > 0))
      return null;

    final byte[] out = new byte[hashLength];
    cryptoHash(out, message);
    return out;
  }

  public static byte[] sha512(final String message) throws UnsupportedEncodingException {
    return sha512(message.getBytes("utf-8"));
  }
}