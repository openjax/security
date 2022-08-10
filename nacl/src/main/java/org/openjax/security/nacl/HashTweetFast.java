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
 * Hash algorithm, Implements SHA-512.
 */
final class HashTweetFast extends Hash {
  private static final long[] K = {0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L, 0x12835b0145706fbeL, 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L, 0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L, 0x983e5152ee66dfabL, 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 0x53380d139d95b3dfL, 0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL, 0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L, 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L, 0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL, 0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL, 0xca273eceea26619cL, 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 0x113f9804bef90daeL, 0x1b710b35131c471bL, 0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L};

  private static int cryptoHashBlocksHl(final int[] hh, final int[] hl, final byte[] m, final int moff, int n) {
    final int[] wh = new int[16], wl = new int[16];
    int bh0, bh1, bh2, bh3, bh4, bh5, bh6, bh7, bl0, bl1, bl2, bl3, bl4, bl5, bl6, bl7, th, tl, h, l, i, j, a, b, c, d;

    int ah0 = hh[0], ah1 = hh[1], ah2 = hh[2], ah3 = hh[3], ah4 = hh[4], ah5 = hh[5], ah6 = hh[6], ah7 = hh[7],
        al0 = hl[0], al1 = hl[1], al2 = hl[2], al3 = hl[3], al4 = hl[4], al5 = hl[5], al6 = hl[6], al7 = hl[7];

    int pos = 0;
    while (n >= 128) {
      for (i = 0; i < 16; ++i) { // [A]
        j = 8 * i + pos;
        wh[i] = ((m[j + 0 + moff] & 0xff) << 24) | ((m[j + 1 + moff] & 0xff) << 16) | ((m[j + 2 + moff] & 0xff) << 8) | ((m[j + 3 + moff] & 0xff));
        wl[i] = ((m[j + 4 + moff] & 0xff) << 24) | ((m[j + 5 + moff] & 0xff) << 16) | ((m[j + 6 + moff] & 0xff) << 8) | ((m[j + 7 + moff] & 0xff));
      }

      for (i = 0; i < 80; ++i) { // [A]
        bh0 = ah0;
        bh1 = ah1;
        bh2 = ah2;
        bh3 = ah3;
        bh4 = ah4;
        bh5 = ah5;
        bh6 = ah6;
        bh7 = ah7;

        bl0 = al0;
        bl1 = al1;
        bl2 = al2;
        bl3 = al3;
        bl4 = al4;
        bl5 = al5;
        bl6 = al6;
        bl7 = al7;

        // add
        h = ah7;
        l = al7;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        // Sigma1
        h = ((ah4 >>> 14) | (al4 << (32 - 14))) ^ ((ah4 >>> 18) | (al4 << (32 - 18))) ^ ((al4 >>> (41 - 32)) | (ah4 << (32 - (41 - 32))));
        l = ((al4 >>> 14) | (ah4 << (32 - 14))) ^ ((al4 >>> 18) | (ah4 << (32 - 18))) ^ ((ah4 >>> (41 - 32)) | (al4 << (32 - (41 - 32))));

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        // Ch
        h = (ah4 & ah5) ^ (~ah4 & ah6);
        l = (al4 & al5) ^ (~al4 & al6);

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        // K
        // h = K[i*2];
        // l = K[i*2+1];
        h = (int)(K[i] >>> 32);
        l = (int)K[i];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        // w
        h = wh[i % 16];
        l = wl[i % 16];

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        th = c & 0xffff | d << 16;
        tl = a & 0xffff | b << 16;

        // add
        h = th;
        l = tl;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        // Sigma0
        h = ((ah0 >>> 28) | (al0 << (32 - 28))) ^ ((al0 >>> (34 - 32)) | (ah0 << (32 - (34 - 32)))) ^ ((al0 >>> (39 - 32)) | (ah0 << (32 - (39 - 32))));
        l = ((al0 >>> 28) | (ah0 << (32 - 28))) ^ ((ah0 >>> (34 - 32)) | (al0 << (32 - (34 - 32)))) ^ ((ah0 >>> (39 - 32)) | (al0 << (32 - (39 - 32))));

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        // Maj
        h = (ah0 & ah1) ^ (ah0 & ah2) ^ (ah1 & ah2);
        l = (al0 & al1) ^ (al0 & al2) ^ (al1 & al2);

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        bh7 = (c & 0xffff) | (d << 16);
        bl7 = (a & 0xffff) | (b << 16);

        // add
        h = bh3;
        l = bl3;

        a = l & 0xffff;
        b = l >>> 16;
        c = h & 0xffff;
        d = h >>> 16;

        h = th;
        l = tl;

        a += l & 0xffff;
        b += l >>> 16;
        c += h & 0xffff;
        d += h >>> 16;

        b += a >>> 16;
        c += b >>> 16;
        d += c >>> 16;

        bh3 = (c & 0xffff) | (d << 16);
        bl3 = (a & 0xffff) | (b << 16);

        ah1 = bh0;
        ah2 = bh1;
        ah3 = bh2;
        ah4 = bh3;
        ah5 = bh4;
        ah6 = bh5;
        ah7 = bh6;
        ah0 = bh7;

        al1 = bl0;
        al2 = bl1;
        al3 = bl2;
        al4 = bl3;
        al5 = bl4;
        al6 = bl5;
        al7 = bl6;
        al0 = bl7;

        if (i % 16 == 15) {
          for (j = 0; j < 16; j++) { // [A]
            // add
            h = wh[j];
            l = wl[j];

            a = l & 0xffff;
            b = l >>> 16;
            c = h & 0xffff;
            d = h >>> 16;

            h = wh[(j + 9) % 16];
            l = wl[(j + 9) % 16];

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            // sigma0
            th = wh[(j + 1) % 16];
            tl = wl[(j + 1) % 16];
            h = ((th >>> 1) | (tl << (32 - 1))) ^ ((th >>> 8) | (tl << (32 - 8))) ^ (th >>> 7);
            l = ((tl >>> 1) | (th << (32 - 1))) ^ ((tl >>> 8) | (th << (32 - 8))) ^ ((tl >>> 7) | (th << (32 - 7)));

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            // sigma1
            th = wh[(j + 14) % 16];
            tl = wl[(j + 14) % 16];
            h = ((th >>> 19) | (tl << (32 - 19))) ^ ((tl >>> (61 - 32)) | (th << (32 - (61 - 32)))) ^ (th >>> 6);
            l = ((tl >>> 19) | (th << (32 - 19))) ^ ((th >>> (61 - 32)) | (tl << (32 - (61 - 32)))) ^ ((tl >>> 6) | (th << (32 - 6)));

            a += l & 0xffff;
            b += l >>> 16;
            c += h & 0xffff;
            d += h >>> 16;

            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;

            wh[j] = (c & 0xffff) | (d << 16);
            wl[j] = (a & 0xffff) | (b << 16);
          }
        }
      }

      // add
      h = ah0;
      l = al0;

      a = l & 0xffff;
      b = l >>> 16;
      c = h & 0xffff;
      d = h >>> 16;

      h = hh[0];
      l = hl[0];

      a += l & 0xffff;
      b += l >>> 16;
      c += h & 0xffff;
      d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      hh[0] = ah0 = (c & 0xffff) | (d << 16);
      hl[0] = al0 = (a & 0xffff) | (b << 16);

      h = ah1;
      l = al1;

      a = l & 0xffff;
      b = l >>> 16;
      c = h & 0xffff;
      d = h >>> 16;

      h = hh[1];
      l = hl[1];

      a += l & 0xffff;
      b += l >>> 16;
      c += h & 0xffff;
      d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      hh[1] = ah1 = (c & 0xffff) | (d << 16);
      hl[1] = al1 = (a & 0xffff) | (b << 16);

      h = ah2;
      l = al2;

      a = l & 0xffff;
      b = l >>> 16;
      c = h & 0xffff;
      d = h >>> 16;

      h = hh[2];
      l = hl[2];

      a += l & 0xffff;
      b += l >>> 16;
      c += h & 0xffff;
      d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      hh[2] = ah2 = (c & 0xffff) | (d << 16);
      hl[2] = al2 = (a & 0xffff) | (b << 16);

      h = ah3;
      l = al3;

      a = l & 0xffff;
      b = l >>> 16;
      c = h & 0xffff;
      d = h >>> 16;

      h = hh[3];
      l = hl[3];

      a += l & 0xffff;
      b += l >>> 16;
      c += h & 0xffff;
      d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      hh[3] = ah3 = (c & 0xffff) | (d << 16);
      hl[3] = al3 = (a & 0xffff) | (b << 16);

      h = ah4;
      l = al4;

      a = l & 0xffff;
      b = l >>> 16;
      c = h & 0xffff;
      d = h >>> 16;

      h = hh[4];
      l = hl[4];

      a += l & 0xffff;
      b += l >>> 16;
      c += h & 0xffff;
      d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      hh[4] = ah4 = (c & 0xffff) | (d << 16);
      hl[4] = al4 = (a & 0xffff) | (b << 16);

      h = ah5;
      l = al5;

      a = l & 0xffff;
      b = l >>> 16;
      c = h & 0xffff;
      d = h >>> 16;

      h = hh[5];
      l = hl[5];

      a += l & 0xffff;
      b += l >>> 16;
      c += h & 0xffff;
      d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      hh[5] = ah5 = (c & 0xffff) | (d << 16);
      hl[5] = al5 = (a & 0xffff) | (b << 16);

      h = ah6;
      l = al6;

      a = l & 0xffff;
      b = l >>> 16;
      c = h & 0xffff;
      d = h >>> 16;

      h = hh[6];
      l = hl[6];

      a += l & 0xffff;
      b += l >>> 16;
      c += h & 0xffff;
      d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      hh[6] = ah6 = (c & 0xffff) | (d << 16);
      hl[6] = al6 = (a & 0xffff) | (b << 16);

      h = ah7;
      l = al7;

      a = l & 0xffff;
      b = l >>> 16;
      c = h & 0xffff;
      d = h >>> 16;

      h = hh[7];
      l = hl[7];

      a += l & 0xffff;
      b += l >>> 16;
      c += h & 0xffff;
      d += h >>> 16;

      b += a >>> 16;
      c += b >>> 16;
      d += c >>> 16;

      hh[7] = ah7 = (c & 0xffff) | (d << 16);
      hl[7] = al7 = (a & 0xffff) | (b << 16);

      pos += 128;
      n -= 128;
    }

    return n;
  }

  // TBD 64bits of n
  static int cryptoHash(final byte[] out, final byte[] m, final int moff, int n) {
    final int[] hh = new int[8];
    final int[] hl = new int[8];
    final byte[] x = new byte[256];
    final int b = n;
    long u;

    hh[0] = 0x6a09e667;
    hh[1] = 0xbb67ae85;
    hh[2] = 0x3c6ef372;
    hh[3] = 0xa54ff53a;
    hh[4] = 0x510e527f;
    hh[5] = 0x9b05688c;
    hh[6] = 0x1f83d9ab;
    hh[7] = 0x5be0cd19;

    hl[0] = 0xf3bcc908;
    hl[1] = 0x84caa73b;
    hl[2] = 0xfe94f82b;
    hl[3] = 0x5f1d36f1;
    hl[4] = 0xade682d1;
    hl[5] = 0x2b3e6c1f;
    hl[6] = 0xfb41bd6b;
    hl[7] = 0x137e2179;

    if (n >= 128) {
      cryptoHashBlocksHl(hh, hl, m, moff, n);
      n %= 128;
    }

    int i;
    for (i = 0; i < n; ++i) // [A]
      x[i] = m[b - n + i + moff];
    x[n] = (byte)128;

    n = 256 - 128 * (n < 112 ? 1 : 0);
    x[n - 9] = 0;

    ts64(x, n - 8, b << 3/* (b / 0x20000000) | 0, b << 3 */);

    cryptoHashBlocksHl(hh, hl, x, 0, n);

    for (i = 0; i < 8; ++i) { // [A]
      u = hh[i];
      u <<= 32;
      u |= hl[i] & 0xffffffffL;
      ts64(out, 8 * i, u);
    }

    return 0;
  }

  @Override
  public int cryptoHash(final byte[] out, final byte[] m) {
    return cryptoHash(out, m, 0, m != null ? m.length : 0);
  }

  private static void ts64(final byte[] x, final int xoff, long u) {
    x[7 + xoff] = (byte)(u & 0xff);
    u >>>= 8;
    x[6 + xoff] = (byte)(u & 0xff);
    u >>>= 8;
    x[5 + xoff] = (byte)(u & 0xff);
    u >>>= 8;
    x[4 + xoff] = (byte)(u & 0xff);
    u >>>= 8;
    x[3 + xoff] = (byte)(u & 0xff);
    u >>>= 8;
    x[2 + xoff] = (byte)(u & 0xff);
    u >>>= 8;
    x[1 + xoff] = (byte)(u & 0xff);
    u >>>= 8;
    x[0 + xoff] = (byte)(u & 0xff);
  }

  HashTweetFast() {
  }
}