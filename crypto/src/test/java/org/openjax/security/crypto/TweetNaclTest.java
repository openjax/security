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

package org.openjax.security.crypto;

import static org.junit.Assert.*;
import static org.openjax.security.crypto.TweetNacl.Box.*;

import java.io.UnsupportedEncodingException;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TweetNaclTest {
  private static final Logger logger = LoggerFactory.getLogger(TweetNaclTest.class);
  private static final String TAG = "TweetNaclTest";

  @Test
  public void testBox() throws UnsupportedEncodingException {
    // keypair A
    final byte[] ska = new byte[32];
    for (int i = 0; i < 32; ++i)
      ska[i] = 0;

    final KeyPair ka = TweetNacl.Box.keyPair(ska);

    String skat = "";
    for (int i = 0; i < ka.getSecretKey().length; ++i)
      skat += " " + ka.getSecretKey()[i];

    logger.debug(TAG, "skat: " + skat);

    String pkat = "";
    for (int i = 0; i < ka.getPublicKey().length; ++i)
      pkat += " " + ka.getPublicKey()[i];

    logger.debug(TAG, "pkat: " + pkat);

    // keypair B
    final byte[] skb = new byte[32];
    for (int i = 0; i < 32; ++i)
      skb[i] = 1;

    final KeyPair kb = TweetNacl.Box.keyPair(skb);

    String skbt = "";
    for (int i = 0; i < kb.getSecretKey().length; ++i)
      skbt += " " + kb.getSecretKey()[i];

    logger.debug(TAG, "skbt: " + skbt);

    String pkbt = "";
    for (int i = 0; i < kb.getPublicKey().length; ++i)
      pkbt += " " + kb.getPublicKey()[i];

    logger.debug(TAG, "pkbt: " + pkbt);

    // peer A -> B
    TweetNacl.Box pab = new TweetNacl.Box(kb.getPublicKey(), ka.getSecretKey(), 0);

    // peer B -> A
    TweetNacl.Box pba = new TweetNacl.Box(ka.getPublicKey(), kb.getSecretKey(), 0);

    // messages
    String m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    final byte[] cab = pab.box(m0.getBytes("utf-8"));
    String cabt = "";
    for (int i = 0; i < cab.length; ++i)
      cabt += " " + cab[i];

    logger.debug(TAG, "cabt: " + cabt);

    final byte[] mba = pba.open(cab);
    String mbat = "";
    for (int i = 0; i < mba.length; ++i)
      mbat += " " + mba[i];

    logger.debug(TAG, "mbat: " + mbat);

    final String nm0 = new String(mba, "utf-8");
    assertEquals("box/open string failed", nm0, nm0);

    // cipher B -> A
    final byte[] b0 = new byte[6];

    logger.debug(TAG, "box@" + System.currentTimeMillis());
    byte[] cba = pba.box(b0);
    byte[] mab = pab.open(cba);
    logger.debug(TAG, "open@" + System.currentTimeMillis());

    assertArrayEquals("box/open binary failed", b0, mab);
  }

  @Test
  public void testBoxNonce() throws UnsupportedEncodingException {
    // explicit nonce
    final byte[] theNonce = new byte[nonceLength];
    TweetNacl.randombytes(theNonce, nonceLength);
    String theNoncet = "";
    for (int i = 0; i < theNonce.length; ++i)
      theNoncet += " " + theNonce[i];

    logger.debug(TAG, "BoxNonce: " + theNoncet);

    // keypair A
    byte[] ska = new byte[32];
    for (int i = 0; i < 32; ++i)
      ska[i] = 0;

    final KeyPair ka = TweetNacl.Box.keyPair(ska);

    String skat = "";
    for (int i = 0; i < ka.getSecretKey().length; ++i)
      skat += " " + ka.getSecretKey()[i];

    logger.debug(TAG, "skat: " + skat);

    String pkat = "";
    for (int i = 0; i < ka.getPublicKey().length; ++i)
      pkat += " " + ka.getPublicKey()[i];

    logger.debug(TAG, "pkat: " + pkat);

    // keypair B
    byte[] skb = new byte[32];
    for (int i = 0; i < 32; ++i)
      skb[i] = 1;

    final KeyPair kb = TweetNacl.Box.keyPair(skb);

    String skbt = "";
    for (int i = 0; i < kb.getSecretKey().length; ++i)
      skbt += " " + kb.getSecretKey()[i];

    logger.debug(TAG, "skbt: " + skbt);

    String pkbt = "";
    for (int i = 0; i < kb.getPublicKey().length; ++i)
      pkbt += " " + kb.getPublicKey()[i];
    logger.debug(TAG, "pkbt: " + pkbt);

    // peer A -> B
    final TweetNacl.Box pab = new TweetNacl.Box(kb.getPublicKey(), ka.getSecretKey());

    // peer B -> A
    final TweetNacl.Box pba = new TweetNacl.Box(ka.getPublicKey(), kb.getSecretKey());

    // messages
    final String m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    byte[] cab = pab.box(m0.getBytes("utf-8"), theNonce);
    String cabt = "";
    for (int i = 0; i < cab.length; ++i)
      cabt += " " + cab[i];

    logger.debug(TAG, "cabt: " + cabt);

    final byte[] mba = pba.open(cab, theNonce);
    String mbat = "";
    for (int i = 0; i < mba.length; ++i)
      mbat += " " + mba[i];

    logger.debug(TAG, "mbat: " + mbat);

    String nm0 = new String(mba, "utf-8");
    assertEquals("box/open string failed (with nonce)", nm0, m0);

    // cipher B -> A
    final byte[] b0 = new byte[6];

    logger.debug(TAG, "box@" + System.currentTimeMillis());
    final byte[] cba = pba.box(b0, theNonce);
    final byte[] mab = pab.open(cba, theNonce);
    logger.debug(TAG, "open@" + System.currentTimeMillis());

    assertArrayEquals("box/open binary failed (with nonce)", b0, mab);
  }

  @Test
  public void testSecretBox() throws UnsupportedEncodingException {
    // shared key
    final byte[] shk = new byte[TweetNacl.SecretBox.keyLength];
    for (int i = 0; i < shk.length; ++i)
      shk[i] = 0x66;

    // peer A -> B
    final TweetNacl.SecretBox pab = new TweetNacl.SecretBox(shk, 0);

    // peer B -> A
    final TweetNacl.SecretBox pba = new TweetNacl.SecretBox(shk, 0);

    // messages
    String m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    logger.debug(TAG, "stress on secret box@" + m0);

    for (int t = 0; t < 19; t++, m0 += m0) {
      final byte[] mb0 = m0.getBytes("utf-8");
      logger.debug(TAG, "\n\n\tstress/" + (mb0.length / 1000.0) + "kB: " + t + " times");

      /*
       * String mb0t = "mb0/"+mb0.length + ": "; for (int i = 0; i < mb0.length;
       * i ++) mb0t += " "+mb0[i]; logger.debug(TAG, mb0t);
       */
      logger.debug(TAG, "secret box ...@" + System.currentTimeMillis());
      final byte[] cab = pab.box(mb0);
      logger.debug(TAG, "... secret box@" + System.currentTimeMillis());

      /*
       * String cabt = "cab/"+cab.length + ": "; for (int i = 0; i < cab.length;
       * i ++) cabt += " "+cab[i]; logger.debug(TAG, cabt);
       */
      logger.debug(TAG, "\nsecret box open ...@" + System.currentTimeMillis());
      final byte[] mba = pba.open(cab);
      logger.debug(TAG, "... secret box open@" + System.currentTimeMillis());

      /*
       * String mbat = "mba/"+mba.length + ": "; for (int i = 0; i < mba.length;
       * i ++) mbat += " "+mba[i]; logger.debug(TAG, mbat);
       */

      final String nm0 = new String(mba, "utf-8");
      assertEquals("secret box/open failed", nm0, m0);
    }
  }

  @Test
  public void testSecretBoxNonce() throws UnsupportedEncodingException {
    // shared key plus explicit nonce

    // explicit nonce
    final byte[] theNonce = new byte[nonceLength];
    TweetNacl.randombytes(theNonce, nonceLength);
    String theNoncet = "";
    for (int i = 0; i < theNonce.length; ++i)
      theNoncet += " " + theNonce[i];

    logger.debug(TAG, "SecretBoxNonce: " + theNoncet);

    final byte[] shk = new byte[TweetNacl.SecretBox.keyLength];
    for (int i = 0; i < shk.length; ++i)
      shk[i] = 0x66;

    // peer A -> B
    final TweetNacl.SecretBox pab = new TweetNacl.SecretBox(shk);

    // peer B -> A
    final TweetNacl.SecretBox pba = new TweetNacl.SecretBox(shk);

    // messages
    String m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    logger.debug(TAG, "stress on secret box with explicit nonce@" + m0);

    for (int t = 0; t < 19; t++, m0 += m0) {
      final byte[] mb0 = m0.getBytes("utf-8");
      logger.debug(TAG, "\n\n\tstress/" + (mb0.length / 1000.0) + "kB: " + t + " times");

      /*
       * String mb0t = "mb0/"+mb0.length + ": "; for (int i = 0; i < mb0.length;
       * i ++) mb0t += " "+mb0[i]; logger.debug(TAG, mb0t);
       */
      logger.debug(TAG, "secret box ...@" + System.currentTimeMillis());
      final byte[] cab = pab.box(mb0, theNonce);
      logger.debug(TAG, "... secret box@" + System.currentTimeMillis());

      /*
       * String cabt = "cab/"+cab.length + ": "; for (int i = 0; i < cab.length;
       * i ++) cabt += " "+cab[i]; logger.debug(TAG, cabt);
       */
      logger.debug(TAG, "\nsecret box open ...@" + System.currentTimeMillis());
      final byte[] mba = pba.open(cab, theNonce);
      logger.debug(TAG, "... secret box open@" + System.currentTimeMillis());

      /*
       * String mbat = "mba/"+mba.length + ": "; for (int i = 0; i < mba.length;
       * i ++) mbat += " "+mba[i]; logger.debug(TAG, mbat);
       */

      final String nm0 = new String(mba, "utf-8");
      assertEquals("secret box/open failed (with nonce)", nm0, m0);
    }
  }

  @Test
  public void testSign() throws UnsupportedEncodingException {
    // keypair A
    final KeyPair ka = TweetNacl.Signature.keyPair();

    // keypair B
    final KeyPair kb = TweetNacl.Signature.keyPair();

    // peer A -> B
    final TweetNacl.Signature pab = new TweetNacl.Signature(kb.getPublicKey(), ka.getSecretKey());

    // peer B -> A
    final TweetNacl.Signature pba = new TweetNacl.Signature(ka.getPublicKey(), kb.getSecretKey());

    // messages
    final String m0 = "Helloword, Am Tom ...";

    // signature A -> B
    logger.debug(TAG, "\nsign...@" + System.currentTimeMillis());
    final byte[] sab = pab.sign(m0.getBytes("utf-8"));
    logger.debug(TAG, "...sign@" + System.currentTimeMillis());

    String sgt = "sign@" + m0 + ": ";
    for (int i = 0; i < TweetNacl.Signature.signatureLength; ++i)
      sgt += " " + sab[i];

    logger.debug(TAG, sgt);

    logger.debug(TAG, "verify...@" + System.currentTimeMillis());
    final byte[] oba = pba.open(sab);
    logger.debug(TAG, "...verify@" + System.currentTimeMillis());

    assertNotNull("verify failed", oba);
    String nm0 = new String(oba, "utf-8");
    assertEquals("sign failed", nm0, m0);

    // keypair C
    final byte[] seed = new byte[TweetNacl.Signature.seedLength];
    for (int i = 0; i < seed.length; ++i)
      seed[i] = 0x66;

    final KeyPair kc = TweetNacl.Signature.keyPairFromSeed(seed);

    String skct = "";
    for (int i = 0; i < kc.getSecretKey().length; ++i)
      skct += " " + kc.getSecretKey()[i];

    logger.debug(TAG, "skct: " + skct);

    String pkct = "";
    for (int i = 0; i < kc.getPublicKey().length; ++i)
      pkct += " " + kc.getPublicKey()[i];

    logger.debug(TAG, "pkct: " + pkct);

    // self-signed
    final TweetNacl.Signature pcc = new TweetNacl.Signature(kc.getPublicKey(), kc.getSecretKey());

    logger.debug(TAG, "\nself-sign...@" + System.currentTimeMillis());
    byte[] scc = pcc.sign(m0.getBytes("utf-8"));
    logger.debug(TAG, "...self-sign@" + System.currentTimeMillis());

    String ssc = "self-sign@" + m0 + ": ";
    for (int i = 0; i < TweetNacl.Signature.signatureLength; ++i)
      ssc += " " + scc[i];

    logger.debug(TAG, ssc);

    logger.debug(TAG, "self-verify...@" + System.currentTimeMillis());
    final byte[] occ = pcc.open(scc);
    logger.debug(TAG, "...self-verify@" + System.currentTimeMillis());

    assertNotNull("self-verify failed", occ);
    nm0 = new String(occ, "utf-8");
    assertEquals("self-sign failed", nm0, m0);
  }

  /*
   * SHA-512
   */
  @Test
  public void testHash() throws UnsupportedEncodingException {
    final String m0 = "Helloword, Am Tom ...";
    final byte[] b0 = m0.getBytes("utf-8");

    logger.debug(TAG, "\nsha512...@" + System.currentTimeMillis());
    final byte[] hash = Hash.sha512(b0);
    logger.debug(TAG, "...sha512@" + System.currentTimeMillis());

    String hst = "sha512@" + m0 + "/" + b0.length + ": ";
    for (int i = 0; i < hash.length; ++i)
      hst += " " + hash[i];

    logger.debug(TAG, hst);
  }

  @Test
  public void testSignDetached1() {
    testSignDetached("ac49000da11249ea3510941703a7e21a39837c4d2d5300daebbd532df20f8135");
  }

  @Test
  public void testSignDetached2() {
    testSignDetached("e56f0eef73ade8f79bc1d16a99cbc5e4995afd8c14adb49410ecd957aecc8d02");
  }

  private static void testSignDetached(final String seedStr) {
    logger.debug(TAG, "seed:@" + System.currentTimeMillis());

    final byte[] seed = TweetNaclFast.hexDecode(seedStr);
    final KeyPair kp = TweetNacl.Signature.keyPairFromSeed(seed);

    final String testString = "test string";
    final byte[] bytes = testString.getBytes();

    final TweetNacl.Signature s1 = new TweetNacl.Signature(null, kp.getSecretKey());
    logger.debug(TAG, "\ndetached...@" + System.currentTimeMillis());
    byte[] signature = s1.detached(bytes);
    logger.debug(TAG, "...detached@" + System.currentTimeMillis());

    final TweetNacl.Signature s2 = new TweetNacl.Signature(kp.getPublicKey(), null);
    logger.debug(TAG, "\nverify...@" + System.currentTimeMillis());
    final boolean result = s2.detachedVerify(bytes, signature);
    logger.debug(TAG, "...verify@" + System.currentTimeMillis());

    assertTrue("verify failed", result);
  }

  /*
   * bench test using tweetnacl.c, tweetnacl.js result
   */
  @Test
  public void testBench() {
  }
}