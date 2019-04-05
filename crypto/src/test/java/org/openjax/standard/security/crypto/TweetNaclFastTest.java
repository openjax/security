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

package org.openjax.standard.security.crypto;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;

import org.junit.Test;
import org.openjax.standard.security.crypto.KeyPair;
import org.openjax.standard.security.crypto.HashFast;
import org.openjax.standard.security.crypto.TweetNaclFast;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TweetNaclFastTest {
  private static final Logger logger = LoggerFactory.getLogger(TweetNaclFastTest.class);
  private static final String TAG = "TweetNaclFastTest";

  /**
   * Curve25519 test vectors to help ensure correctness and interoperability
   * copied from Kalium project (https://github.com/abstractj/kalium)
   */

  public static final String BOB_PRIVATE_KEY = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
  public static final String BOB_PUBLIC_KEY = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

  public static final String ALICE_PRIVATE_KEY = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
  public static final String ALICE_PUBLIC_KEY = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
  public static final String ALICE_MULT_BOB = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

  public static final String BOX_NONCE = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";
  public static final String BOX_MESSAGE = "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffce5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb310e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f937763848645e0705";
  public static final String BOX_CIPHERTEXT = "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5";

  public static final String SECRET_KEY = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";

  public static final String SIGN_PRIVATE = "b18e1d0045995ec3d010c387ccfeb984d783af8fbb0f40fa7db126d889f6dadd";
  public static final String SIGN_MESSAGE = "916c7d1d268fc0e77c1bef238432573c39be577bbea0998936add2b50a653171ce18a542b0b7f96c1691a3be6031522894a8634183eda38798a0c5d5d79fbd01dd04a8646d71873b77b221998a81922d8105f892316369d5224c9983372d2313c6b1f4556ea26ba49d46e8b561e0fc76633ac9766e68e21fba7edca93c4c7460376d7f3ac22ff372c18f613f2ae2e856af40";
  public static final String SIGN_SIGNATURE = "6bd710a368c1249923fc7a1610747403040f0cc30815a00f9ff548a896bbda0b4eb2ca19ebcf917f0f34200a9edbad3901b64ab09cc5ef7b9bcc3c40c0ff7509";
  public static final String SIGN_PUBLIC = "77f48b59caeda77751ed138b0ec667ff50f8768c25d48309a8f386a2bad187fb";

  @Test
  public void testBoxKalium() {
    logger.debug(TAG, "testBoxKalium: test vectors from Kalium project");

    // explicit nonce
    final byte[] theNonce = TweetNaclFast.hexDecode(BOX_NONCE);
    logger.debug(TAG, "BOX_NONCE: \"" + TweetNaclFast.hexEncodeToString(theNonce) + "\"");

    // keypair A
    final byte[] ska = TweetNaclFast.hexDecode(ALICE_PRIVATE_KEY);
    final KeyPair ka = TweetNaclFast.Box.keyPair(ska);

    logger.debug(TAG, "ska: \"" + TweetNaclFast.hexEncodeToString(ka.getSecretKey()) + "\"");
    logger.debug(TAG, "pka: \"" + TweetNaclFast.hexEncodeToString(ka.getPublicKey()) + "\"");

    // keypair B
    final byte[] skb = TweetNaclFast.hexDecode(BOB_PRIVATE_KEY);
    final KeyPair kb = TweetNaclFast.Box.keyPair(skb);

    logger.debug(TAG, "skb: \"" + TweetNaclFast.hexEncodeToString(kb.getSecretKey()) + "\"");
    logger.debug(TAG, "pkb: \"" + TweetNaclFast.hexEncodeToString(kb.getPublicKey()) + "\"");

    // peer A -> B
    final TweetNaclFast.Box pabFast = new TweetNaclFast.Box(kb.getPublicKey(), ka.getSecretKey());

    // peer B -> A
    final TweetNaclFast.Box pbaFast = new TweetNaclFast.Box(ka.getPublicKey(), kb.getSecretKey());

    // messages
    logger.debug(TAG, "BOX_MESSAGE: \n" + BOX_MESSAGE.toUpperCase());
    logger.debug(TAG, "BOX_CIPHERTEXT: \n" + BOX_CIPHERTEXT.toUpperCase());

    // cipher A -> B
    final byte[] cabFast = pabFast.box(TweetNaclFast.hexDecode(BOX_MESSAGE), theNonce);
    logger.debug(TAG, "cabFast: \n" + TweetNaclFast.hexEncodeToString(cabFast));

    assertEquals("!!! TweetNaclFast Box::box/open failed Kalium compatibility !!!", BOX_CIPHERTEXT.toUpperCase(), TweetNaclFast.hexEncodeToString(cabFast));

    final byte[] mbaFastFast = pbaFast.open(cabFast, theNonce);
    logger.debug(TAG, "mbaFastFast: \n" + TweetNaclFast.hexEncodeToString(mbaFastFast));

    assertEquals("!!! TweetNaclFast Box::box/open failed Kalium compatibility !!!", BOX_MESSAGE.toUpperCase(), TweetNaclFast.hexEncodeToString(mbaFastFast));
  }

  @Test
  public void testBox() throws UnsupportedEncodingException {
    // keypair A
    final byte[] ska = new byte[32];
    for (int i = 0; i < 32; i++)
      ska[i] = 0;

    final KeyPair ka = TweetNaclFast.Box.keyPair(ska);

    String skat = "";
    for (int i = 0; i < ka.getSecretKey().length; i++)
      skat += " " + ka.getSecretKey()[i];

    logger.debug(TAG, "skat: " + skat);

    String pkat = "";
    for (int i = 0; i < ka.getPublicKey().length; i++)
      pkat += " " + ka.getPublicKey()[i];

    logger.debug(TAG, "pkat: " + pkat);

    // keypair B
    final byte[] skb = new byte[32];
    for (int i = 0; i < 32; i++)
      skb[i] = 1;

    final KeyPair kb = TweetNaclFast.Box.keyPair(skb);

    String skbt = "";
    for (int i = 0; i < kb.getSecretKey().length; i++)
      skbt += " " + kb.getSecretKey()[i];

    logger.debug(TAG, "skbt: " + skbt);

    String pkbt = "";
    for (int i = 0; i < kb.getPublicKey().length; i++)
      pkbt += " " + kb.getPublicKey()[i];

    logger.debug(TAG, "pkbt: " + pkbt);

    // peer A -> B
    final TweetNaclFast.Box pab = new TweetNaclFast.Box(kb.getPublicKey(), ka.getSecretKey(), 0);

    // peer B -> A
    final TweetNaclFast.Box pba = new TweetNaclFast.Box(ka.getPublicKey(), kb.getSecretKey(), 0);

    // messages
    final String m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    final byte[] cab = pab.box(m0.getBytes("utf-8"));
    String cabt = "";
    for (int i = 0; i < cab.length; i++)
      cabt += " " + cab[i];

    logger.debug(TAG, "cabt: " + cabt);

    final byte[] mba = pba.open(cab);
    String mbat = "";
    for (int i = 0; i < mba.length; i++)
      mbat += " " + mba[i];

    logger.debug(TAG, "mbat: " + mbat);

    final String nm0 = new String(mba, "utf-8");
    assertEquals("box/open string failed", nm0, m0);

    // cipher B -> A
    final byte[] b0 = new byte[100 * 1000000];
    for (int i = 0; i < b0.length; i++)
      b0[i] = (byte)i;

    logger.debug(TAG, "big of 100M  box@" + System.currentTimeMillis());
    final byte[] cba = pba.box(b0);
    final byte[] mab = pab.open(cba);
    logger.debug(TAG, "big of 100M open@" + System.currentTimeMillis());

    assertArrayEquals("big of 100M box/open binary failed", b0, mab);
  }

  @Test
  public void testBoxNonce() throws UnsupportedEncodingException {
    // explicit nonce
    final byte[] theNonce = TweetNaclFast.makeBoxNonce();
    final byte[] theNonce3 = TweetNaclFast.hexDecode(TweetNaclFast.hexEncodeToString(theNonce));
    logger.debug(TAG, "BoxNonce Hex test Equal: \"" + java.util.Arrays.equals(theNonce, theNonce3) + "\"");
    String theNoncet = "";
    for (int i = 0; i < theNonce.length; i++)
      theNoncet += " " + theNonce[i];

    logger.debug(TAG, "BoxNonce: " + theNoncet);
    logger.debug(TAG, "BoxNonce: \"" + TweetNaclFast.hexEncodeToString(theNonce) + "\"");

    // keypair A
    final byte[] ska = new byte[32];
    for (int i = 0; i < 32; i++)
      ska[i] = 0;

    final KeyPair ka = TweetNaclFast.Box.keyPair(ska);

    String skat = "";
    for (int i = 0; i < ka.getSecretKey().length; i++)
      skat += " " + ka.getSecretKey()[i];

    logger.debug(TAG, "skat: " + skat);

    String pkat = "";
    for (int i = 0; i < ka.getPublicKey().length; i++)
      pkat += " " + ka.getPublicKey()[i];

    logger.debug(TAG, "pkat: " + pkat);

    // keypair B
    byte[] skb = new byte[32];
    for (int i = 0; i < 32; i++)
      skb[i] = 1;

    final KeyPair kb = TweetNaclFast.Box.keyPair(skb);

    String skbt = "";
    for (int i = 0; i < kb.getSecretKey().length; i++)
      skbt += " " + kb.getSecretKey()[i];

    logger.debug(TAG, "skbt: " + skbt);

    String pkbt = "";
    for (int i = 0; i < kb.getPublicKey().length; i++)
      pkbt += " " + kb.getPublicKey()[i];

    logger.debug(TAG, "pkbt: " + pkbt);

    // peer A -> B
    final TweetNaclFast.Box pab = new TweetNaclFast.Box(kb.getPublicKey(), ka.getSecretKey());

    // peer B -> A
    final TweetNaclFast.Box pba = new TweetNaclFast.Box(ka.getPublicKey(), kb.getSecretKey());

    // messages
    String m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    final byte[] cab = pab.box(m0.getBytes("utf-8"), theNonce);
    String cabt = "";
    for (int i = 0; i < cab.length; i++)
      cabt += " " + cab[i];

    logger.debug(TAG, "cabt: " + cabt);

    final byte[] mba = pba.open(cab, theNonce);
    String mbat = "";
    for (int i = 0; i < mba.length; i++)
      mbat += " " + mba[i];

    logger.debug(TAG, "mbat: " + mbat);

    final String nm0 = new String(mba, "utf-8");
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
    final byte[] shk = new byte[TweetNaclFast.SecretBox.keyLength];
    for (int i = 0; i < shk.length; i++)
      shk[i] = 0x66;

    // peer A -> B
    final TweetNaclFast.SecretBox pab = new TweetNaclFast.SecretBox(shk, 0);

    // peer B -> A
    final TweetNaclFast.SecretBox pba = new TweetNaclFast.SecretBox(shk, 0);

    // messages
    String m0 = "Helloword, Am Tom ...";

    // cipher A -> B
    logger.debug(TAG, "streess on secret box@" + m0);

    for (int t = 0; t < 19; t++, m0 += m0) {
      final byte[] mb0 = m0.getBytes("utf-8");
      logger.debug(TAG, "\n\n\tstreess/" + (mb0.length / 1000.0) + "kB: " + t + " times");

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
    // explicit nonce
    final byte[] theNonce = TweetNaclFast.makeSecretBoxNonce();
    String theNoncet = "";
    for (int i = 0; i < theNonce.length; i++)
      theNoncet += " " + theNonce[i];

    logger.debug(TAG, "SecretBoxNonce: " + theNoncet);

    // shared key
    final byte[] shk = new byte[TweetNaclFast.SecretBox.keyLength];
    for (int i = 0; i < shk.length; i++)
      shk[i] = 0x66;

    // peer A -> B
    final TweetNaclFast.SecretBox pab = new TweetNaclFast.SecretBox(shk);

    // peer B -> A
    final TweetNaclFast.SecretBox pba = new TweetNaclFast.SecretBox(shk);

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
    final KeyPair ka = TweetNaclFast.Signature.keyPair();

    // keypair B
    final KeyPair kb = TweetNaclFast.Signature.keyPair();

    // peer A -> B
    final TweetNaclFast.Signature pab = new TweetNaclFast.Signature(kb.getPublicKey(), ka.getSecretKey());

    // peer B -> A
    final TweetNaclFast.Signature pba = new TweetNaclFast.Signature(ka.getPublicKey(), kb.getSecretKey());

    // messages
    String m0 = "Helloword, Am Tom ...";

    // signature A -> B
    logger.debug(TAG, "\nsign...@" + System.currentTimeMillis());
    final byte[] sab = pab.sign(m0.getBytes("utf-8"));
    logger.debug(TAG, "...sign@" + System.currentTimeMillis());

    String sgt = "sign@" + m0 + ": ";
    for (int i = 0; i < TweetNaclFast.Signature.signatureLength; i++)
      sgt += " " + sab[i];

    logger.debug(TAG, sgt);

    logger.debug(TAG, "verify...@" + System.currentTimeMillis());
    final byte[] oba = pba.open(sab);
    logger.debug(TAG, "...verify@" + System.currentTimeMillis());

    assertNotNull("verify failed", oba);
    String nm0 = new String(oba, "utf-8");
    assertEquals("sign failed", nm0, m0);

    // keypair C
    final byte[] seed = new byte[TweetNaclFast.Signature.seedLength];
    for (int i = 0; i < seed.length; i++)
      seed[i] = 0x66;

    final KeyPair kc = TweetNaclFast.Signature.keyPairFromSeed(seed);

    String skct = "";
    for (int i = 0; i < kc.getSecretKey().length; i++)
      skct += " " + kc.getSecretKey()[i];

    logger.debug(TAG, "skct: " + skct);

    String pkct = "";
    for (int i = 0; i < kc.getPublicKey().length; i++)
      pkct += " " + kc.getPublicKey()[i];

    logger.debug(TAG, "pkct: " + pkct);

    // self-signed
    final TweetNaclFast.Signature pcc = new TweetNaclFast.Signature(kc.getPublicKey(), kc.getSecretKey());

    logger.debug(TAG, "\nself-sign...@" + System.currentTimeMillis());
    final byte[] scc = pcc.sign(m0.getBytes("utf-8"));
    logger.debug(TAG, "...self-sign@" + System.currentTimeMillis());

    String ssc = "self-sign@" + m0 + ": ";
    for (int i = 0; i < TweetNaclFast.Signature.signatureLength; i++)
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
    final byte[] hash = HashFast.sha512(b0);
    logger.debug(TAG, "...sha512@" + System.currentTimeMillis());

    String hst = "sha512@" + m0 + "/" + b0.length + ": ";
    for (int i = 0; i < hash.length; i++)
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

  private static void testSignDetached(String seedStr) {
    logger.debug(TAG, "seed:@" + System.currentTimeMillis());

    final byte[] seed = TweetNaclFast.hexDecode(seedStr);
    final KeyPair kp = TweetNaclFast.Signature.keyPairFromSeed(seed);

    final String testString = "test string";
    final byte[] bytes = testString.getBytes();

    final TweetNaclFast.Signature s1 = new TweetNaclFast.Signature(null, kp.getSecretKey());
    logger.debug(TAG, "\ndetached...@" + System.currentTimeMillis());
    final byte[] signature = s1.detached(bytes);
    logger.debug(TAG, "...detached@" + System.currentTimeMillis());

    final TweetNaclFast.Signature s2 = new TweetNaclFast.Signature(kp.getPublicKey(), null);
    logger.debug(TAG, "\nverify...@" + System.currentTimeMillis());
    final boolean result = s2.detached_verify(bytes, signature);
    logger.debug(TAG, "...verify@" + System.currentTimeMillis());

    assertTrue("verify failed", result);
  }

  /**
   * bench test using tweetnacl.c, tweetnacl.js result
   */
  @Test
  public void testBench() {
  }
}