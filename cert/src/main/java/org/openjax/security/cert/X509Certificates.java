/* Copyright (c) 2021 OpenJAX
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

package org.openjax.security.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import org.openjax.security.crypto.Hash;

/**
 * Utility functions pertaining to {@link X509Certificate}s.
 */
public final class X509Certificates {
  private enum Type {
    CERTIFICATE("CERTIFICATE"),
    PUBLIC_KEY("PUBLIC KEY"),
    PRIVATE_KEY("PRIVATE KEY");

    private final String name;

    private Type(final String name) {
      this.name = name;
    }

    @Override
    public String toString() {
      return name;
    }
  }

  private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
  private static final String END_CERT = "-----END CERTIFICATE-----";
  private static final String LINE_SEPARATOR = System.getProperty("line.separator");

  private static String certToBase64(final byte[] encoded, final boolean wrap) {
    final Base64.Encoder encoder = Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes());
    final String encodedCertText = new String(encoder.encode(encoded));
    return wrap ? BEGIN_CERT + LINE_SEPARATOR + encodedCertText + LINE_SEPARATOR + END_CERT : encodedCertText;
  }

  private static String removeBeginEnd(String pem, final Type type) {
    pem = pem.replace("\r\n", "");
    pem = pem.replace("\n", "");
    final int len = pem.length();
    if (type == null) {
      pem = pem.replaceAll("-----(BEGIN|END) (.*)-----", "");
    }
    else {
      pem = pem.replace("-----BEGIN " + type + "-----", "");
      if (pem.length() == len)
        return pem;

      pem = pem.replace("-----END " + type + "----", "");
    }

    return pem.trim();
  }

  /**
   * Returns a {@link X509Certificate} decoded from the provided Base64-encoded
   * PEM certificate.
   *
   * @param cert The Base64-encoded PEM certificate.
   * @return A {@link X509Certificate} decoded from the provided Base64-encoded
   *         PEM certificate.
   * @throws CertificateException If an exception occurs parsing the provided
   *           {@code cert}.
   */
  public static X509Certificate decodeCertificate(final String cert) throws CertificateException {
    final byte[] der;
    return cert == null ? null : (der = pemToDer(cert, Type.CERTIFICATE)) == null ? null : decodeCertificate(new ByteArrayInputStream(der));
  }

  /**
   * Returns a {@link PublicKey} decoded from the provided Base64-encoded public
   * key.
   *
   * @param key The Base64-encoded public key.
   * @return A {@link PublicKey} decoded from the provided Base64-encoded public
   *         key.
   * @throws InvalidKeySpecException If an exception occurs producing the public
   *           key from the provided {@code key}.
   */
  public static PublicKey decodePublicKey(final String key) throws InvalidKeySpecException {
    return key == null ? null : decodePublicKey(pemToDer(key, Type.PUBLIC_KEY));
  }

  /**
   * Returns a {@link PrivateKey} decoded from the provided Base64-encoded
   * private key.
   *
   * @param key The Base64-encoded private key.
   * @return A {@link PrivateKey} decoded from the provided Base64-encoded
   *         private key.
   * @throws InvalidKeySpecException If an exception occurs producing the
   *           private key from the provided {@code key}.
   */
  public static PrivateKey decodePrivateKey(final String key) throws InvalidKeySpecException {
    return key == null ? null : decodePrivateKey(pemToDer(key, Type.PRIVATE_KEY));
  }

  /**
   * Returns a Base64-encoded string representation of the provided {@link Key}.
   *
   * @param key The {@link Key} to encode.
   * @return A Base64-encoded string representation of the provided {@link Key}.
   * @throws NullPointerException If {@code key} is null.
   */
  public static String encodeKey(final Key key) {
    return certToBase64(key.getEncoded(), false);
  }

  /**
   * Returns a Base64-encoded string representation of the provided
   * {@link Certificate}.
   *
   * @param certificate The {@link Certificate} to encode.
   * @return A Base64-encoded string representation of the provided
   *         {@link Certificate}.
   * @throws CertificateEncodingException If an encoding error occurs.
   * @throws NullPointerException If {@code certificate} is null.
   */
  public static String encodeCertificate(final Certificate certificate) throws CertificateEncodingException {
    return certToBase64(certificate.getEncoded(), false);
  }

  /**
   * Returns a DER representation of the provided Base64-encoded string PEM.
   *
   * @param pem The Base64-encoded string PEM.
   * @return A DER representation of the provided Base64-encoded string PEM.
   */
  public static byte[] pemToDer(final String pem) {
    return pemToDer(pem, null);
  }

  /**
   * Returns a DER representation of the provided Base64-encoded string PEM.
   *
   * @param pem The Base64-encoded string PEM.
   * @param type The {@link Type} of the PEM.
   * @return A DER representation of the provided Base64-encoded string PEM.
   */
  private static byte[] pemToDer(final String pem, final Type type) {
    try {
      return pem == null ? null : Base64.getDecoder().decode(removeBeginEnd(pem, type));
    }
    catch (final IllegalArgumentException e) {
      return null;
    }
  }

  /**
   * Returns a thumbprint of the provided Base64-encoded PEM {@code certificate}
   * with the specified {@link Hash} algorithm.
   *
   * @param certificate The Base64-encoded PEM certificate.
   * @param hash The {@link Hash} algorithm.
   * @return A thumbprint of the provided {@code certChain} with the specified
   *         {@link Hash} algorithm.
   * @throws NullPointerException If {@code certChain} or {@code hash} is null.
   */
  public static byte[] generateThumbprint(final String certificate, final Hash hash) {
    return hash.encode(pemToDer(certificate, Type.CERTIFICATE));
  }

  /**
   * Returns a {@link PublicKey} from the provided {@code der} byte array.
   *
   * @param der The DER byte array.
   * @return A {@link PublicKey} from the provided {@code der} byte array.
   * @throws InvalidKeySpecException If an exception occurs generating the
   *           private key from the provided {@code der} byte array.
   * @throws NullPointerException If {@code der} is null.
   */
  public static PublicKey decodePublicKey(final byte[] der) throws InvalidKeySpecException {
    try {
      return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
    }
    catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Returns a {@link PrivateKey} from the provided {@code der} byte array.
   *
   * @param der The DER byte array.
   * @return A {@link PrivateKey} from the provided {@code der} byte array.
   * @throws InvalidKeySpecException If an exception occurs generating the
   *           private key from the provided {@code der} byte array.
   * @throws NullPointerException If {@code der} is null.
   */
  public static PrivateKey decodePrivateKey(final byte[] der) throws InvalidKeySpecException {
    try {
      return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }
    catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Returns a {@link X509Certificate} from the specified {@link InputStream}
   * providing a DER-formatted certificate.
   *
   * @param in An {@link InputStream} providing a DER-formatted certificate.
   * @return A {@link X509Certificate} from the specified {@link InputStream}
   *         providing a DER-formatted certificate.
   * @throws CertificateException If an exception occurs parsing the
   *           DER-formatted certificate from the provided {@link InputStream}.
   * @throws NullPointerException If {@code in} is null.
   */
  public static X509Certificate decodeCertificate(final InputStream in) throws CertificateException {
    Objects.requireNonNull(in);
    final CertificateFactory certificateFactory;
    try {
      certificateFactory = CertificateFactory.getInstance("X.509");
    }
    catch (final CertificateException e) {
      throw new RuntimeException(e);
    }

    return (X509Certificate)certificateFactory.generateCertificate(in);
  }

  /**
   * Returns a new {@link KeyStore} instance that is loaded and initialized from
   * the provided {@link InputStream}, and unlocked if the provided
   * {@code storePassword} is not null. The type of the new {@link KeyStore} is
   * the default keystore type as specified by the {@code keystore.type}
   * {@linkplain java.security.Security#getProperty security property}, or the
   * string "jks" (acronym for "Java keystore") if no such property exists.
   *
   * @param url
   * @param storePassword
   * @return A new {@link KeyStore} instance that is loaded and initialized from
   *         the provided {@link InputStream}, and unlocked if the provided
   *         {@code storePassword} is not null.
   * @throws CertificateException If any of the certificates in the keystore
   *           could not be loaded.
   * @throws IOException If an I/O error has occurred.
   * @throws KeyStoreException If no {@link java.security.Provider} supports a
   *           {@link java.security.KeyStoreSpi} implementation for the
   *           specified type.
   * @throws NoSuchAlgorithmException If the algorithm used to check the
   *           integrity of the keystore cannot be found.
   * @throws NullPointerException If {@code url} is null.
   */
  public static KeyStore getKeyStore(final URL url, final String storePassword) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
    final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
    try (final InputStream in = url.openStream()) {
      keyStore.load(in, storePassword == null ? null : storePassword.toCharArray());
    }

    return keyStore;
  }

  /**
   * Returns {@code true} if the provided {@link X509Certificate} is self
   * issued, otherwise {@code false}.
   *
   * @param cert The {@link X509Certificate}.
   * @return {@code true} if the provided {@link X509Certificate} is self
   *         issued, otherwise {@code false}.
   */
  public static boolean isSelfIssued(final X509Certificate cert) {
    return cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());
  }

  private X509Certificates() {
  }
}