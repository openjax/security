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
  private static final String LINE_SEPARATOR = System.getProperty("line.separator");

  private enum Type {
    CERTIFICATE("CERTIFICATE"),
    PUBLIC_KEY("PUBLIC KEY"),
    PRIVATE_KEY("PRIVATE KEY");

    private final String name;
    private final String begin;
    private final String end;

    private Type(final String name) {
      this.name = name;
      this.begin = "-----BEGIN " + name + "-----";
      this.end = "-----END " + name + "-----";
    }

    /**
     * Returns a DER representation of the provided Base64-encoded string PEM.
     *
     * @param pem The Base64-encoded string PEM.
     * @return A DER representation of the provided Base64-encoded string PEM.
     */
    byte[] pemToDer(final String pem) {
      try {
        return pem == null ? null : Base64.getDecoder().decode(unwrap(pem));
      }
      catch (final IllegalArgumentException e) {
        return null;
      }
    }

    /**
     * Returns a Base64-encoded string PEM representation of the provided DER.
     *
     * @param der The DER.
     * @param wrap Whether the PEM should be wrapped with a header and footer.
     * @return A Base64-encoded string PEM representation of the provided DER.
     */
    String derToPem(final byte[] der, final boolean wrap) {
      return wrap ? begin + LINE_SEPARATOR + Base64.getMimeEncoder(64, LINE_SEPARATOR.getBytes()).encodeToString(der) + LINE_SEPARATOR + end : Base64.getEncoder().encodeToString(der);
    }

    String unwrap(String pem) {
      pem = pem.replace("\r\n", "").replace("\n", "");
      final int len = pem.length();
      pem = pem.replace(begin, "");
      return pem.length() == len ? pem : pem.replace(end, "");
    }

    @Override
    public String toString() {
      return name;
    }
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
    return cert == null ? null : (der = Type.CERTIFICATE.pemToDer(cert)) == null ? null : decodeCertificate(new ByteArrayInputStream(der));
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
    return key == null ? null : decodePublicKey(Type.PUBLIC_KEY.pemToDer(key));
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
    return key == null ? null : decodePrivateKey(Type.PRIVATE_KEY.pemToDer(key));
  }

  /**
   * Returns a Base64-encoded string (with "-----PRIVATE KEY-----" header)
   * representation of the provided {@link PrivateKey}.
   *
   * @param key The {@link PrivateKey} to encode.
   * @return A Base64-encoded string (with "-----PRIVATE KEY-----" header)
   *         representation of the provided {@link PrivateKey}.
   * @throws IllegalArgumentException If {@code key} is null.
   */
  public static String encodeKey(final PrivateKey key) {
    return Type.PRIVATE_KEY.derToPem(key.getEncoded(), true);
  }

  /**
   * Returns a Base64-encoded string (with "-----PUBLIC KEY-----" header)
   * representation of the provided {@link PublicKey}.
   *
   * @param key The {@link PublicKey} to encode.
   * @return A Base64-encoded string (with "-----PUBLIC KEY-----" header)
   *         representation of the provided {@link PublicKey}.
   * @throws IllegalArgumentException If {@code key} is null.
   */
  public static String encodeKey(final PublicKey key) {
    return Type.PUBLIC_KEY.derToPem(key.getEncoded(), true);
  }

  /**
   * Returns a Base64-encoded string (without "-----CERTIFICATE-----" header)
   * representation of the provided der-encoded certificate bytes.
   *
   * @param certificate The der-encoded certificate bytes to encode.
   * @return A Base64-encoded string (without "-----CERTIFICATE-----" header)
   *         representation of the provided {@link Certificate}.
   * @throws CertificateEncodingException If an encoding error occurs.
   * @throws IllegalArgumentException If {@code certificate} is null.
   */
  public static String encodeCertificate(final byte[] certificate) throws CertificateEncodingException {
    return Type.CERTIFICATE.derToPem(certificate, false);
  }

  /**
   * Returns a Base64-encoded string (with "-----CERTIFICATE-----" header)
   * representation of the provided {@link Certificate}.
   *
   * @param certificate The {@link Certificate} to encode.
   * @return A Base64-encoded string (with "-----CERTIFICATE-----" header)
   *         representation of the provided {@link Certificate}.
   * @throws CertificateEncodingException If an encoding error occurs.
   * @throws IllegalArgumentException If {@code certificate} is null.
   */
  public static String encodeCertificate(final Certificate certificate) throws CertificateEncodingException {
    return Type.CERTIFICATE.derToPem(certificate.getEncoded(), false);
  }

  /**
   * Returns a thumbprint of the provided Base64-encoded PEM {@code certificate}
   * with the specified {@link Hash} algorithm.
   *
   * @param certificate The Base64-encoded PEM certificate.
   * @param hash The {@link Hash} algorithm.
   * @return A thumbprint of the provided {@code certChain} with the specified
   *         {@link Hash} algorithm.
   * @throws IllegalArgumentException If {@code certChain} or {@code hash} is null.
   */
  public static byte[] generateThumbprint(final String certificate, final Hash hash) {
    return hash.encode(Type.CERTIFICATE.pemToDer(certificate));
  }

  /**
   * Returns a {@link PublicKey} from the provided {@code der} byte array.
   *
   * @param der The DER byte array.
   * @return A {@link PublicKey} from the provided {@code der} byte array.
   * @throws InvalidKeySpecException If an exception occurs generating the
   *           private key from the provided {@code der} byte array.
   * @throws IllegalArgumentException If {@code der} is null.
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
   * @throws IllegalArgumentException If {@code der} is null.
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
   * @throws IllegalArgumentException If {@code in} is null.
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
   * Returns a {@link X509Certificate} from the specified {@code byte[]}
   * DER-formatted certificate.
   *
   * @param der A {@code byte[]} DER-formatted certificate.
   * @return A {@link X509Certificate} from the specified {@link InputStream}
   *         providing a DER-formatted certificate.
   * @throws CertificateException If an exception occurs parsing the
   *           DER-formatted certificate from the provided {@link InputStream}.
   * @throws IllegalArgumentException If {@code in} is null.
   */
  public static X509Certificate decodeCertificate(final byte[] der) throws CertificateException {
    return decodeCertificate(new ByteArrayInputStream(der));
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
   * @throws IllegalArgumentException If {@code url} is null.
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