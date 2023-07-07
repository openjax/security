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

package org.openjax.security.crypto;

import static java.nio.charset.StandardCharsets.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * An enum of common AES crypto functions.
 */
public enum AES {
  OPEN_SSL_256_CBC {
    @Override
    public byte[] encrypt(final byte[] data, final String password) {
      return encrypt(data, password, new SecureRandom().generateSeed(8));
    }

    @Override
    public byte[] encrypt(final byte[] data, final String password, final byte[] salt) {
      if (salt.length != 8)
        throw new IllegalArgumentException("salt.length (" + salt.length + ") must be equal to 8");

      final byte[] pass = password.getBytes(US_ASCII);

      byte[] hash = {};
      byte[] keyAndIv = {};
      for (int i = 0; i < 3 && keyAndIv.length < 48; ++i) { // [A]
        final byte[] hashPassSalt = new byte[hash.length + pass.length + 8];
        System.arraycopy(hash, 0, hashPassSalt, 0, hash.length);
        System.arraycopy(pass, 0, hashPassSalt, hash.length, pass.length);
        System.arraycopy(salt, 0, hashPassSalt, hash.length + pass.length, 8);
        hash = Hash.MD5.encode(hashPassSalt);
        keyAndIv = concat(keyAndIv, hash);
      }

      try {
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        final SecretKeySpec key = new SecretKeySpec(keyAndIv, 0, 32, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(keyAndIv, 32, 16));
        final byte[] encrypted = cipher.doFinal(data);
        return concat(MAGIC, salt, encrypted);
      }
      catch (final BadPaddingException | IllegalBlockSizeException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
        throw new RuntimeException("data: " + data + ", password: " + password + ", salt: " + salt, e);
      }
    }

    @Override
    public String decryptToString(final String encryptedBase64, final String password) {
      return new String(decrypt(encryptedBase64, password), ISO_8859_1);
    }

    @Override
    public String decryptToString(final byte[] encrypted, final String password) {
      return new String(decrypt(encrypted, password), ISO_8859_1);
    }

    @Override
    public byte[] decrypt(final String encryptedBase64, final String password) {
      return decrypt(Base64.getDecoder().decode(encryptedBase64.replaceAll("\\s", "")), password);
    }

    @Override
    public byte[] decrypt(final byte[] encrypted, final String password) {
      for (int i = 0, i$ = MAGIC.length; i < i$; ++i) // [A]
        if (MAGIC[i] != encrypted[i])
          throw new IllegalArgumentException("Bad magic number");

      final byte[] pass = password.getBytes(US_ASCII);

      byte[] hash = {};
      byte[] keyAndIv = {};
      for (int i = 0; i < 3 && keyAndIv.length < 48; ++i) { // [A]
        final byte[] hashPassSalt = new byte[hash.length + pass.length + 8];
        System.arraycopy(hash, 0, hashPassSalt, 0, hash.length);
        System.arraycopy(pass, 0, hashPassSalt, hash.length, pass.length);
        System.arraycopy(encrypted, MAGIC.length, hashPassSalt, hash.length + pass.length, 8);
        hash = Hash.MD5.encode(hashPassSalt);
        keyAndIv = concat(keyAndIv, hash);
      }

      try {
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        final SecretKeySpec key = new SecretKeySpec(keyAndIv, 0, 32, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(keyAndIv, 32, 16));
        return cipher.doFinal(encrypted, 16, encrypted.length - 16);
      }
      catch (final BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
        throw new RuntimeException("data: " + encrypted + ", password: " + password, e);
      }
    }
  };

  private static final byte[] MAGIC = "Salted__".getBytes(US_ASCII);

  private static byte[] concat(final byte[] a, final byte[] b) {
    final byte[] concat = new byte[a.length + b.length];
    System.arraycopy(a, 0, concat, 0, a.length);
    System.arraycopy(b, 0, concat, a.length, b.length);
    return concat;
  }

  private static byte[] concat(final byte[] a, final byte[] b, final byte[] c) {
    final byte[] concat = new byte[a.length + b.length + c.length];
    System.arraycopy(a, 0, concat, 0, a.length);
    System.arraycopy(b, 0, concat, a.length, b.length);
    System.arraycopy(c, 0, concat, a.length + b.length, c.length);
    return concat;
  }

  /**
   * Encrypt the specified {@code data} with the provided {@code password} and random SALT.
   *
   * @implNote This implementation reproduces the encryption mechanism of: {@code openssl enc -aes-256-cbc -p -k $password}
   * @param data The data to be encrypted.
   * @param password The password to be used for encryption.
   * @return The encrypted data.
   * @throws NullPointerException If {@code data} or {@code password} is null.
   */
  public abstract byte[] encrypt(byte[] data, String password);

  /**
   * Encrypt the specified {@code data} with the provided {@code password} and {@code salt}.
   *
   * @implNote This implementation reproduces the encryption mechanism of: {@code openssl enc -aes-256-cbc -p -k $password}
   * @param data The data to be encrypted.
   * @param password The password to be used for encryption.
   * @param salt The SALT (length must equal 8).
   * @return The encrypted data.
   * @throws NullPointerException If {@code data}, {@code password}, or {@code salt} is null.
   * @throws IllegalArgumentException If {@code salt.length != 8}.
   */
  public abstract byte[] encrypt(byte[] data, String password, byte[] salt);

  /**
   * Decrypt the specified Base-64 encoded data with the provided {@code password} and return as an ISO_8859_1-encoded string.
   *
   * @implNote This implementation reproduces the encryption mechanism of: {@code openssl aes-256-cbc -d -k $password}
   * @param encryptedBase64 The Base-64 encoded data to be decrypted.
   * @param password The password to be used for decryption.
   * @return The decrypted data.
   * @throws NullPointerException If {@code encryptedBase64} or {@code password} is null.
   */
  public abstract String decryptToString(String encryptedBase64, String password);

  /**
   * Decrypt the specified data with the provided {@code password} and return as an ISO_8859_1-encoded string.
   *
   * @implNote This implementation reproduces the encryption mechanism of: {@code openssl aes-256-cbc -d -k $password}
   * @param encrypted The data to be decrypted.
   * @param password The password to be used for decryption.
   * @return The decrypted data.
   * @throws NullPointerException If {@code encrypted} or {@code password} is null.
   */
  public abstract String decryptToString(byte[] encrypted, String password);

  /**
   * Decrypt the specified Base-64 encoded data with the provided {@code password}.
   *
   * @implNote This implementation reproduces the encryption mechanism of: {@code openssl aes-256-cbc -d -k $password}
   * @param encryptedBase64 The Base-64 encoded data to be decrypted.
   * @param password The password to be used for decryption.
   * @return The decrypted data.
   * @throws NullPointerException If {@code encryptedBase64} or {@code password} is null.
   */
  public abstract byte[] decrypt(String encryptedBase64, String password);

  /**
   * Decrypt the specified data with the provided {@code password}.
   *
   * @implNote This implementation reproduces the encryption mechanism of: {@code openssl aes-256-cbc -d -k $password}
   * @param encrypted The data to be decrypted.
   * @param password The password to be used for decryption.
   * @return The decrypted data.
   * @throws NullPointerException If {@code encrypted} or {@code password} is null.
   * @throws IllegalArgumentException If the magic number in the provided data is not equal to {@code "Salted__"}.
   */
  public abstract byte[] decrypt(byte[] encrypted, String password);
}