package org.lib4j.security;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public enum Hmac {
  HmacSHA1("HmacSHA1"),
  HmacSHA256("HmacSHA256"),
  HmacSHA512("HmacSHA512");

  private final ThreadLocal<Mac> mac;

  private Hmac(final String algorithm) {
    this.mac = new ThreadLocal<>() {
      @Override
      protected Mac initialValue() {
        try {
          return Mac.getInstance(algorithm);
        }
        catch (final NoSuchAlgorithmException e) {
          throw new UnsupportedOperationException(e);
        }
      }
    };
  }

  /**
   * Generate the Hashed Message Authentication Code for the given {@code key}
   * and {@code data}.
   * <p>
   * This method uses JCE to provide the crypto algorithm.
   *
   * @param key The HMAC key.
   * @param data The text to be authenticated.
   * @return The Hashed Message Authentication Code.
   * @throws IllegalArgumentException If {@code key} is invalid.
   */
  public byte[] generate(final byte[] key, final byte[] data) {
    try {
      final SecretKeySpec secretKey = new SecretKeySpec(key, "RAW");
      mac.get().init(secretKey);
      return mac.get().doFinal(data);
    }
    catch (final InvalidKeyException e) {
      throw new IllegalArgumentException(e);
    }
  }
}