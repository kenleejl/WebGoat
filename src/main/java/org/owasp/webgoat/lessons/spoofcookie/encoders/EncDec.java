/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

public class EncDec {

  private static final byte[] SIGNING_KEY = createSigningKey();

  private EncDec() {}

  public static String encode(final String value) {
    if (value == null) {
      return null;
    }

    String subject =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(value.toLowerCase().getBytes(StandardCharsets.UTF_8));
    return subject + "." + sign(subject);
  }

  public static String decode(final String encodedValue) throws IllegalArgumentException {
    if (encodedValue == null) {
      return null;
    }

    String[] parts = encodedValue.split("\\.", -1);
    if (parts.length != 2
        || !MessageDigest.isEqual(
            sign(parts[0]).getBytes(StandardCharsets.US_ASCII),
            parts[1].getBytes(StandardCharsets.US_ASCII))) {
      throw new IllegalArgumentException("Invalid authentication cookie");
    }
    return new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
  }

  private static String sign(String value) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(SIGNING_KEY, "HmacSHA256"));
      return Base64.getUrlEncoder()
          .withoutPadding()
          .encodeToString(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    } catch (Exception e) {
      throw new IllegalStateException("Unable to sign authentication cookie", e);
    }
  }

  private static byte[] createSigningKey() {
    byte[] key = new byte[32];
    new SecureRandom().nextBytes(key);
    return key;
  }
}
