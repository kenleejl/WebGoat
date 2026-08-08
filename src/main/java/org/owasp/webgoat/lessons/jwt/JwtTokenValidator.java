/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt;

import com.auth0.jwt.JWT;
import java.security.SecureRandom;
import java.util.Base64;

public final class JwtTokenValidator {

  private JwtTokenValidator() {}

  public static boolean hasExpectedAlgorithm(String token, String expectedAlgorithm) {
    if (token == null) {
      return false;
    }
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3 || parts[2].isBlank()) {
      return false;
    }
    try {
      return expectedAlgorithm.equals(JWT.decode(token).getAlgorithm());
    } catch (RuntimeException ignored) {
      return false;
    }
  }

  public static String newHmacKey() {
    byte[] key = new byte[64];
    new SecureRandom().nextBytes(key);
    return Base64.getEncoder().encodeToString(key);
  }
}
