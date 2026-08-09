/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.webwolfintroduction;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/** Maintains unpredictable, user- and flow-bound verification codes for the WebWolf lessons. */
@Component
public class UniqueCodes {

  public static final String MAIL = "mail";
  public static final String PASSWORD_RESET = "password-reset";

  private static final int CODE_LENGTH_IN_BYTES = 16;

  private final SecureRandom secureRandom = new SecureRandom();
  private final Map<String, String> codes = new ConcurrentHashMap<>();

  public String get(String username, String flow) {
    return codes.computeIfAbsent(key(username, flow), unused -> generate());
  }

  public boolean matches(String username, String flow, String code) {
    String expected = codes.get(key(username, flow));
    if (expected == null || code == null) {
      return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), code.getBytes(StandardCharsets.UTF_8));
  }

  private String key(String username, String flow) {
    return flow + ":" + username;
  }

  private String generate() {
    byte[] code = new byte[CODE_LENGTH_IN_BYTES];
    secureRandom.nextBytes(code);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(code);
  }
}
