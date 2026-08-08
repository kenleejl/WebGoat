/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;

final class SameOriginPolicy {

  private SameOriginPolicy() {}

  static boolean allows(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null || host.isBlank()) {
      return false;
    }

    String source = request.getHeader("Origin");
    if (source == null || source.isBlank() || "null".equals(source)) {
      source = request.getHeader("Referer");
    }
    if (source == null || source.isBlank()) {
      return false;
    }

    try {
      String authority = URI.create(source).getRawAuthority();
      return authority != null && authority.equalsIgnoreCase(host);
    } catch (IllegalArgumentException ignored) {
      return false;
    }
  }
}
