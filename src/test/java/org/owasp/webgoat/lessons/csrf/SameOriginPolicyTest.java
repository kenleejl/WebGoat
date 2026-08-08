/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class SameOriginPolicyTest {

  @Test
  void acceptsMatchingOrigin() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Host", "localhost:8080");
    request.addHeader("Origin", "http://localhost:8080");

    assertThat(SameOriginPolicy.allows(request)).isTrue();
  }

  @Test
  void acceptsMatchingRefererWhenOriginIsAbsent() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Host", "localhost:8080");
    request.addHeader("Referer", "http://localhost:8080/WebGoat/start.mvc");

    assertThat(SameOriginPolicy.allows(request)).isTrue();
  }

  @Test
  void rejectsCrossOriginRequests() {
    MockHttpServletRequest request = new MockHttpServletRequest();
    request.addHeader("Host", "localhost:8080");
    request.addHeader("Origin", "https://attacker.example");

    assertThat(SameOriginPolicy.allows(request)).isFalse();
  }
}
