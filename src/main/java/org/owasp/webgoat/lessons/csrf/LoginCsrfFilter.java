/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Rejects browser authentication and registration requests submitted by another origin. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LoginCsrfFilter extends OncePerRequestFilter {

  private static final String LOGIN_PATH = "/login";
  private static final String REGISTER_PATH = "/register.mvc";

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if (hasOriginEvidence(request) && !SameOriginPolicy.allows(request)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN);
      return;
    }
    filterChain.doFilter(request, response);
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      return true;
    }
    String path = pathWithinApplication(request);
    return !LOGIN_PATH.equals(path) && !REGISTER_PATH.equals(path);
  }

  private boolean hasOriginEvidence(HttpServletRequest request) {
    return hasText(request.getHeader("Origin")) || hasText(request.getHeader("Referer"));
  }

  private boolean hasText(String value) {
    return value != null && !value.isBlank();
  }

  private String pathWithinApplication(HttpServletRequest request) {
    String path = request.getRequestURI();
    if (path == null) {
      return "";
    }
    String contextPath = request.getContextPath();
    if (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath)) {
      path = path.substring(contextPath.length());
    }
    int pathParameter = path.indexOf(';');
    return pathParameter == -1 ? path : path.substring(0, pathParameter);
  }
}
