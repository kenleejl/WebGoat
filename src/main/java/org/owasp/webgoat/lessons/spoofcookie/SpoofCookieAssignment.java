/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.informationMessage;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.UnsatisfiedServletRequestParameterException;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

@AssignmentHints({"spoofcookie.hint1", "spoofcookie.hint2", "spoofcookie.hint3"})
@RestController
public class SpoofCookieAssignment implements AssignmentEndpoint {

  private static final String COOKIE_NAME = "spoof_auth";
  private static final String ATTACK_USERNAME = "tom";
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private static final Map<String, String> users =
      Map.of("webgoat", "webgoat", "admin", "admin", ATTACK_USERNAME, "apasswordfortom");
  private final Map<String, String> authenticatedSessions = new ConcurrentHashMap<>();

  @PostMapping(path = "/SpoofCookie/login")
  @ResponseBody
  @ExceptionHandler(UnsatisfiedServletRequestParameterException.class)
  public AttackResult login(
      @RequestParam String username,
      @RequestParam String password,
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      HttpServletResponse response) {

    if (StringUtils.isEmpty(cookieValue)) {
      return credentialsLoginFlow(username, password, response);
    } else {
      return cookieLoginFlow(cookieValue);
    }
  }

  @GetMapping(path = "/SpoofCookie/cleanup")
  public void cleanup(
      @CookieValue(value = COOKIE_NAME, required = false) String cookieValue,
      HttpServletResponse response) {
    if (cookieValue != null) {
      authenticatedSessions.remove(cookieValue);
    }
    Cookie cookie = new Cookie(COOKIE_NAME, "");
    cookie.setMaxAge(0);
    cookie.setPath("/WebGoat");
    response.addCookie(cookie);
  }

  private AttackResult credentialsLoginFlow(
      String username, String password, HttpServletResponse response) {
    String lowerCasedUsername = username.toLowerCase();
    if (ATTACK_USERNAME.equals(lowerCasedUsername)
        && users.get(lowerCasedUsername).equals(password)) {
      return informationMessage(this).feedback("spoofcookie.cheating").build();
    }

    String authPassword = users.getOrDefault(lowerCasedUsername, "");
    if (!authPassword.isBlank() && authPassword.equals(password)) {
      byte[] sessionBytes = new byte[32];
      SECURE_RANDOM.nextBytes(sessionBytes);
      String newCookieValue =
          Base64.getUrlEncoder().withoutPadding().encodeToString(sessionBytes);
      authenticatedSessions.put(newCookieValue, lowerCasedUsername);
      Cookie newCookie = new Cookie(COOKIE_NAME, newCookieValue);
      newCookie.setPath("/WebGoat");
      newCookie.setSecure(true);
      newCookie.setHttpOnly(true);
      newCookie.setAttribute("SameSite", "Strict");
      response.addCookie(newCookie);
      return informationMessage(this).feedback("spoofcookie.login").build();
    }

    return informationMessage(this).feedback("spoofcookie.wrong-login").build();
  }

  private AttackResult cookieLoginFlow(String cookieValue) {
    String cookieUsername = authenticatedSessions.get(cookieValue);
    if (cookieUsername != null && users.containsKey(cookieUsername)) {
      return informationMessage(this).feedback("spoofcookie.cookie-login").build();
    }

    return failed(this).feedback("spoofcookie.wrong-cookie").build();
  }
}
