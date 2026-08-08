/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.jwt.claimmisuse;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import org.apache.commons.lang3.StringUtils;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/JWT/")
@RestController
@AssignmentHints({
  "jwt-jku-hint1",
  "jwt-jku-hint2",
  "jwt-jku-hint3",
  "jwt-jku-hint4",
  "jwt-jku-hint5"
})
public class JWTHeaderJKUEndpoint implements AssignmentEndpoint {

  @PostMapping("jku/follow/{user}")
  public @ResponseBody String follow(@PathVariable("user") String user) {
    if ("Jerry".equals(user)) {
      return "Following yourself seems redundant";
    } else {
      return "You are now following Tom";
    }
  }

  @PostMapping("jku/delete")
  public @ResponseBody AttackResult resetVotes(@RequestParam("token") String token) {
    if (StringUtils.isEmpty(token)) {
      return failed(this).feedback("jwt-invalid-token").build();
    }
    // Never resolve a verification key from a URL controlled by the token.
    return failed(this).feedback("jwt-invalid-token").build();
  }
}
