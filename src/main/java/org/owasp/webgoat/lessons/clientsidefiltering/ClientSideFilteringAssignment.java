/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.clientsidefiltering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "ClientSideFilteringHint1",
  "ClientSideFilteringHint2",
  "ClientSideFilteringHint3",
  "ClientSideFilteringHint4"
})
public class ClientSideFilteringAssignment implements AssignmentEndpoint {

  @PostMapping("/clientSideFiltering/attack1")
  @ResponseBody
  public AttackResult completed(@RequestParam String answer) {
    // Knowledge of a confidential value is not proof of authorization.  Never turn the former
    // client-side disclosure into an authorization success on the server.
    return failed(this).feedback("ClientSideFiltering.incorrect").build();
  }
}
