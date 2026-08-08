/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.htmltampering;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"hint1", "hint2", "hint3"})
public class HtmlTamperingTask implements AssignmentEndpoint {

  @PostMapping("/HtmlTampering/task")
  @ResponseBody
  public AttackResult completed(@RequestParam String QTY, @RequestParam String Total) {
    try {
      int quantity = Integer.parseInt(QTY);
      if (quantity < 1 || quantity > 100) {
        return failed(this).feedback("html-tampering.tamper.failure").build();
      }
    } catch (NumberFormatException ignored) {
      return failed(this).feedback("html-tampering.tamper.failure").build();
    }
    // Prices are calculated by the server; a client-submitted total is never an
    // authorization signal for a discounted purchase.
    return failed(this).feedback("html-tampering.tamper.failure").build();
  }
}
