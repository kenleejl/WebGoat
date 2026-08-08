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

/**
 * @author nbaars
 * @since 4/6/17.
 */
@RestController
@AssignmentHints({
  "client.side.filtering.free.hint1",
  "client.side.filtering.free.hint2",
  "client.side.filtering.free.hint3"
})
public class ClientSideFilteringFreeAssignment implements AssignmentEndpoint {
  /** Kept for source compatibility with the lesson tests; it is never accepted as an entitlement. */
  public static final String SUPER_COUPON_CODE = "disabled";

  @PostMapping("/clientSideFiltering/getItForFree")
  @ResponseBody
  public AttackResult completed(@RequestParam String checkoutCode) {
    // A static code shipped to the browser is not an entitlement. Discounts
    // must be tied to an authenticated account and validated in a server store.
    return failed(this).build();
  }
}
