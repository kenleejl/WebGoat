/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.spoofcookie.encoders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/***
 *
 * @author Angel Olle Blazquez
 *
 */

class EncDecTest {

  @Test
  @DisplayName("Signed cookies round trip")
  void signedCookieRoundTrip() {
    String encoded = EncDec.encode("webgoat");

    assertThat(encoded).contains(".");
    assertThat(EncDec.decode(encoded)).isEqualTo("webgoat");
  }

  @Test
  @DisplayName("Tampered cookies are rejected")
  void tamperedCookieIsRejected() {
    String encoded = EncDec.encode("tom");
    String tampered = encoded.substring(0, encoded.indexOf('.') + 1) + "A";

    assertThatThrownBy(() -> EncDec.decode(tampered))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Invalid authentication cookie");
  }

  @Test
  @DisplayName("null encode test")
  void testNullEncode() {
    assertThat(EncDec.encode(null)).isNull();
  }

  @Test
  @DisplayName("null decode test")
  void testNullDecode() {
    assertThat(EncDec.decode(null)).isNull();
  }
}
