#include "test.h"

/* The server reflects the peer's spin; the client inverts it. */
static void test_spin_roles(void) {
  CHECK(spin_outgoing(1, 0) == 0); /* server reflects 0 */
  CHECK(spin_outgoing(1, 1) == 1); /* server reflects 1 */
  CHECK(spin_outgoing(0, 0) == 1); /* client inverts 0 */
  CHECK(spin_outgoing(0, 1) == 0); /* client inverts 1 */
}

/* The spin bit reads back from and writes into a short-header first byte. */
static void test_spin_byte(void) {
  u8 b = 0x40; /* short header fixed bit, spin clear */
  CHECK(spin_get(b) == 0);
  u8 set = spin_set(b, 1);
  CHECK(spin_get(set) == 1 && (set & 0x40) == 0x40); /* other bits kept */
  CHECK(spin_get(spin_set(set, 0)) == 0);
}

/* A client-server exchange flips the bit once per round trip. */
static void test_spin_cycle(void) {
  int spin       = 0;                            /* start of round */
  int client_out = spin_outgoing(0, spin);       /* client inverts -> 1 */
  int server_out = spin_outgoing(1, client_out); /* server reflects -> 1 */
  int next       = spin_outgoing(0, server_out); /* client inverts -> 0 */
  CHECK(client_out == 1 && server_out == 1 && next == 0); /* back to start */
}

/* spin_outgoing_ex matches spin_outgoing when not disabled, and
 * always sends 0 when disabled. */
static void test_spin_outgoing_ex(void) {
  CHECK(spin_outgoing_ex(1, 0, 0) == spin_outgoing(1, 0));
  CHECK(spin_outgoing_ex(1, 1, 0) == spin_outgoing(1, 1));
  CHECK(spin_outgoing_ex(0, 0, 0) == spin_outgoing(0, 0));
  CHECK(spin_outgoing_ex(1, 1, 1) == 0); /* disabled: always 0 */
  CHECK(spin_outgoing_ex(0, 1, 1) == 0); /* disabled: always 0 */
}

/* Exactly 1/16 of the byte value space selects disablement. */
static void test_spin_disabled_selects_one_in_16(void) {
  int count = 0;
  for (int v = 0; v < 256; v++)
    if (spin_disabled((u8)v)) count++;
  CHECK(count == 16); /* 256/16 */
}

/* RFC 9000 17.4: each endpoint independently disables spinning for a random
 * 1/16 of its own connections/paths (the MUST value this SDK implements);
 * the RFC states this "ensures that the spin bit signal is disabled on
 * approximately one in eight network paths" combining both independent
 * draws. The exact combined rate is 1 - (15/16)^2 = 31/256 ~= 12.11%, just
 * under the nominal 1/8 (12.5%) -- consistent with the RFC's own wording of
 * "approximately", not "at least" (that stronger phrasing is RFC 9312
 * 3.8.2's own paraphrase of this RFC 9000 mechanism, not an independent
 * requirement this SDK derives a different value for). This test pins that
 * combined rate to the hand-computed 31/256 exactly, rather than asserting
 * an "at least 1/8" bound the RFC's own math does not actually reach. */
static void test_spin_disabled_combined_rate_matches_rfc9000_math(void) {
  int client_disabled = 0, either_disabled = 0;
  for (int c = 0; c < 256; c++)
    for (int s = 0; s < 256; s++) {
      int cd = spin_disabled((u8)c);
      int sd = spin_disabled((u8)s);
      if (cd) client_disabled++;
      if (cd || sd) either_disabled++;
    }
  CHECK(client_disabled == 16 * 256); /* 1/16 of the client's own draws */
  /* 1 - (15/16)^2 over 256*256 draws = (256*256 - 240*240) = 31*256. */
  CHECK(either_disabled == 31 * 256);
}

void test_spin(void) {
  test_spin_roles();
  test_spin_byte();
  test_spin_cycle();
  test_spin_outgoing_ex();
  test_spin_disabled_selects_one_in_16();
  test_spin_disabled_combined_rate_matches_rfc9000_math();
}
