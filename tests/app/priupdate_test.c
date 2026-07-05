#include "app/http3/core/h3/priupdate.h"

#include "test.h"

/* PRIORITY_UPDATE round-trip (RFC 9218 7.1): request variant 0x0F0700,
 * element id and field value recovered exactly; the push variant carries
 * its own type. */
static void test_priupdate_roundtrip(void) {
  u8                buf[64];
  quic_h3_priupdate out  = {0};
  static const u8   fv[] = {'u', '=', '1', ',', ' ', 'i'};
  usz               n    = quic_h3_priupdate_put(
      buf, sizeof buf, &(quic_h3_priupdate){0, 4, quic_span_of(fv, 6)});
  CHECK(n > 0);
  CHECK(quic_h3_priupdate_get(quic_span_of(buf, n), &out) == n);
  CHECK(out.push == 0 && out.element_id == 4);
  CHECK(out.value.n == 6 && out.value.p[0] == 'u' && out.value.p[5] == 'i');
  n = quic_h3_priupdate_put(
      buf, sizeof buf, &(quic_h3_priupdate){1, 2, quic_span_of(fv, 6)});
  CHECK(n > 0);
  CHECK(quic_h3_priupdate_get(quic_span_of(buf, n), &out) == n);
  CHECK(out.push == 1 && out.element_id == 2);
}

/* Truncated or wrong-type input decodes to nothing. */
static void test_priupdate_rejects_malformed(void) {
  u8                buf[64];
  quic_h3_priupdate out = {0};
  usz               n   = quic_h3_priupdate_put(
      buf, sizeof buf, &(quic_h3_priupdate){0, 4, quic_span_of(0, 0)});
  CHECK(n > 0);
  CHECK(quic_h3_priupdate_get(quic_span_of(buf, n - 1), &out) == 0);
  buf[0] = 0x01; /* not a PRIORITY_UPDATE type */
  CHECK(quic_h3_priupdate_get(quic_span_of(buf, n), &out) == 0);
}

/* The Priority Field Value dictionary (RFC 9218 4/5, RFC 8941 shape):
 * u=N picks the urgency, bare i (or i=?1) sets incremental, junk and
 * unknown keys fall back to the defaults (u=3, i=0). */
static void test_priupdate_sfv_parse(void) {
  quic_h3_priority p;
  quic_h3_priority_sfv(quic_span_of((const u8*)"u=1, i", 6), &p);
  CHECK(p.urgency == 1 && p.incremental == 1);
  quic_h3_priority_sfv(quic_span_of((const u8*)"u=7", 3), &p);
  CHECK(p.urgency == 7 && p.incremental == 0);
  quic_h3_priority_sfv(quic_span_of((const u8*)"i=?1", 4), &p);
  CHECK(p.urgency == 3 && p.incremental == 1);
  quic_h3_priority_sfv(quic_span_of((const u8*)"i=?0, u=0", 9), &p);
  CHECK(p.urgency == 0 && p.incremental == 0);
  /* out-of-range urgency and junk keep the defaults */
  quic_h3_priority_sfv(quic_span_of((const u8*)"u=9", 3), &p);
  CHECK(p.urgency == 3);
  quic_h3_priority_sfv(quic_span_of((const u8*)"x=2,junk", 8), &p);
  CHECK(p.urgency == 3 && p.incremental == 0);
  quic_h3_priority_sfv(quic_span_of(0, 0), &p);
  CHECK(p.urgency == 3 && p.incremental == 0);
}

void test_priupdate(void) {
  test_priupdate_roundtrip();
  test_priupdate_rejects_malformed();
  test_priupdate_sfv_parse();
}
