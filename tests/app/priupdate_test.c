#include "app/http3/core/h3/priupdate.h"

#include "common/bytes/util/bytes.h"
#include "test.h"

/* PRIORITY_UPDATE round-trip (RFC 9218 7.1): request variant 0x0F0700,
 * element id and field value recovered exactly; the push variant carries
 * its own type. */
static void test_priupdate_roundtrip(void) {
  u8              buf[64];
  h3_priupdate    out  = {0};
  static const u8 fv[] = {'u', '=', '1', ',', ' ', 'i'};
  usz             n    = h3_priupdate_put(
      buf, sizeof buf, &(h3_priupdate){0, 4, wired_span_of(fv, 6)});
  CHECK(n > 0);
  CHECK(h3_priupdate_get(wired_span_of(buf, n), &out) == n);
  CHECK(out.push == 0 && out.element_id == 4);
  CHECK(out.value.n == 6 && out.value.p[0] == 'u' && out.value.p[5] == 'i');
  n = h3_priupdate_put(
      buf, sizeof buf, &(h3_priupdate){1, 2, wired_span_of(fv, 6)});
  CHECK(n > 0);
  CHECK(h3_priupdate_get(wired_span_of(buf, n), &out) == n);
  CHECK(out.push == 1 && out.element_id == 2);
}

/* Truncated or wrong-type input decodes to nothing. */
static void test_priupdate_rejects_malformed(void) {
  u8           buf[64];
  h3_priupdate out = {0};
  usz          n   = h3_priupdate_put(
      buf, sizeof buf, &(h3_priupdate){0, 4, wired_span_of(0, 0)});
  CHECK(n > 0);
  CHECK(h3_priupdate_get(wired_span_of(buf, n - 1), &out) == 0);
  buf[0] = 0x01; /* not a PRIORITY_UPDATE type */
  CHECK(h3_priupdate_get(wired_span_of(buf, n), &out) == 0);
}

/* The Priority Field Value dictionary (RFC 9218 4/5, RFC 8941 shape):
 * u=N picks the urgency, bare i (or i=?1) sets incremental, junk and
 * unknown keys fall back to the defaults (u=3, i=0). */
static void test_priupdate_sfv_parse(void) {
  h3_priority p;
  h3_priority_sfv(wired_span_of((const u8*)"u=1, i", 6), &p);
  CHECK(p.urgency == 1 && p.incremental == 1);
  h3_priority_sfv(wired_span_of((const u8*)"u=7", 3), &p);
  CHECK(p.urgency == 7 && p.incremental == 0);
  h3_priority_sfv(wired_span_of((const u8*)"i=?1", 4), &p);
  CHECK(p.urgency == 3 && p.incremental == 1);
  h3_priority_sfv(wired_span_of((const u8*)"i=?0, u=0", 9), &p);
  CHECK(p.urgency == 0 && p.incremental == 0);
  /* out-of-range urgency and junk keep the defaults */
  h3_priority_sfv(wired_span_of((const u8*)"u=9", 3), &p);
  CHECK(p.urgency == 3);
  h3_priority_sfv(wired_span_of((const u8*)"x=2,junk", 8), &p);
  CHECK(p.urgency == 3 && p.incremental == 0);
  h3_priority_sfv(wired_span_of(0, 0), &p);
  CHECK(p.urgency == 3 && p.incremental == 0);
}

/* Parse s (NUL-terminated) as a Priority Field Value; 1 iff the result is
 * urgency u, incremental i. */
static int sfv_is(const char* s, u8 u, u8 i) {
  h3_priority p = {0, 0};
  h3_priority_sfv(wired_span_of((const u8*)s, wired_cstr_len(s)), &p);
  return p.urgency == u && p.incremental == i;
}

/* 9218-002/-003 (RFC 8941 3.2 Dictionary): a value of the wrong type or out
 * of range is ignored (that key keeps its default), parameters and unknown
 * members of every item type are skipped, and the last duplicate wins. */
static void test_priupdate_sfv_dictionary_types(void) {
  CHECK(sfv_is("u=10", 3, 0));      /* integer out of 0..7 */
  CHECK(sfv_is("u=1.5", 3, 0));     /* decimal, not integer */
  CHECK(sfv_is("u=-1", 3, 0));      /* negative */
  CHECK(sfv_is("u=\"1\"", 3, 0));   /* string */
  CHECK(sfv_is("u=?1, i=1", 3, 0)); /* boolean u, integer i */
  CHECK(sfv_is("u=0, i=?0", 0, 0));
  CHECK(sfv_is(" u=2 ", 2, 0)); /* field-level SP around the value */
  CHECK(sfv_is("u=2;x=1, foo=(a \"b\" 1.5);q, i", 2, 1));
  CHECK(sfv_is("x=*tok/en:1, y=:aGk=:, z=(), i;p=?0, u=4", 4, 1));
  CHECK(sfv_is("u=1, u=5", 5, 0)); /* last duplicate wins */
  CHECK(sfv_is("u=1, u=x", 3, 0)); /* ...even an ignored one */
  CHECK(sfv_is("u=7,i", 7, 1));
}

/* 9218-009: a Priority Field Value that is not a valid Dictionary falls back
 * to the defaults as a whole, even when it carries a good u= / i member. */
static void test_priupdate_sfv_parse_failure_defaults(void) {
  static const char* const bad[] = {
      "u=1,",                  /* trailing comma */
      "u=1 i",                 /* members not comma-separated */
      "U=1, i",                /* key must start lcalpha or '*' */
      "u=1;, i",               /* parameter without a key */
      "i, u=\"ab",             /* unterminated string */
      "i, u=\"a\\q\"",         /* bad string escape */
      "i, x=(a b",             /* unterminated inner list */
      "i, x=(a,b)",            /* inner-list items need SP */
      "i, x=1234567890123456", /* integer longer than 15 digits */
      "i, x=1234567890123.1",  /* decimal integer part past 12 */
      "i, x=1.2345",           /* decimal fraction past 3 digits */
      "i, x=1.",               /* decimal with no fraction */
      "i, x=?2",               /* boolean not ?0 / ?1 */
      "i, x=:a!:",             /* byte sequence outside base64 */
      "i, x=:aGk=",            /* unterminated byte sequence */
      "i, x=@1",               /* no bare item starts with '@' */
      "i, x=",                 /* missing value */
      "i, u=1, ",              /* trailing comma then SP */
  };
  for (usz k = 0; k < sizeof bad / sizeof *bad; k++) {
    CHECK(sfv_is(bad[k], 3, 0));
  }
}

void test_priupdate(void) {
  test_priupdate_sfv_dictionary_types();
  test_priupdate_sfv_parse_failure_defaults();
  test_priupdate_roundtrip();
  test_priupdate_rejects_malformed();
  test_priupdate_sfv_parse();
}
