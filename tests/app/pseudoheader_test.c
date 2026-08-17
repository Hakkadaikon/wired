#include "test.h"

#define NAME(s) ((const u8*)(s)), (sizeof(s) - 1)

/* Classification of pseudo, regular, and unknown names. */
static void test_ph_classify(void) {
  CHECK(h3_ph_classify(NAME(":method")) == H3_PH_METHOD);
  CHECK(h3_ph_classify(NAME(":status")) == H3_PH_STATUS);
  CHECK(h3_ph_classify(NAME("content-type")) == H3_PH_NONE);
  CHECK(h3_ph_classify(NAME(":bogus")) == H3_PH_UNKNOWN);
  /* a prefix of a known name must not match */
  CHECK(h3_ph_classify(NAME(":pat")) == H3_PH_UNKNOWN);
  CHECK(h3_ph_classify(NAME(":")) == H3_PH_UNKNOWN);
}

/* A complete, well-ordered request is valid. */
static void test_ph_request_ok(void) {
  h3_ph_set p;
  h3_ph_init(&p);
  h3_ph_field(&p, NAME(":method"));
  h3_ph_field(&p, NAME(":scheme"));
  h3_ph_field(&p, NAME(":authority"));
  h3_ph_field(&p, NAME(":path"));
  h3_ph_field(&p, NAME("user-agent"));
  CHECK(h3_ph_request_ok(&p) == 1);
  CHECK(h3_ph_response_ok(&p) == 0); /* no :status */
}

/* Missing a required pseudo-header makes the request malformed. */
static void test_ph_request_missing(void) {
  h3_ph_set p;
  h3_ph_init(&p);
  h3_ph_field(&p, NAME(":method"));
  h3_ph_field(&p, NAME(":scheme"));
  CHECK(h3_ph_request_ok(&p) == 0); /* no :path */
}

/* A pseudo-header after a regular field is malformed. */
static void test_ph_order(void) {
  h3_ph_set p;
  h3_ph_init(&p);
  h3_ph_field(&p, NAME(":method"));
  h3_ph_field(&p, NAME("accept"));
  h3_ph_field(&p, NAME(":scheme")); /* pseudo after regular */
  h3_ph_field(&p, NAME(":path"));
  CHECK(p.ok == 0);
  CHECK(h3_ph_request_ok(&p) == 0);
}

/* A duplicate pseudo-header is malformed. */
static void test_ph_duplicate(void) {
  h3_ph_set p;
  h3_ph_init(&p);
  h3_ph_field(&p, NAME(":method"));
  h3_ph_field(&p, NAME(":method"));
  CHECK(p.ok == 0);
}

/* An unknown pseudo-header is malformed. */
static void test_ph_unknown(void) {
  h3_ph_set p;
  h3_ph_init(&p);
  h3_ph_field(&p, NAME(":bogus"));
  CHECK(p.ok == 0);
}

/* RFC 9220 3: :protocol is a known pseudo-header (Extended CONNECT). */
static void test_ph_classify_protocol(void) {
  CHECK(h3_ph_classify(NAME(":protocol")) == H3_PH_PROTOCOL);
}

/* A response needs only :status. */
static void test_ph_response_ok(void) {
  h3_ph_set p;
  h3_ph_init(&p);
  h3_ph_field(&p, NAME(":status"));
  h3_ph_field(&p, NAME("content-length"));
  CHECK(h3_ph_response_ok(&p) == 1);
  CHECK(h3_ph_request_ok(&p) == 0);
}

void test_pseudoheader(void) {
  test_ph_classify();
  test_ph_request_ok();
  test_ph_request_missing();
  test_ph_order();
  test_ph_duplicate();
  test_ph_unknown();
  test_ph_response_ok();
  test_ph_classify_protocol();
}
