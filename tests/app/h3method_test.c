#include "test.h"

#define METHOD(s) quic_span_of((const u8*)(s), sizeof(s) - 1)

/* RFC 9110 9.1: every registered method (plus RFC 5789 PATCH) is known. */
static void test_h3method_known_methods(void) {
  CHECK(quic_h3_method_is_known(METHOD("GET")) == 1);
  CHECK(quic_h3_method_is_known(METHOD("HEAD")) == 1);
  CHECK(quic_h3_method_is_known(METHOD("POST")) == 1);
  CHECK(quic_h3_method_is_known(METHOD("PUT")) == 1);
  CHECK(quic_h3_method_is_known(METHOD("DELETE")) == 1);
  CHECK(quic_h3_method_is_known(METHOD("CONNECT")) == 1);
  CHECK(quic_h3_method_is_known(METHOD("OPTIONS")) == 1);
  CHECK(quic_h3_method_is_known(METHOD("TRACE")) == 1);
  CHECK(quic_h3_method_is_known(METHOD("PATCH")) == 1);
}

/* RFC 9110 9.1 (9110-017): an unrecognized method token is not known --
 * the condition the server's 501 path gates on. */
static void test_h3method_unknown_method(void) {
  CHECK(quic_h3_method_is_known(METHOD("FOOBAR")) == 0);
  CHECK(quic_h3_method_is_known(METHOD("")) == 0);
}

/* RFC 9110 9.1: method tokens are case-sensitive -- a lowercase spelling of a
 * known method is itself unknown. */
static void test_h3method_case_sensitive(void) {
  CHECK(quic_h3_method_is_known(METHOD("get")) == 0);
}

/* Boundary: a prefix or superset of a known name does not match. */
static void test_h3method_no_partial_match(void) {
  CHECK(quic_h3_method_is_known(METHOD("GE")) == 0);
  CHECK(quic_h3_method_is_known(METHOD("GETX")) == 0);
}

/* RFC 9110 9.1 (9110-018): the server-wide allow set (GET/HEAD/POST/PUT/
 * DELETE/OPTIONS/PATCH/CONNECT) accepts a request into the application
 * handler. CONNECT is allowed because a plain (non-Extended) CONNECT already
 * falls through to the application handler as pre-existing, separately
 * tested srvrun behavior (test_srvrun_plain_connect_no_protocol_no_wt_session
 * in srvrun_test.c) that this gate must not change. */
static void test_h3method_allowed_methods(void) {
  CHECK(quic_h3_method_is_allowed(METHOD("GET")) == 1);
  CHECK(quic_h3_method_is_allowed(METHOD("HEAD")) == 1);
  CHECK(quic_h3_method_is_allowed(METHOD("POST")) == 1);
  CHECK(quic_h3_method_is_allowed(METHOD("PUT")) == 1);
  CHECK(quic_h3_method_is_allowed(METHOD("DELETE")) == 1);
  CHECK(quic_h3_method_is_allowed(METHOD("OPTIONS")) == 1);
  CHECK(quic_h3_method_is_allowed(METHOD("PATCH")) == 1);
  CHECK(quic_h3_method_is_allowed(METHOD("CONNECT")) == 1);
}

/* RFC 9110 9.1 (9110-018): TRACE is recognized (RFC 9110 9.3.8) but this
 * server does not implement it -- the 405 case. An unknown method is also
 * not allowed (it is a 501, not a 405). */
static void test_h3method_recognized_not_allowed(void) {
  CHECK(quic_h3_method_is_allowed(METHOD("TRACE")) == 0);
  CHECK(quic_h3_method_is_allowed(METHOD("FOOBAR")) == 0);
}

void test_h3method(void) {
  test_h3method_known_methods();
  test_h3method_unknown_method();
  test_h3method_case_sensitive();
  test_h3method_no_partial_match();
  test_h3method_allowed_methods();
  test_h3method_recognized_not_allowed();
}
