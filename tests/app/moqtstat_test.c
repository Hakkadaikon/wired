#include "app/moqt/tstat/moqtstat.h"

#include "moqt_golden.h"
#include "test.h"

/* draft-ietf-moq-transport-19 TRACK_STATUS (10.14), TRACK_STATUS_OK
 * (REQUEST_OK, 10.5) and REQUEST_UPDATE (10.9). Wire bytes for the round
 * trips come from tests/app/moqt_golden.h. */

/* Frames a golden message with moqctl_peek_type and returns its body. */
static wired_span moqtstat_t_body(const u8* msg, usz n, u64 want_type) {
  usz        off  = 0;
  u64        type = 0;
  wired_span body = wired_span_of(msg, 0);
  int        r    = moqctl_peek_type(wired_span_of(msg, n), &off, &type, &body);
  CHECK(r == MOQCTL_OK || r == MOQCTL_KNOWN_UNIMPLEMENTED);
  CHECK(type == want_type);
  CHECK(off == n);
  return body;
}

static void moqtstat_t_same(const u8* out, usz n, wired_span want) {
  CHECK(n == want.n);
  for (usz i = 0; i < n && i < want.n; i++) CHECK(out[i] == want.p[i]);
}

static void test_moqtstat_golden(void) {
  wired_span body = moqtstat_t_body(
      g_moqt_ctl_track_status_basic, G_MOQT_CTL_TRACK_STATUS_BASIC_LEN,
      MOQTSTAT_T_TRACK_STATUS);
  moqctl_subscribe m;
  u8               out[MOQCTL_MAX_MSG_LEN];
  usz              n = 0;
  if (moqtstat_take(body, &m) != MOQCTL_OK) {
    CHECK(0);
    return;
  }
  CHECK(m.request_id == 10);
  CHECK(m.name.ns.n == 2);
  CHECK(m.name.name.n == 5);
  CHECK(m.name.name.p[0] == 'a');
  CHECK(m.params.n == 0);
  CHECK(moqctl_subscribe_encode(wired_mspan_of(out, sizeof out), &n, &m));
  moqtstat_t_same(out, n, body);
}

/* 10.14: delivery parameters such as SUBSCRIBER_PRIORITY are not part of
 * TRACK_STATUS; AUTHORIZATION_TOKEN is (10.2.2). */
static void test_moqtstat_param_scope(void) {
  static const u8  prio[] = {0x00, 0x01, 0x01, 'a', 0x00, 0x01, 0x20, 0x05};
  static const u8  auth[] = {0x00, 0x01, 0x01, 'a',  0x00,
                             0x01, 0x03, 0x02, 0x03, 0x00};
  moqctl_subscribe m;
  CHECK(
      moqtstat_take(wired_span_of(prio, sizeof prio), &m) == MOQCTL_VIOLATION);
  CHECK(moqtstat_take(wired_span_of(auth, sizeof auth), &m) == MOQCTL_OK);
  CHECK(m.params.n == 1);
}

static void test_moqtstat_length_mismatch(void) {
  const u8*        b = g_moqt_ctl_track_status_basic + 3;
  usz              n = G_MOQT_CTL_TRACK_STATUS_BASIC_MSG_LEN;
  u8               extra[G_MOQT_CTL_TRACK_STATUS_BASIC_MSG_LEN + 1];
  moqctl_subscribe m;
  for (usz cut = 0; cut < n; cut++)
    CHECK(moqtstat_take(wired_span_of(b, cut), &m) == MOQCTL_VIOLATION);
  for (usz i = 0; i < n; i++) extra[i] = b[i];
  extra[n] = 0;
  CHECK(moqtstat_take(wired_span_of(extra, n + 1), &m) == MOQCTL_VIOLATION);
}

static void test_moqtstat_ok_golden(void) {
  wired_span body = moqtstat_t_body(
      g_moqt_ctl_track_status_ok_basic, G_MOQT_CTL_TRACK_STATUS_OK_BASIC_LEN,
      MOQCTL_T_REQUEST_OK);
  moqctl_request_ok   m;
  const moqctl_param* p;
  u8                  out[MOQCTL_MAX_MSG_LEN];
  usz                 n = 0;
  if (moqtstat_ok_take(body, &m) != MOQCTL_OK) {
    CHECK(0);
    return;
  }
  p = moqctl_params_find(&m.params, MOQCTL_PARAM_LARGEST_OBJECT);
  CHECK(p != 0);
  if (p) CHECK(p->loc.group == 2 && p->loc.object == 5);
  CHECK(m.track_properties.n == 2);
  CHECK(m.track_properties.p[0] == 0x0e);
  CHECK(moqctl_request_ok_encode(wired_mspan_of(out, sizeof out), &n, &m));
  moqtstat_t_same(out, n, body);
}

/* 10.2.15: EXPIRES is not listed for TRACK_STATUS_OK, though the generic
 * REQUEST_OK decoder (union of every OK) admits it. */
static void test_moqtstat_ok_scope(void) {
  static const u8   exp[] = {0x01, 0x08, 0x05};
  moqctl_request_ok m;
  usz               off = 0;
  CHECK(
      moqtstat_ok_take(wired_span_of(exp, sizeof exp), &m) == MOQCTL_VIOLATION);
  CHECK(
      moqctl_request_ok_take(wired_span_of(exp, sizeof exp), &off, &m) ==
      MOQCTL_OK);
  CHECK(moqtstat_ok_take(wired_span_of(exp, 0), &m) == MOQCTL_VIOLATION);
}

static void test_moqtstat_update_golden(void) {
  wired_span body = moqtstat_t_body(
      g_moqt_ctl_request_update_forward, G_MOQT_CTL_REQUEST_UPDATE_FORWARD_LEN,
      MOQTSTAT_T_REQUEST_UPDATE);
  moqtstat_update m;
  u8              out[MOQCTL_MAX_MSG_LEN];
  usz             n = 0;
  if (moqtstat_update_take(body, MOQCTL_PCTX_UPDATE_SUBSCRIPTION, &m) !=
      MOQCTL_OK) {
    CHECK(0);
    return;
  }
  CHECK(m.request_id == 12);
  CHECK(m.params.n == 1);
  CHECK(m.params.items[0].type == MOQCTL_PARAM_FORWARD);
  CHECK(m.params.items[0].u8v == 0);
  CHECK(moqtstat_update_encode(wired_mspan_of(out, sizeof out), &n, &m));
  moqtstat_t_same(out, n, body);
}

/* 10.2.17: FORWARD may update a subscription, not a FETCH. */
static void test_moqtstat_update_scope(void) {
  wired_span body = wired_span_of(
      g_moqt_ctl_request_update_forward + 3,
      G_MOQT_CTL_REQUEST_UPDATE_FORWARD_MSG_LEN);
  moqtstat_update m;
  CHECK(
      moqtstat_update_take(body, MOQCTL_PCTX_UPDATE_FETCH, &m) ==
      MOQCTL_VIOLATION);
}

static void test_moqtstat_update_length_mismatch(void) {
  const u8*       b = g_moqt_ctl_request_update_forward + 3;
  usz             n = G_MOQT_CTL_REQUEST_UPDATE_FORWARD_MSG_LEN;
  u8              extra[G_MOQT_CTL_REQUEST_UPDATE_FORWARD_MSG_LEN + 1];
  moqtstat_update m;
  for (usz cut = 0; cut < n; cut++)
    CHECK(
        moqtstat_update_take(
            wired_span_of(b, cut), MOQCTL_PCTX_UPDATE_SUBSCRIPTION, &m) ==
        MOQCTL_VIOLATION);
  for (usz i = 0; i < n; i++) extra[i] = b[i];
  extra[n] = 0;
  CHECK(
      moqtstat_update_take(
          wired_span_of(extra, n + 1), MOQCTL_PCTX_UPDATE_SUBSCRIPTION, &m) ==
      MOQCTL_VIOLATION);
}

/* 1.4.1 MOQT varint size boundaries on Request ID (minimal encoding). */
static void moqtstat_t_rid(u64 rid, usz want_len) {
  moqtstat_update m = {0};
  moqtstat_update d;
  u8              out[16];
  usz             n = 0;
  m.request_id      = rid;
  CHECK(moqtstat_update_encode(wired_mspan_of(out, sizeof out), &n, &m));
  CHECK(n == want_len + 1);
  CHECK(
      moqtstat_update_take(
          wired_span_of(out, n), MOQCTL_PCTX_UPDATE_FETCH, &d) == MOQCTL_OK);
  CHECK(d.request_id == rid);
}

static void test_moqtstat_varint_boundaries(void) {
  moqtstat_t_rid(127, 1);
  moqtstat_t_rid(128, 2);
  moqtstat_t_rid(16383, 2);
  moqtstat_t_rid(16384, 3);
}

static void test_moqtstat_update_no_room(void) {
  moqtstat_update m = {0};
  u8              out[1];
  usz             n = 0;
  CHECK(!moqtstat_update_encode(wired_mspan_of(out, sizeof out), &n, &m));
}

void test_moqtstat(void) {
  test_moqtstat_golden();
  test_moqtstat_param_scope();
  test_moqtstat_length_mismatch();
  test_moqtstat_ok_golden();
  test_moqtstat_ok_scope();
  test_moqtstat_update_golden();
  test_moqtstat_update_scope();
  test_moqtstat_update_length_mismatch();
  test_moqtstat_varint_boundaries();
  test_moqtstat_update_no_room();
}
