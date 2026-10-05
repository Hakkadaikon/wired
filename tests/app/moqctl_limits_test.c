#include "app/moqt/fetch/moqfetch.h"
#include "app/moqt/ns/moqns.h"
#include "app/moqt/vi/moqvi.h"
#include "test.h"

/* Codec limits found by the Lean proofs (ledger 7-2 D2/D3). */

/* draft-22 FETCH body: Request ID 0, NS of one ns_len-byte field, a
 * name_len-byte Track Name, 0 Parameters. */
static usz moqlim_t_req22(u8* b, usz cap, usz ns_len, usz name_len) {
  wired_mspan m = wired_mspan_of(b, cap);
  usz         n = 0;
  CHECK(moqvi_put(m, &n, 0) && moqvi_put(m, &n, 1));
  CHECK(moqvi_put(m, &n, ns_len));
  for (usz i = 0; i < ns_len; i++) b[n++] = 'n';
  CHECK(moqvi_put(m, &n, name_len));
  for (usz i = 0; i < name_len; i++) b[n++] = 't';
  b[n++] = 0x00; /* Number of Parameters */
  return n;
}

/* SS2.4.1/SS1.5: Full Track Name (namespace fields + name) > 4096 bytes is
 * a PROTOCOL_VIOLATION -- the d22 FETCH take must apply it like d19 does. */
static void test_moqctl_limits_req22_ftn_boundary(void) {
  static u8    body[MOQCTL_MAX_FTN_LEN + 32];
  moqfetch_req m;
  usz          n = moqlim_t_req22(body, sizeof body, 4000, 96);
  CHECK(moqfetch_req22_take(wired_span_of(body, n), &m) == MOQCTL_OK);
  n = moqlim_t_req22(body, sizeof body, 4000, 97);
  CHECK(moqfetch_req22_take(wired_span_of(body, n), &m) == MOQCTL_VIOLATION);
}

static void moqlim_t_req19(moqfetch_req* m, moqctl_rsk sk, moqctl_rek ek) {
  static const u8 nb[]  = {'a'};
  *m                    = (moqfetch_req){0};
  m->fetch_type         = MOQFETCH_STANDALONE;
  m->track.ns.n         = 1;
  m->track.ns.fields[0] = wired_span_of(nb, 1);
  m->track.name         = wired_span_of(nb, 1);
  m->range.sk           = sk;
  m->range.ek           = ek;
  m->range.end_group    = 5;
}

/* d19 10.12.1: a Standalone Fetch carries an absolute Start and a bounded
 * End Location; an open end or a relative start has no d19 wire form, so
 * the encoder refuses instead of emitting a different range. */
static void test_moqctl_limits_req19_unrepresentable(void) {
  moqfetch_req m, back;
  u8           out[64];
  usz          n = 0;
  moqlim_t_req19(&m, MOQCTL_RSK_ABS, MOQCTL_REK_UNBOUNDED);
  CHECK(!moqfetch_req19_encode(wired_mspan_of(out, sizeof out), &n, &m));
  moqlim_t_req19(&m, MOQCTL_RSK_REL_GROUP, MOQCTL_REK_GROUP);
  CHECK(!moqfetch_req19_encode(wired_mspan_of(out, sizeof out), &n, &m));
  moqlim_t_req19(&m, MOQCTL_RSK_ABS, MOQCTL_REK_GROUP);
  CHECK(moqfetch_req19_encode(wired_mspan_of(out, sizeof out), &n, &m));
  CHECK(
      moqfetch_req19_take(MOQVER_D19, wired_span_of(out, n), &back) ==
      MOQCTL_OK);
  CHECK(back.range.ek == MOQCTL_REK_GROUP && back.range.end_group == 5);
}

/* One ns_len-byte namespace field and a name_len-byte Track Name, both
 * views into one shared filler buffer. */
static u8 moqlim_t_fill[MOQCTL_MAX_FTN_LEN];

static void moqlim_t_ftn(
    moqctl_ns* ns, wired_span* name, usz ns_len, usz name_len) {
  *ns           = (moqctl_ns){0};
  ns->n         = 1;
  ns->fields[0] = wired_span_of(moqlim_t_fill, ns_len);
  *name         = wired_span_of(moqlim_t_fill, name_len);
}

static int moqlim_t_redirect(usz ns_len, usz name_len) {
  static u8            buf[MOQCTL_MAX_FTN_LEN + 64];
  moqctl_request_error m = {0}, out;
  usz                  n = 0, off = 0;
  m.error_code   = MOQCTL_ERR_REDIRECT;
  m.has_redirect = 1;
  moqlim_t_ftn(
      &m.redirect.track_namespace, &m.redirect.track_name, ns_len, name_len);
  CHECK(moqctl_request_error_encode(wired_mspan_of(buf, sizeof buf), &n, &m));
  return moqctl_request_error_take(wired_span_of(buf, n), &off, &out);
}

/* d22 SS9.4.1: the Redirect target (Track Namespace + Track Name) is a
 * Full Track Name, so SS2.4.1's 4096-byte bound applies. */
static void test_moqctl_limits_redirect_ftn_boundary(void) {
  CHECK(moqlim_t_redirect(4000, 96) == MOQCTL_OK);
  CHECK(moqlim_t_redirect(4000, 97) == MOQCTL_VIOLATION);
}

static int moqlim_t_skipped(usz ns_len, usz name_len) {
  static u8         buf[MOQCTL_MAX_FTN_LEN + 64];
  moqns_pub_skipped m, out;
  usz               n = 0;
  moqlim_t_ftn(&m.ns, &m.name, ns_len, name_len);
  CHECK(moqns_pub_skipped_encode(wired_mspan_of(buf, sizeof buf), &n, &m));
  return moqns_pub_skipped_take(wired_span_of(buf, n), &out);
}

/* d22 SS9.19: Suffix + Track Name is a lower bound on the Full Track Name
 * (the prefix only adds bytes), so > 4096 already violates SS2.4.1. */
static void test_moqctl_limits_pub_skipped_ftn_boundary(void) {
  CHECK(moqlim_t_skipped(4000, 96) == MOQCTL_OK);
  CHECK(moqlim_t_skipped(4000, 97) == MOQCTL_VIOLATION);
}

void test_moqctl_limits(void) {
  test_moqctl_limits_req22_ftn_boundary();
  test_moqctl_limits_req19_unrepresentable();
  test_moqctl_limits_redirect_ftn_boundary();
  test_moqctl_limits_pub_skipped_ftn_boundary();
}
