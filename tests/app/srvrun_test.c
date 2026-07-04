#include "app/http3/server/srvrun/srvrun.h"

#include "app/http3/core/h3/frame.h"
#include "test.h"
#include "transport/packet/frame/frame/frame.h"

/* @file
 * Graceful shutdown (SIGTERM) behavior. rt_sigaction registration itself
 * (sigterm.c) delivers a real kernel signal and is not exercised here — these
 * tests drive the shutdown flag directly via srvrun_test_set_shutdown, the
 * documented test-only hook, and assert on what srvrun.c does once the flag
 * is set: new-Initial rejection, GOAWAY fan-out, and drain completion. Reuses
 * srvloop_test.c's lp_fix/lp_confirm to reach a confirmed connection (same
 * translation unit, included earlier in tests/run.c). */

/* A confirmed srvrun_conn built from a freshly-confirmed lp_fix, up and ready
 * to receive GOAWAY. */
static void sr_make_confirmed_conn(
    srvrun_conn *c, struct lp_fix *f, quic_obuf *ob) {
  lp_confirm(f, ob);
  *c = (srvrun_conn){f->s, f->l, 1, {0}, {0}, 0};
}

/* Find the H3 GOAWAY frame's id in a 1-RTT payload carrying a STREAM frame on
 * the control stream (id 3). Returns 1 and sets *id if found. */
static int sr_find_goaway_id(const u8 *pl, usz pll, u64 *id) {
  quic_stream_frame sf;
  usz               n = quic_frame_get_stream(pl, pll, &sf);
  if (n == 0 || sf.stream_id != SRVRUN_CTRL_STREAM) return 0;
  return quic_h3_goaway_get(sf.data, (usz)sf.length, id) > 0;
}

/* BASELINE: no shutdown requested -> a fresh Initial is accepted as usual
 * (srvrun_is_new says yes on a not-yet-up slot). */
static void test_srvrun_no_shutdown_accepts_new(void) {
  srvrun_conn c       = {0};
  u8          ini[64] = {0xc3, 0, 0, 0, 1, 0, 0}; /* long-header Initial-ish */
  srvrun_test_set_shutdown(0);
  CHECK(wired_srvboot_is_initial(ini, sizeof ini));
  CHECK(srvrun_is_new(&c, quic_mspan_of(ini, sizeof ini)) == 1);
}

/* NEW-ACCEPT STOPPED: once shutdown is requested, a fresh Initial on a slot
 * not yet up is refused (srvrun_is_new returns 0), the gate this task adds. */
static void test_srvrun_shutdown_rejects_new_initial(void) {
  srvrun_conn c       = {0};
  u8          ini[64] = {0xc3, 0, 0, 0, 1, 0, 0};
  srvrun_test_set_shutdown(1);
  CHECK(srvrun_is_new(&c, quic_mspan_of(ini, sizeof ini)) == 0);
  srvrun_test_set_shutdown(0);
}

/* EXISTING CONNECTIONS UNAFFECTED: shutdown does not stop srvrun_claim_slot
 * from being asked, but it must refuse — proving the "no new slot" rule is
 * enforced at the claim step new connections funnel through. */
static void test_srvrun_shutdown_refuses_slot_claim(void) {
  srvrun_step_ctx ctx;
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_state    st      = {table, 0};
  u8              dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  ctx = (srvrun_step_ctx){0, 0, &st};
  srvrun_test_set_shutdown(1);
  CHECK(srvrun_claim_slot(&ctx, quic_span_of(dcid, 8), 1) == -1);
  srvrun_test_set_shutdown(0);
  CHECK(srvrun_claim_slot(&ctx, quic_span_of(dcid, 8), 1) >= 0);
}

/* GOAWAY OWED: a confirmed, live connection that has not yet been sent GOAWAY
 * owes one; the same connection after sending does not (sent exactly once). */
static void test_srvrun_owes_goaway_once(void) {
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            out[256], obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  CHECK(srvrun_owes_goaway(&c) == 1);
  {
    quic_obuf  gob = {out, sizeof out, 0};
    srvrun_cfg cfg = {-1, 0, 0, 0}; /* fd unused: srvrun_send skips len==0,
                                       but sealed GOAWAY is non-empty, so this
                                       exercises a real (harmless) send(2) to
                                       an invalid fd -- accepted since srvrun_
                                       send does not check the return value */
    CHECK(srvrun_send_goaway(&cfg, &c, &gob) == 1);
  }
  CHECK(c.goaway_sent == 1);
  CHECK(srvrun_owes_goaway(&c) == 0);
}

/* GOAWAY WIRE CONTENT: the sealed packet opens under the client's 1-RTT peer
 * key and carries a GOAWAY frame on the control stream. */
static void test_srvrun_goaway_wire_content(void) {
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob;
  u8            out[256], obuf[1024];
  const u8     *pl;
  usz           pll;
  u64           id = 0xffffffffu;
  ob               = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  {
    quic_obuf  gob = {out, sizeof out, 0};
    srvrun_cfg cfg = {-1, 0, 0, 0};
    CHECK(srvrun_send_goaway(&cfg, &c, &gob) == 1);
    CHECK(client_open_onertt(&f, out, gob.len, &pl, &pll) == 1);
  }
  CHECK(sr_find_goaway_id(pl, pll, &id) == 1);
  CHECK(id == SRVRUN_GOAWAY_ID);
}

/* NOT UP: a slot that never came up owes no GOAWAY (no peer to send it to). */
static void test_srvrun_not_up_owes_nothing(void) {
  srvrun_conn c = {0};
  CHECK(srvrun_owes_goaway(&c) == 0);
}

/* NOT CONFIRMED: an up-but-unconfirmed slot (no 1-RTT key yet) owes nothing
 * either -- it is left to the handshake timeout instead. */
static void test_srvrun_unconfirmed_owes_nothing(void) {
  srvrun_conn c = {0};
  c.up          = 1;
  CHECK(c.l.hs_done_sent == 0);
  CHECK(srvrun_owes_goaway(&c) == 0);
}

/* DRAIN COMPLETE: srvrun_all_drained is 1 once every slot is down. */
static void test_srvrun_all_drained_true_when_all_down(void) {
  srvrun_state   st;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  st                                       = (srvrun_state){table, conns};
  CHECK(srvrun_all_drained(&st) == 1);
}

/* DRAIN PENDING: one slot still up -> not drained. */
static void test_srvrun_all_drained_false_when_one_up(void) {
  srvrun_state   st;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  conns[3].up                              = 1;
  st                                       = (srvrun_state){table, conns};
  CHECK(srvrun_all_drained(&st) == 0);
}

void test_srvrun(void) {
  test_srvrun_no_shutdown_accepts_new();
  test_srvrun_shutdown_rejects_new_initial();
  test_srvrun_shutdown_refuses_slot_claim();
  test_srvrun_owes_goaway_once();
  test_srvrun_goaway_wire_content();
  test_srvrun_not_up_owes_nothing();
  test_srvrun_unconfirmed_owes_nothing();
  test_srvrun_all_drained_true_when_all_down();
  test_srvrun_all_drained_false_when_one_up();
}
