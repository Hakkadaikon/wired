#include "test.h"

/* RFC 9000 8.1.1-8.1.4 / RFC 9369 5: the server's token gate for a fresh
 * Initial (srvrun_retry_consumed, the call srvrun_serve makes) and the
 * NEW_TOKEN tokens it accepts. Datagrams here are bare long headers: the
 * gate reads the header only, never the protected payload. */

static srvrun_conn      g_srvtok_conns[WIRED_CONNTABLE_CAP];
static conntable        g_srvtok_table[WIRED_CONNTABLE_CAP];
static wired_srvboot_id g_srvtok_id;
static srvrun_cfg       g_srvtok_cfg;
static srvrun_state     g_srvtok_st;
static sockaddr         g_srvtok_peer;

static srvrun_step_ctx srvtok_ctx(int force_retry) {
  srvrun_step_ctx ctx      = {0};
  g_srvtok_id              = (wired_srvboot_id){0};
  g_srvtok_id.scid_len     = 8;
  g_srvtok_cfg             = (srvrun_cfg){0};
  g_srvtok_cfg.fd          = -1;
  g_srvtok_cfg.id          = &g_srvtok_id;
  g_srvtok_cfg.env         = &g_srvrun_env;
  g_srvtok_cfg.force_retry = force_retry;
  conntable_init(g_srvtok_table, WIRED_CONNTABLE_CAP);
  bytes_memset(g_srvtok_conns, 0, sizeof g_srvtok_conns);
  g_srvtok_st = (srvrun_state){g_srvtok_table, g_srvtok_conns};
  wired_udp_addr(&g_srvtok_peer, 50000, (const u8[4]){192, 0, 2, 7});
  ctx.cfg  = &g_srvtok_cfg;
  ctx.st   = &g_srvtok_st;
  ctx.peer = &g_srvtok_peer;
  return ctx;
}

/* A v1 Initial long header (RFC 9000 17.2.2): DCID 8 x 0xAB, empty SCID,
 * token, Length 20, 20 payload bytes. */
static usz srvtok_initial(u8* out, wired_span token) {
  usz n    = 0;
  out[n++] = 0xC0;
  be_put_be32(out + n, VERSION_1);
  n += 4;
  out[n++] = 8;
  bytes_memset(out + n, 0xAB, 8);
  n += 8;
  out[n++] = 0;
  out[n++] = (u8)(0x40 | (token.n >> 8));
  out[n++] = (u8)token.n;
  bytes_memcpy(out + n, token.p, token.n);
  n += token.n;
  out[n++] = 0x40;
  out[n++] = 20;
  bytes_memset(out + n, 0, 20);
  return n + 20;
}

typedef struct {
  int        consumed, validated;
  wired_span odcid;
  usz        sent; /* datagrams the gate sent (a Retry or a close) */
} srvtok_out;

/* Run the production gate over an Initial carrying token. */
static srvtok_out srvtok_gate(const srvrun_step_ctx* ctx, wired_span token) {
  u8         dg[256];
  usz        n    = srvtok_initial(dg, token);
  usz        sent = g_srvrun_env.tx_flush_count;
  srvtok_out o    = {0, 0, {0, 0}, 0};
  o.consumed      = srvrun_retry_consumed(
      ctx, wired_span_of(dg + 6, 8), wired_mspan_of(dg, n), &o.odcid,
      &o.validated);
  o.sent = g_srvrun_env.tx_flush_count - sent;
  return o;
}

/* A tagged Retry token for ctx's peer and odcid {1,2,3,4} into tok. */
static usz srvtok_retry_token(const srvrun_step_ctx* ctx, u8* tok) {
  static const u8 odcid[4] = {1, 2, 3, 4};
  lhdr            h        = {0};
  u8              scid[8];
  usz             tn;
  h.dcid = wired_span_of(odcid, 4);
  srvrun_retry_prep(ctx, &h, scid, tok, &tn);
  CHECK(tn == 1 + 1 + 4 + RETRYTOKEN_LEN);
  CHECK(tok[0] == TOKEN_TAG_RETRY); /* RFC 9000 8.1.1 */
  return tn;
}

/* RFC 9000 8.1.2: a valid Retry token is served with its ODCID and
 * validates the address. */
static void test_srvrun_token_retry_valid_served(void) {
  srvrun_step_ctx ctx = srvtok_ctx(1);
  u8              tok[SRVRUN_RETRY_TOKEN_MAX];
  usz             tn = srvtok_retry_token(&ctx, tok);
  srvtok_out      o  = srvtok_gate(&ctx, wired_span_of(tok, tn));
  CHECK(o.consumed == 0);
  CHECK(o.validated == 1);
  CHECK(o.odcid.n == 4 && o.odcid.p[3] == 4);
  CHECK(o.sent == 0);
}

/* RFC 9000 8.1.2: an invalid Retry token closes with INVALID_TOKEN (one
 * Initial CONNECTION_CLOSE out, the datagram consumed) -- with or without
 * force_retry -- instead of being silently dropped. */
static void test_srvrun_token_retry_invalid_closes(void) {
  for (int force = 0; force < 2; force++) {
    srvrun_step_ctx ctx = srvtok_ctx(force);
    u8              tok[SRVRUN_RETRY_TOKEN_MAX];
    usz             tn = srvtok_retry_token(&ctx, tok);
    lhdr            h  = {0};
    wired_span      od;
    int             v = 0;
    tok[tn - 1] ^= 1;
    h.token = wired_span_of(tok, tn);
    CHECK(
        srvrun_token_verdict(&ctx, &h, VERSION_1, &od, &v) == SRVRUN_TOK_CLOSE);
    srvtok_out o = srvtok_gate(&ctx, wired_span_of(tok, tn));
    CHECK(o.consumed == 1);
    CHECK(o.validated == 0);
    CHECK(o.sent == 1);
  }
}

/* RFC 9000 8.1.3: no token, or one the server cannot validate, proceeds
 * unvalidated -- a Retry under force_retry, served as is otherwise. */
static void test_srvrun_token_unknown_proceeds_unvalidated(void) {
  u8         junk[SRVRUN_NEWTOK_LEN] = {TOKEN_TAG_NEWTOKEN, 9, 9, 9};
  u8         other[3]                = {0x7f, 1, 2};
  wired_span toks[3]                 = {
      wired_span_of(0, 0), wired_span_of(junk, sizeof junk),
      wired_span_of(other, sizeof other)};
  for (usz i = 0; i < 3; i++) {
    srvrun_step_ctx ctx = srvtok_ctx(1);
    srvtok_out      o   = srvtok_gate(&ctx, toks[i]);
    CHECK(o.consumed == 1); /* a Retry went out */
    CHECK(o.sent == 1);
    CHECK(o.validated == 0);
    ctx = srvtok_ctx(0);
    o   = srvtok_gate(&ctx, toks[i]);
    CHECK(o.consumed == 0);
    CHECK(o.validated == 0);
    CHECK(o.sent == 0);
  }
}

/* RFC 9000 8.1.3/8.1.4: a NEW_TOKEN token we issued validates the address
 * (no Retry even under force_retry), once only. */
static void test_srvrun_token_newtoken_validates_once(void) {
  srvrun_step_ctx ctx = srvtok_ctx(1);
  u8              tok[SRVRUN_NEWTOK_LEN];
  CHECK(
      srvrun_newtok_make(
          &g_srvtok_peer, VERSION_1, wired_clock_epoch_secs(), tok) ==
      SRVRUN_NEWTOK_LEN);
  CHECK(tok[0] == TOKEN_TAG_NEWTOKEN); /* RFC 9000 8.1.1 */
  srvtok_out o = srvtok_gate(&ctx, wired_span_of(tok, sizeof tok));
  CHECK(o.consumed == 0);
  CHECK(o.validated == 1);
  CHECK(o.sent == 0);
  o = srvtok_gate(&ctx, wired_span_of(tok, sizeof tok)); /* replayed */
  CHECK(o.consumed == 1);
  CHECK(o.validated == 0);
}

/* RFC 9000 8.1.4: bound to the client IP but not the port (a new
 * connection uses a new port); RFC 9369 5: bound to the version; RFC 9000
 * 8.1.3: expires. */
static void test_srvrun_newtok_binding(void) {
  sockaddr a, port2, ip2;
  u64      now = wired_clock_epoch_secs();
  u8       t[5][SRVRUN_NEWTOK_LEN];
  wired_udp_addr(&a, 50000, (const u8[4]){192, 0, 2, 7});
  wired_udp_addr(&port2, 50001, (const u8[4]){192, 0, 2, 7});
  wired_udp_addr(&ip2, 50000, (const u8[4]){192, 0, 2, 8});
  for (usz i = 0; i < 5; i++) {
    CHECK(srvrun_newtok_make(&a, VERSION_1, now, t[i]) == SRVRUN_NEWTOK_LEN);
  }
  CHECK(srvrun_newtok_ok(&port2, VERSION_1, wired_span_of(t[0], 57), now));
  CHECK(!srvrun_newtok_ok(&ip2, VERSION_1, wired_span_of(t[1], 57), now));
  CHECK(!srvrun_newtok_ok(&a, VERSION_2, wired_span_of(t[2], 57), now));
  CHECK(!srvrun_newtok_ok(
      &a, VERSION_1, wired_span_of(t[3], 57), now + NEWTOKEN_MAX_AGE_SECS + 1));
  t[4][0] = TOKEN_TAG_RETRY; /* a re-tagged token is not a NEW_TOKEN one */
  CHECK(!srvrun_newtok_ok(&a, VERSION_1, wired_span_of(t[4], 57), now));
}

/* RFC 9000 8.1: a token-validated address is not held to the 3x limit. */
static void test_srvrun_token_lifts_antiamp(void) {
  srvrun_conn* c = &g_srvtok_conns[0];
  bytes_memset(c, 0, sizeof *c);
  CHECK(srvrun_boot_gate_blocks(c, 0, 100) == 1);
  c->addr_validated = 1;
  CHECK(srvrun_boot_gate_blocks(c, 0, 100) == 0);
}

void test_srvrun_token(void) {
  CHECK(SRVRUN_NEWTOK_LEN == 57);
  test_srvrun_token_retry_valid_served();
  test_srvrun_token_retry_invalid_closes();
  test_srvrun_token_unknown_proceeds_unvalidated();
  test_srvrun_token_newtoken_validates_once();
  test_srvrun_newtok_binding();
  test_srvrun_token_lifts_antiamp();
}
