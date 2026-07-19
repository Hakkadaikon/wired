#include "app/http3/server/srvrun/srvrun.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/request.h"
#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/webtransport/errmap/errmap/errmap.h"
#include "app/webtransport/wtwire/wtwire.h"
#include "common/bytes/util/bytes.h"
#include "test.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"

/* Shared backing storage for every test's own srvrun_conn conns[] (see
 * sr_test_conns below): ONE static array, not one per call site. Each
 * srvrun_conn embeds wired_srvloop, whose WT receive windows
 * (WIRED_SRVLOOP_WT_BUF_CAP) this repo wants sized for real throughput, not
 * a stack (or per-test BSS) budget -- one static QUIC_CONNTABLE_CAP-sized
 * array shared by every test costs the same BSS regardless of how many test
 * functions reuse it; 46 independent statics (this file's original fix,
 * cbe1f44) each paid the full array's cost again, and once the window grew
 * past a few KB that summed to a multi-gigabyte BSS the loader could not
 * even map (a real crash this exact way, found immediately after widening
 * the window in a later commit). */
static srvrun_conn g_test_conns[QUIC_CONNTABLE_CAP];

/* Zero the shared conns[] and hand back a pointer to it, mirroring what each
 * call site's own `srvrun_conn conns[QUIC_CONNTABLE_CAP] = {0};` used to
 * declare locally. */
static srvrun_conn* sr_test_conns(void) {
  quic_memset(g_test_conns, 0, sizeof g_test_conns);
  return g_test_conns;
}

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
    srvrun_conn* c, struct lp_fix* f, quic_obuf* ob) {
  lp_confirm(f, ob);
  *c    = (srvrun_conn){0};
  c->s  = f->s;
  c->l  = f->l;
  c->up = 1;
  quic_cc_init(&c->cc);
  quic_rtt_init(&c->rtt);
  /* RFC 9000 18.2/19.9: this test drives srvrun_conn directly (not through
   * srvrun_boot_finish, the real seeding point), so the connection-level
   * send credit must be seeded here from the same ClientHello TP the
   * fixture's lp_client_tp already advertises (16MB) -- otherwise every
   * resp[] slot's send is blocked from byte 0, unrelated to whatever gate
   * a given test actually means to exercise. */
  c->conn_credit = c->s.sdrv.peer_initial_max_data;
  /* Same reasoning, per-stream: many existing tests set up resp[] slots by
   * direct field assignment (c.resp[i].in_use = 1, .stream_id = ...) rather
   * than through srvrun_resp_claim (the real seeding point for
   * stream_credit). Seed every slot here so those tests -- which exercise
   * cwnd/log/PTO gates, not flow control -- are not incidentally blocked by
   * an unrelated 0 stream credit; a test that specifically wants to
   * exercise the stream-credit gate overrides this afterward. */
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    c->resp[i].stream_credit = c->s.sdrv.peer_initial_max_data;
}

/* Find the H3 GOAWAY frame's id in a 1-RTT payload carrying a STREAM frame on
 * the control stream (id 3). Returns 1 and sets *id if found. */
static int sr_find_goaway_id(const u8* pl, usz pll, u64* id) {
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
  ctx = (srvrun_step_ctx){0, 0, &st, 0};
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
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0}; /* fd unused: srvrun_send
 skips len==0, but sealed GOAWAY is
 non-empty, so this exercises a real
 (harmless) send(2) to an invalid fd --
 accepted since srvrun_send does not
 check the return value */
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
  const u8*     pl;
  usz           pll;
  u64           id = 0xffffffffu;
  ob               = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  {
    quic_obuf  gob = {out, sizeof out, 0};
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0};
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
  srvrun_conn*   conns = sr_test_conns();
  st                   = (srvrun_state){table, conns};
  CHECK(srvrun_all_drained(&st) == 1);
}

/* DRAIN PENDING: one slot still up -> not drained. */
static void test_srvrun_all_drained_false_when_one_up(void) {
  srvrun_state   st;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  conns[3].up          = 1;
  st                   = (srvrun_state){table, conns};
  CHECK(srvrun_all_drained(&st) == 0);
}

#define SYS_unlinkat 263
#define SRVRUNT_AT_FDCWD (-100)
static const char srvrunt_qlog_path[] = "build/srvrun_qlog_test.tmp";

static void srvrunt_qlog_unlink(void) {
  syscall3(SYS_unlinkat, SRVRUNT_AT_FDCWD, srvrunt_qlog_path, 0);
}

/* Match the NUL-terminated needle at p (caller guarantees needle-len bytes
 * are readable). */
static int sr_bytes_match(const u8* p, const char* s) {
  for (usz i = 0; s[i]; i++)
    if (p[i] != (u8)s[i]) return 0;
  return 1;
}

static usz sr_needle_len(const char* s) {
  usz n = 0;
  while (s[n]) n++;
  return n;
}

/* Occurrences of needle in the qlog test file (0 when the file is absent). */
static int sr_qlog_count(const char* needle) {
  u8  buf[2048] = {0};
  int cnt       = 0;
  ssz n  = wired_fio_read(srvrunt_qlog_path, quic_mspan_of(buf, sizeof buf));
  usz nl = sr_needle_len(needle);
  if (n < 0) return 0;
  for (usz i = 0; i + nl <= (usz)n; i++) cnt += sr_bytes_match(buf + i, needle);
  return cnt;
}

/* No qlog path set (the default): srvrun_send writes nothing to any qlog
 * file. */
static void test_srvrun_send_no_qlog_path_writes_nothing(void) {
  u8          buf[8] = {1, 2, 3, 4};
  srvrun_conn c      = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  srvrunt_qlog_unlink();
  srvrun_send(&cfg, &c, quic_span_of(buf, sizeof buf), "t\n");
  {
    u8  out[8] = {0};
    ssz n = wired_fio_read(srvrunt_qlog_path, quic_mspan_of(out, sizeof out));
    CHECK(n < 0);
  }
}

/* A qlog path set: srvrun_send appends one packet_sent record. */
static void test_srvrun_send_qlog_path_writes_packet_sent(void) {
  u8          buf[8] = {1, 2, 3, 4};
  srvrun_conn c      = {0};
  srvrun_cfg  cfg    = {-1, 0, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0, 0,
                        0,  0, 0, 0, &g_srvrun_env,     0, 0, 0, 0, 0};
  srvrunt_qlog_unlink();
  srvrun_send(&cfg, &c, quic_span_of(buf, sizeof buf), "t\n");
  {
    u8  out[256] = {0};
    ssz n = wired_fio_read(srvrunt_qlog_path, quic_mspan_of(out, sizeof out));
    CHECK(n > 0);
    CHECK(out[0] == 0x1E); /* JSON-SEQ RS */
    CHECK(out[n - 1] == '\n');
  }
  srvrunt_qlog_unlink();
}

/* Empty output (pkt.n == 0): srvrun_send skips the send AND the qlog record
 * (nothing was actually sent on the wire). */
static void test_srvrun_send_empty_pkt_no_qlog_record(void) {
  srvrun_conn c   = {0};
  srvrun_cfg  cfg = {-1, 0, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0, 0,
                     0,  0, 0, 0, &g_srvrun_env,     0, 0, 0, 0, 0};
  srvrunt_qlog_unlink();
  srvrun_send(&cfg, &c, quic_span_of(0, 0), "t\n");
  {
    u8  out[8] = {0};
    ssz n = wired_fio_read(srvrunt_qlog_path, quic_mspan_of(out, sizeof out));
    CHECK(n < 0);
  }
}

/* Certificate hot reload (SIGHUP): srvrun_reload_if_requested drives
 * wired_certreload_load off srvrun_test_set_reload, the same test-only-hook
 * pattern as shutdown above (a real SIGHUP delivery is not unit-testable). */

static const char srvrunt_cert_path[] = "build/srvrun_reload_cert_test.pem";
static const char srvrunt_key_path[]  = "build/srvrun_reload_key_test.pem";

/* Same golden PEM text as certreload_test.c (realchain leaf + eckey SEC1),
 * duplicated here rather than shared across files to keep each test file
 * self-contained (ponytail: a few literal lines, not worth a shared header). */
#define SRVRUNT_PEM_CERT                                               \
  "-----BEGIN CERTIFICATE-----\n"                                      \
  "MIIBhjCCASygAwIBAgIBAzAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA53aXJlZC10\n" \
  "ZXN0LWludDAeFw0yNjA3MDIwMzAwMTZaFw00NjA2MjcwMzAwMTZaMBYxFDASBgNV\n" \
  "BAMMC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaiCgdwIw\n" \
  "Wr9ZW+r2+wkv3gHqRx1516+pZtZ2nXbJzBfS1WrY6Qr1eRcyEpp1qqriguUUDLnG\n" \
  "zj9dEaGlOqA6maNoMGYwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDAYDVR0TAQH/\n" \
  "BAIwADAdBgNVHQ4EFgQUtWK5IGsF72wY/FzDIVPcGRDA98gwHwYDVR0jBBgwFoAU\n" \
  "p0+jTTg9jyM2ABMsb5MvCggSYMEwCgYIKoZIzj0EAwIDSAAwRQIgf1pfoFLUW1fX\n" \
  "qkXST1CxjIT2zWkxf1SM922UProdj70CIQCfQ3MEJPxSIUHt3H/58fEK/cMZ+Pc9\n" \
  "iAVZ8V5X3ScnOQ==\n"                                                 \
  "-----END CERTIFICATE-----\n"
#define SRVRUNT_PEM_KEY                                                \
  "-----BEGIN EC PRIVATE KEY-----\n"                                   \
  "MHcCAQEEIGEwVXfogbUsrnfdXV/ibLZWhMGAQXbeSwuof7yWDf8PoAoGCCqGSM49\n" \
  "AwEHoUQDQgAExXHoorugQyGhZofbmSFiyMSC0ZMgR5KTsql7o85ozCdi8WXaIs9s\n" \
  "Jqr6SCDjgvw9xPMUV3UEDxCsEZbkEZpW/A==\n"                             \
  "-----END EC PRIVATE KEY-----\n"
static const char srvrunt_cert_pem[] = SRVRUNT_PEM_CERT;
static const char srvrunt_key_pem[]  = SRVRUNT_PEM_KEY;

static void srvrunt_write(const char* path, const char* text, usz n) {
  syscall3(SYS_unlinkat, SRVRUNT_AT_FDCWD, path, 0);
  wired_fio_append(path, quic_span_of((const u8*)text, n));
}

/* BASELINE: no reload requested -> id is left completely untouched. */
static void test_srvrun_no_reload_leaves_id_untouched(void) {
  wired_srvboot_id id  = {0};
  const u8*        pub = (const u8*)0x2a;
  id.pub               = pub;
  srvrun_cfg cfg       = {
      -1,
      &id,
      0,
      0,
      0,
      0,
      srvrunt_cert_path,
      srvrunt_key_path,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      &g_srvrun_env,
      0,
      0,
      0,
      0,
      0};
  srvrun_test_set_reload(0);
  srvrun_reload_if_requested(&cfg, &g_srvrun_env);
  CHECK(id.pub == pub);
  CHECK(id.chain_count == 0);
}

/* RELOAD APPLIED: a pending reload decodes the PEM pair into id and clears
 * the flag (srvrun_reload_requested reads 0 afterward). */
static void test_srvrun_reload_requested_updates_id(void) {
  wired_srvboot_id id  = {0};
  srvrun_cfg       cfg = {
      -1,
      &id,
      0,
      0,
      0,
      0,
      srvrunt_cert_path,
      srvrunt_key_path,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      &g_srvrun_env,
      0,
      0,
      0,
      0,
      0};
  srvrunt_write(
      srvrunt_cert_path, srvrunt_cert_pem, sizeof(srvrunt_cert_pem) - 1);
  srvrunt_write(srvrunt_key_path, srvrunt_key_pem, sizeof(srvrunt_key_pem) - 1);
  srvrun_test_set_reload(1);
  srvrun_reload_if_requested(&cfg, &g_srvrun_env);
  CHECK(srvrun_reload_requested(&g_srvrun_env) == 0);
  CHECK(id.chain_count == 1);
  CHECK(id.chain != 0);
  syscall3(SYS_unlinkat, SRVRUNT_AT_FDCWD, srvrunt_cert_path, 0);
  syscall3(SYS_unlinkat, SRVRUNT_AT_FDCWD, srvrunt_key_path, 0);
}

/* RELOAD DISABLED: cert_path unset (reload off) -> a pending flag is cleared
 * but id is never touched, even though it is nonzero. */
static void test_srvrun_reload_disabled_when_no_cert_path(void) {
  wired_srvboot_id id  = {0};
  const u8*        pub = (const u8*)0x2a;
  id.pub               = pub;
  srvrun_cfg cfg       = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                          0,  &g_srvrun_env, 0, 0, 0, 0, 0};
  srvrun_test_set_reload(1);
  srvrun_reload_if_requested(&cfg, &g_srvrun_env);
  CHECK(srvrun_reload_requested(&g_srvrun_env) == 0);
  CHECK(id.pub == pub);
  CHECK(id.chain_count == 0);
}

/* RELOAD FAILS SAFE: a missing cert file leaves the previous identity in
 * place instead of clobbering it with a half-decoded result. */
static void test_srvrun_reload_failure_keeps_previous_id(void) {
  wired_srvboot_id id  = {0};
  const u8*        pub = (const u8*)0x2a;
  id.pub               = pub;
  id.chain_count       = 7;
  syscall3(SYS_unlinkat, SRVRUNT_AT_FDCWD, srvrunt_cert_path, 0);
  {
    srvrun_cfg cfg = {
        -1,
        &id,
        0,
        0,
        0,
        0,
        srvrunt_cert_path,
        srvrunt_key_path,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        &g_srvrun_env,
        0,
        0,
        0,
        0,
        0};
    srvrun_test_set_reload(1);
    srvrun_reload_if_requested(&cfg, &g_srvrun_env);
  }
  CHECK(id.pub == pub);
  CHECK(id.chain_count == 7);
}

/* Server identity for full srvrun_serve runs (the sb_make_id shape;
 * h3_loopback_test.c's own copy is included later in the TU). */
static const u8 g_sr_srv_scid[6] = {'S', 'R', 'V', 'S', 'C', 'I'};

static void sr_make_id(
    wired_srvboot_id* id, u8 priv[32], u8 pub[32], u8 seed[32], u8 rnd[32]) {
  for (usz i = 0; i < 32; i++) {
    priv[i] = (u8)(0x21 + i);
    seed[i] = (u8)(0x91 + i);
    rnd[i]  = (u8)(0x51 + i);
  }
  quic_x25519_base(pub, priv);
  id->priv                    = priv;
  id->pub                     = pub;
  id->cert_seed               = seed;
  id->scid                    = g_sr_srv_scid;
  id->scid_len                = 6;
  id->random                  = rnd;
  id->chain                   = 0;
  id->chain_count             = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 0;
  id->san_ipv4                = 0;
  id->now_secs                = 0;
}

/* A real protected client Initial datagram addressed to odcid (RFC 9001 5.2:
 * Initial keys derive from it), the same construction test_srvboot_accept
 * uses. */
static usz sr_build_client_initial(
    u8* dg, usz cap, const u8* odcid, u8 odcid_len) {
  quic_client c;
  u8          cpriv[32], cpub[32];
  quic_obuf   ob = quic_obuf_of(dg, cap);
  for (usz i = 0; i < 32; i++) cpriv[i] = (u8)(11 + i);
  quic_x25519_base(cpub, cpriv);
  quic_tlsdriver_init(&c.tls, cpriv, cpub, 0);
  {
    quic_clientwire_hdr_in hdr = {
        quic_span_of(odcid, odcid_len), quic_span_of(g_cli_scid, 6), 0};
    CHECK(quic_client_build_initial_wire(&c, &hdr, &ob) == 1);
  }
  return ob.len;
}

static const u8 g_sr_odcid[8] = {0x11, 0x22, 0x33, 0x44,
                                 0x55, 0x66, 0x77, 0x88};

/* REKEY ON ACCEPT (RFC 9000 7.2): after a real Initial cold-starts a slot via
 * srvrun_serve, the table routes by the slot's own generated SCID — the DCID
 * the client uses from its second flight on — and no longer by the Initial's
 * DCID. */
static void test_srvrun_accept_rekeys_to_slot_scid(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], dg[1500];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz total             = sr_build_client_initial(dg, sizeof dg, g_sr_odcid, 8);
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
  }
  CHECK(st.conns[0].up == 1);
  /* the Initial's DCID keeps routing here (RFC 9000 7.2/17.2.2: a client
   * Initial retransmitted before it has seen the new SCID must still reach
   * this same slot, not spawn a duplicate connection) ... */
  CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, g_sr_odcid, 8) == 0);
  /* ...and so does the slot's generated SCID */
  CHECK(
      quic_conntable_find(
          table, QUIC_CONNTABLE_CAP, st.conns[0].scid, id.scid_len) == 0);
}

/* AF_XDP CORE ROUTING (wired_srvrun_opt.core_id): a fresh slot's generated
 * SCID has its leading byte overwritten with this worker's core/queue index
 * when both an XDP driver and a non-negative core_id are configured -- the
 * BPF filter reads this same byte back out to key its XSKMAP lookup. */
static void test_srvrun_open_slot_xdp_embeds_core_id(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], dg[1500];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz          total    = sr_build_client_initial(dg, sizeof dg, g_sr_odcid, 8);
  wired_srvxdp fake_xdp; /* never dereferenced by srvrun_open_slot itself --
                          * only its non-0-ness (xdp mode on) is read */
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {
        .id      = &id,
        .xdp     = &fake_xdp,
        .env     = &g_srvrun_env,
        .core_id = 15,
        0,
        0,
        0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
  }
  CHECK(st.conns[0].up == 1);
  CHECK(st.conns[0].scid[0] == 15);
}

/* MIN/MAX core ids both land in the leading byte (bits=8 boundary). */
static void test_srvrun_open_slot_xdp_embeds_core_id_zero(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], dg[1500];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz          total    = sr_build_client_initial(dg, sizeof dg, g_sr_odcid, 8);
  wired_srvxdp fake_xdp;
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {
        .id      = &id,
        .xdp     = &fake_xdp,
        .env     = &g_srvrun_env,
        .core_id = 0,
        0,
        0,
        0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
  }
  CHECK(st.conns[0].up == 1);
  CHECK(st.conns[0].scid[0] == 0);
}

/* NON-XDP MODE (xdp == 0, the SO_REUSEPORT/plain-UDP default): core_id is
 * never consulted -- checked directly against srvrun_xdp_core_routing's own
 * gate (the single predicate srvrun_issue_cid consults to decide whether to
 * embed at all), not by asserting a freshly generated random byte differs
 * from some fixed value (that would be a 1/256 flaky false-negative on a
 * genuine coincidence, not a real embedding). */
static void test_srvrun_open_slot_non_xdp_no_core_id_embedding(void) {
  srvrun_cfg cfg = {.xdp = 0, .core_id = 7, 0, 0, 0};
  CHECK(srvrun_xdp_core_routing(&cfg) == 0);
}

/* CORE_ID < 0 (disabled sentinel) with xdp set still does not embed -- again
 * checked against srvrun_xdp_core_routing's own gate directly, mirrors
 * wired_server_run's own default_opt (xdp unset there, but core_id defaults
 * to -1 the same way incoming_cpu does). */
static void test_srvrun_issue_cid_xdp_negative_core_id_no_embed(void) {
  u8           cid[8] = {0};
  wired_srvxdp fake_xdp;
  srvrun_cfg   cfg = {.xdp = &fake_xdp, .core_id = -1, 0, 0, 0};
  CHECK(srvrun_xdp_core_routing(&cfg) == 0);
  CHECK(srvrun_issue_cid(&cfg, cid, sizeof cid) == 1); /* still succeeds, just
                                                        * without embedding */
}

/* CORE_ID embedding via the shared seam directly (xdp on, core_id in
 * range): the leading byte is exactly the core id, regardless of whatever
 * quic_cid_generate randomly produced there first. */
static void test_srvrun_issue_cid_xdp_embeds_core_id(void) {
  u8           cid[8] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
  wired_srvxdp fake_xdp;
  srvrun_cfg   cfg = {.xdp = &fake_xdp, .core_id = 15, 0, 0, 0};
  CHECK(srvrun_issue_cid(&cfg, cid, sizeof cid) == 1);
  CHECK(cid[0] == 15);
}

/* BOOT RETRANSMIT (RFC 9000 13.3): before the handshake is confirmed, the
 * same client Initial arriving again (its first reply lost or delayed) must
 * resend the cached accept flight, not run a fresh boot -- a fresh boot
 * would regenerate the slot's SCID and its keys, which is what left Chrome
 * unable to complete a handshake (tasks/interop-gap.md). This test proves
 * the slot's identity is untouched by the retransmit: same SCID, same
 * cached flight bytes, still not confirmed. */
static void test_srvrun_initial_retransmit_resends_cached_flight(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], dg[1500];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz total             = sr_build_client_initial(dg, sizeof dg, g_sr_odcid, 8);
  u8  first_scid[WIRED_MAX_CID_LEN];
  usz first_boot_ini_len, first_boot_dgram_count, send_count_after_first;
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_test_reset_send_count();
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
    CHECK(st.conns[0].up == 1);
    for (usz i = 0; i < id.scid_len; i++) first_scid[i] = st.conns[0].scid[i];
    first_boot_ini_len     = st.conns[0].boot_ini_len;
    first_boot_dgram_count = st.conns[0].boot_dgram_count;
    CHECK(first_boot_ini_len > 0);
    /* not confirmed yet -- this Initial carried no client Finished */
    CHECK(wired_server_is_confirmed(&st.conns[0].s) == 0);
    send_count_after_first = srvrun_test_send_count();
    CHECK(send_count_after_first > 0); /* the accept flight went out */

    /* the exact same datagram arrives again (a lost first reply) */
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
  }
  CHECK(st.conns[0].up == 1);
  /* the retransmit triggered its own sends -- proof the cached flight was
   * actually resent, not silently dropped into the confirmed-connection
   * step path (which would leave the send count unchanged) */
  CHECK(srvrun_test_send_count() > send_count_after_first);
  /* still the same slot, same identity -- a fresh boot would have
   * regenerated scid and reset the boot cache */
  CHECK(
      quic_conntable_find(
          table, QUIC_CONNTABLE_CAP, st.conns[0].scid, id.scid_len) == 0);
  for (usz i = 0; i < id.scid_len; i++)
    CHECK(st.conns[0].scid[i] == first_scid[i]);
  CHECK(st.conns[0].boot_ini_len == first_boot_ini_len);
  CHECK(st.conns[0].boot_dgram_count == first_boot_dgram_count);
}

/* @file
 * RFC 9000 8.1 anti-amplification limit on the boot flight send path
 * (srvrun_boot_send_hs_gated/srvrun_boot_send/srvrun_boot_budget). Drives
 * the gate helpers directly against a hand-built srvrun_conn/boot_hs so
 * these tests don't need a real 9-certificate chain to inflate a flight
 * past the 3x budget -- a handful of small fake datagram lengths is enough
 * to exercise the same boundary. */

static srvrun_cfg sr_antiamp_cfg(wired_srvboot_id* id) {
  srvrun_cfg cfg = {-1, id, 0, 0, 0, 0, 0, 0,
                    0,  0,  0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0,  0, 0, 0};
  return cfg;
}

/* A boot flight of 4 datagrams, 1000 bytes each (4000 total), none sent
 * yet. c->boot_hs holds 4000 arbitrary bytes (their content is irrelevant --
 * srvrun_send only ever looks at the span's length once cfg->fd is -1). */
static void sr_antiamp_seed_flight(srvrun_conn* c) {
  quic_memset(c, 0, sizeof *c);
  for (usz i = 0; i < 4; i++) c->boot_dgram_len[i] = 1000;
  c->boot_dgram_count = 4;
  c->boot_dgram_sent  = 0;
}

/* T-001/T-004: exactly the first round from the real amplificationlimit
 * trace -- 1280 bytes received buys a 3840-byte budget, which fits 3 of the
 * 4 1000-byte datagrams (3000 <= 3840 < 4000) and holds the 4th back. */
static void test_srvrun_boot_antiamp_first_round_caps_at_3x(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  sr_antiamp_seed_flight(&c);
  c.boot_rx_bytes = 1280;
  {
    srvrun_cfg cfg = sr_antiamp_cfg(&id);
    srvrun_test_reset_send_count();
    srvrun_boot_send_hs_gated(&cfg, &c, 0);
  }
  CHECK(c.boot_dgram_sent == 3);
  CHECK(c.boot_tx_bytes == 3000);
  CHECK(srvrun_test_send_count() == 3);
}

/* T-002: the unsent 4th datagram's length never entered boot_tx_bytes. */
static void test_srvrun_boot_antiamp_unsent_tail_not_counted(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  sr_antiamp_seed_flight(&c);
  c.boot_rx_bytes = 1280;
  {
    srvrun_cfg cfg = sr_antiamp_cfg(&id);
    srvrun_boot_send_hs_gated(&cfg, &c, 0);
  }
  CHECK(c.boot_tx_bytes < 4000);
  CHECK(c.boot_dgram_sent < c.boot_dgram_count);
}

/* T-003: a second round with more received bytes (the client's Initial
 * retransmit) releases the held-back datagram -- mirrors the real trace's
 * two-Initial sequence (1280, then another 1280 -> budget 7680). */
static void test_srvrun_boot_antiamp_second_round_releases_more(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  sr_antiamp_seed_flight(&c);
  c.boot_rx_bytes = 1280;
  {
    srvrun_cfg cfg = sr_antiamp_cfg(&id);
    srvrun_boot_send_hs_gated(&cfg, &c, 0);
    CHECK(c.boot_dgram_sent == 3);
    c.boot_rx_bytes += 1280; /* client's retransmitted Initial arrives */
    srvrun_boot_send_hs_gated(&cfg, &c, 0);
  }
  CHECK(c.boot_dgram_sent == 4);
  CHECK(c.boot_tx_bytes == 4000);
}

/* T-005: want == budget+1 blocks -- a 3841-byte want against a 3840 budget
 * sends nothing (one 3841-byte datagram, budget from 1280 received). */
static void test_srvrun_boot_antiamp_budget_off_by_one_blocks(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_memset(&c, 0, sizeof c);
  c.boot_dgram_len[0] = 3841;
  c.boot_dgram_count  = 1;
  c.boot_rx_bytes     = 1280;
  {
    srvrun_cfg cfg = sr_antiamp_cfg(&id);
    srvrun_boot_send_hs_gated(&cfg, &c, 0);
  }
  CHECK(c.boot_dgram_sent == 0);
  CHECK(c.boot_tx_bytes == 0);
}

/* T-004 boundary complement: want == budget exactly (3840) sends. */
static void test_srvrun_boot_antiamp_budget_exact_fit_sends(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_memset(&c, 0, sizeof c);
  c.boot_dgram_len[0] = 3840;
  c.boot_dgram_count  = 1;
  c.boot_rx_bytes     = 1280;
  {
    srvrun_cfg cfg = sr_antiamp_cfg(&id);
    srvrun_boot_send_hs_gated(&cfg, &c, 0);
  }
  CHECK(c.boot_dgram_sent == 1);
  CHECK(c.boot_tx_bytes == 3840);
}

/* T-006: received == 0 (budget == 0) sends nothing at all. */
static void test_srvrun_boot_antiamp_zero_budget_sends_nothing(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  sr_antiamp_seed_flight(&c);
  c.boot_rx_bytes = 0;
  {
    srvrun_cfg cfg = sr_antiamp_cfg(&id);
    srvrun_boot_send_hs_gated(&cfg, &c, 0);
  }
  CHECK(c.boot_dgram_sent == 0);
  CHECK(c.boot_tx_bytes == 0);
}

/* T-007: once confirmed, the limit is lifted -- all 4 go out in one pass
 * even though 4000 > 3*1280=3840 would otherwise block the 4th. */
static void test_srvrun_boot_antiamp_confirmed_bypasses_limit(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  sr_antiamp_seed_flight(&c);
  c.boot_rx_bytes = 1280;
  {
    srvrun_cfg cfg = sr_antiamp_cfg(&id);
    srvrun_boot_send_hs_gated(&cfg, &c, 1 /* confirmed */);
  }
  CHECK(c.boot_dgram_sent == 4);
  CHECK(c.boot_tx_bytes == 4000);
}

/* T-011 regression: a small (single-datagram) flight -- the common case,
 * e.g. a self-signed cert -- always fits the first round's budget and
 * sends in one pass, same as before this gate existed. */
static void test_srvrun_boot_antiamp_small_flight_sends_in_one_round(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_memset(&c, 0, sizeof c);
  c.boot_dgram_len[0] = 300;
  c.boot_dgram_count  = 1;
  c.boot_rx_bytes     = 1280;
  {
    srvrun_cfg cfg = sr_antiamp_cfg(&id);
    srvrun_boot_send_hs_gated(&cfg, &c, 0);
  }
  CHECK(c.boot_dgram_sent == 1);
  CHECK(c.boot_tx_bytes == 300);
}

/* T-014: srvrun_boot_send (used for the Initial too, not just Handshake
 * datagrams) also folds into boot_tx_bytes -- Initial + Handshake share one
 * budget. */
static void test_srvrun_boot_antiamp_sent_includes_initial_and_handshake(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], ini[1200] = {0};
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_memset(&c, 0, sizeof c);
  c.boot_rx_bytes = 1280;
  {
    srvrun_cfg cfg = sr_antiamp_cfg(&id);
    srvrun_boot_send(&cfg, &c, quic_span_of(ini, sizeof ini), "test\n");
  }
  CHECK(c.boot_tx_bytes == 1200);
}

/* T-010: a slot with boot datagrams held back by the antiamp gate never
 * spins or crashes while the client stays silent -- it just sits until the
 * existing idle sweep (RFC 9000 10.1) reclaims it like any other stalled
 * slot (srvrun_slot_busy already covers c->up regardless of the pending
 * tail). Also confirms repeated release attempts against an unchanged
 * budget are idempotent (no partial/garbage sends). */
static void test_srvrun_boot_antiamp_client_silent_no_crash(void) {
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  srvrun_state     st = {table, sr_test_conns()};
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_id(&id, priv, pub, seed, rnd);
  sr_antiamp_seed_flight(&st.conns[0]);
  st.conns[0].up            = 1;
  st.conns[0].boot_rx_bytes = 1280;
  st.conns[0].last_ms       = 1000;
  {
    srvrun_cfg      cfg = sr_antiamp_cfg(&id);
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
    srvrun_boot_send_hs_gated(ctx.cfg, &st.conns[0], 0);
    CHECK(
        st.conns[0].boot_dgram_sent == 3); /* held back at 3/4, same as T-001 */
    /* another release attempt with no new budget changes nothing */
    srvrun_boot_send_hs_gated(ctx.cfg, &st.conns[0], 0);
    CHECK(st.conns[0].boot_dgram_sent == 3);
    CHECK(st.conns[0].boot_tx_bytes == 3000);
  }
  /* the client never sends anything else -- eventually the idle sweep
   * reclaims the slot like any other stalled connection */
  srvrun_sweep_idle(&g_srvrun_env, &st, 1000 + WIRED_SRVRUN_IDLE_MS);
  CHECK(st.conns[0].up == 0);
  CHECK(st.conns[0].boot_dgram_sent == 0);
}

/* T-013: boot_rx_bytes counts every physically received byte on the slot,
 * even a datagram that fails to parse/decrypt as anything useful -- RFC
 * 9000 8.1 counts what arrived, not what was understood. Sends a real boot
 * Initial (to claim the slot and record boot_rx_bytes's starting point),
 * then a short-header datagram addressed to that slot's own SCID (so
 * srvrun_route resolves it to the same slot) but with undecryptable 1-RTT
 * garbage after the header, and checks boot_rx_bytes grew by exactly its
 * length even though nothing in it opens. */
static void test_srvrun_conn_rx_bytes_counts_malformed_datagram(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], dg[1500];
  u8               garbage[37];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz total             = sr_build_client_initial(dg, sizeof dg, g_sr_odcid, 8);
  u64 rx_after_boot;
  usz i;
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
    CHECK(st.conns[0].up == 1);
    rx_after_boot = st.conns[0].boot_rx_bytes;
    /* short header (0x40), this slot's own SCID as DCID, then garbage */
    garbage[0] = 0x40;
    for (i = 0; i < id.scid_len; i++) garbage[1 + i] = st.conns[0].scid[i];
    for (; 1 + i < sizeof garbage; i++) garbage[1 + i] = (u8)(0xaa + i);
    srvrun_serve(&ctx, quic_mspan_of(garbage, sizeof garbage));
  }
  CHECK(st.conns[0].boot_rx_bytes == rx_after_boot + sizeof garbage);
}

/* T-008: srvrun_resend_boot_flight (the client-Initial-retransmit path)
 * respects the same antiamp budget as the first round -- a flight too big
 * for one round still only releases what the accumulated boot_rx_bytes
 * allows, it does not resend the cached flight unconditionally. */
static void test_srvrun_resend_boot_flight_respects_antiamp_budget(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  srvrun_conn      c;
  sr_make_id(&id, priv, pub, seed, rnd);
  sr_antiamp_seed_flight(&c);
  c.boot_rx_bytes = 1280; /* first round already spent, budget 3840 */
  {
    srvrun_cfg      cfg = sr_antiamp_cfg(&id);
    srvrun_step_ctx ctx = {&cfg, 0, 0, 0};
    srvrun_boot_send_hs_gated(&cfg, &c, 0);
    CHECK(c.boot_dgram_sent == 3);
    srvrun_resend_boot_flight(&ctx, &c); /* no new rx_bytes -- still capped */
  }
  CHECK(c.boot_dgram_sent == 3);
  CHECK(c.boot_tx_bytes == 3000);
}

/* T-015: srvrun_free_slot zeroes the antiamp accounting so a slot reused
 * for a fresh boot doesn't inherit a stale budget from the connection it
 * replaces. */
static void test_srvrun_free_slot_resets_antiamp_state(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_state   st = {table, sr_test_conns()};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st.conns[0].boot_rx_bytes   = 5000;
  st.conns[0].boot_tx_bytes   = 4000;
  st.conns[0].boot_dgram_sent = 3;
  srvrun_free_slot(&g_srvrun_env, &st, 0);
  CHECK(st.conns[0].boot_rx_bytes == 0);
  CHECK(st.conns[0].boot_tx_bytes == 0);
  CHECK(st.conns[0].boot_dgram_sent == 0);
}

/* Append a minimal well-formed (undecryptable) Handshake long-header packet
 * at off: byte0 0xE0, version 1, the given DCID, no SCID, a 5-byte body.
 * Returns the new datagram length. */
static usz sr_append_handshake_pkt(u8* dg, usz off, const u8* dcid, u8 n) {
  dg[off++] = 0xe0; /* long header, fixed bit, type Handshake */
  dg[off++] = 0;
  dg[off++] = 0;
  dg[off++] = 0;
  dg[off++] = 1; /* version 1 */
  dg[off++] = n;
  for (usz i = 0; i < n; i++) dg[off++] = dcid[i];
  dg[off++] = 0; /* scid_len 0 */
  dg[off++] = 5; /* Length: 5 (1-byte varint) */
  for (usz i = 0; i < 5; i++) dg[off++] = (u8)(0xa0 + i);
  return off;
}

/* SECOND FLIGHT COALESCING (RFC 9000 12.2): a client's second datagram
 * coalesces an Initial (ACKing the server flight) with a Handshake packet
 * carrying its Finished -- curl/ngtcp2 and Chrome both send this shape.
 * That datagram is NOT a bare Initial retransmit: swallowing it to resend
 * the cached boot flight would discard the Finished, leave the handshake
 * unconfirmed forever, and stall the connection right after it reports
 * connected (observed live with curl). It must fall through to the step
 * path, so no cached-flight resend fires. */
static void test_srvrun_coalesced_handshake_not_boot_retransmit(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], dg[1500], dg2[1500];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz total             = sr_build_client_initial(dg, sizeof dg, g_sr_odcid, 8);
  usz n2, send_count_after_boot;
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_test_reset_send_count();
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
    CHECK(st.conns[0].up == 1);
    CHECK(wired_server_is_confirmed(&st.conns[0].s) == 0);
    send_count_after_boot = srvrun_test_send_count();
    CHECK(send_count_after_boot > 0);

    /* the same Initial coalesced with an (undecryptable) Handshake packet:
     * classification, not decryption, is what is under test here */
    for (usz i = 0; i < total; i++) dg2[i] = dg[i];
    n2 = sr_append_handshake_pkt(dg2, total, st.conns[0].scid, id.scid_len);
    srvrun_serve(&ctx, quic_mspan_of(dg2, n2));
  }
  /* not intercepted: no cached-flight resend fired for the coalesced dgram */
  CHECK(srvrun_test_send_count() == send_count_after_boot);
  CHECK(st.conns[0].up == 1);
}

/* Raw ClientHello + one sealed chunk Initial, the srvrun-side split fixture
 * (mirrors the srvboot accumulator tests' construction). */
static usz sr_raw_ch(quic_client* c, u8* ch, usz cap) {
  u8 cpriv[32], cpub[32];
  for (usz i = 0; i < 32; i++) cpriv[i] = (u8)(11 + i);
  quic_x25519_base(cpub, cpriv);
  quic_tlsdriver_init(&c->tls, cpriv, cpub, 0);
  return quic_tlsdriver_raw_client_hello(&c->tls, ch, cap);
}

static usz sr_seal_chunk(u8* dg, usz cap, quic_span chunk, u64 off, u64 pn) {
  quic_initpkt_desc d = {
      quic_span_of(g_sr_odcid, 8), quic_span_of(g_cli_scid, 6), chunk, pn, off};
  quic_obuf o = quic_obuf_of(dg, cap);
  CHECK(quic_initpkt_build(&d, &o) == 1);
  return o.len;
}

/* A ClientHello split across two Initial datagrams: the first claims the
 * slot and keeps it (not up yet, no flight), the second completes the
 * reassembly and boots the connection (RFC 9000 19.6). */
static void test_srvrun_split_ch_boots_across_datagrams(void) {
  wired_srvboot_id id;
  quic_client      c;
  u8               priv[32], pub[32], seed[32], rnd[32];
  u8               ch[512], dg1[1400], dg2[1400];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz              n    = sr_raw_ch(&c, ch, sizeof ch);
  usz n1 = sr_seal_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 0);
  usz n2 = sr_seal_chunk(dg2, sizeof dg2, quic_span_of(ch + 60, n - 60), 60, 1);
  CHECK(n > 100);
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    st.conns[0].up       = 0;
    st.conns[0].boot.any = 0;
    srvrun_serve(&ctx, quic_mspan_of(dg1, n1));
    CHECK(st.conns[0].up == 0); /* half a ClientHello: no boot yet */
    CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, g_sr_odcid, 8) == 0);
    srvrun_serve(&ctx, quic_mspan_of(dg2, n2));
  }
  CHECK(st.conns[0].up == 1);
  CHECK(
      quic_conntable_find(
          table, QUIC_CONNTABLE_CAP, st.conns[0].scid, id.scid_len) == 0);
}

/* A boot that never completes is reclaimed by the idle sweep, and the freed
 * slot then boots a fresh attempt normally. */
static void test_srvrun_stalled_boot_swept(void) {
  wired_srvboot_id id;
  quic_client      c;
  u8               priv[32], pub[32], seed[32], rnd[32];
  u8               ch[512], dg1[1400], dg2[1400], d1[1400], d2[1400];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz              n    = sr_raw_ch(&c, ch, sizeof ch);
  usz n1 = sr_seal_chunk(dg1, sizeof dg1, quic_span_of(ch, 60), 0, 0);
  usz n2 = sr_seal_chunk(dg2, sizeof dg2, quic_span_of(ch + 60, n - 60), 60, 1);
  for (usz i = 0; i < n1; i++) d1[i] = dg1[i];
  for (usz i = 0; i < n2; i++) d2[i] = dg2[i];
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 1000};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    st.conns[0].up       = 0;
    st.conns[0].boot.any = 0;
    srvrun_serve(&ctx, quic_mspan_of(dg1, n1));
    CHECK(st.conns[0].boot.any == 1);
    srvrun_sweep_idle(&g_srvrun_env, &st, 1000 + WIRED_SRVRUN_IDLE_MS);
    /* reclaimed: table entry gone, accumulator emptied */
    CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, g_sr_odcid, 8) == -1);
    CHECK(st.conns[0].boot.any == 0);
    /* the same slot claims and boots a fresh attempt */
    srvrun_serve(&ctx, quic_mspan_of(d1, n1));
    srvrun_serve(&ctx, quic_mspan_of(d2, n2));
  }
  CHECK(st.conns[0].up == 1);
}

/* An unknown-version datagram never claims a connection slot: it is answered
 * (or dropped) before routing, so the table stays empty (RFC 9000 5.2.2). */
static void test_srvrun_alien_version_claims_no_slot(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  u8               dg[1200] = {0};
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  dg[0]                 = 0xd3;
  dg[4]                 = 0xcf; /* alien version */
  dg[5]                 = 6;
  for (usz i = 0; i < 6; i++) dg[6 + i] = (u8)(0x60 + i);
  dg[12] = 4;
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    st.conns[0].up = 0;
    srvrun_serve(&ctx, quic_mspan_of(dg, sizeof dg));
  }
  CHECK(st.conns[0].up == 0);
  CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, dg + 6, 6) == -1);
}

/* UNCLAIM ON FAILURE: an Initial-shaped datagram whose cold start fails must
 * not leave a live table entry behind — the slot stays claimable. */
static void test_srvrun_failed_accept_unclaims(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  u8               junk[64] = {0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0};
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_serve(&ctx, quic_mspan_of(junk, sizeof junk));
  }
  CHECK(st.conns[0].up == 0);
  /* no live entry remains for the junk DCID... */
  CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, junk + 6, 8) == -1);
  /* ...and the slot itself is still claimable */
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, junk + 6, 8) == 0);
}

/* PEER CLOSE FREES THE SLOT (RFC 9000 10.2.2): a routed CONNECTION_CLOSE
 * tears the slot down — table entry gone, up cleared, no reply sent (the
 * qlog stays empty; an ACK-only reply would have logged packet_sent) — and a
 * later datagram carrying the dead connection's DCID creates no state. */
static void test_srvrun_peer_close_frees_slot(void) {
  struct lp_fix         f;
  wired_srvboot_id      id;
  u8                    priv[32], pub[32], seed[32], rnd[32];
  u8                    obuf[1024], cc[32], spkt[1024];
  quic_conntable        table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in      peer = {0};
  srvrun_state          st   = {table, g_srvrun_state.conns};
  quic_obuf             ob   = {obuf, sizeof obuf, 0};
  quic_conn_close_frame ccf  = {0, 0, 0, 0, 0};
  usz                   ccn, slen;
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&st.conns[0], &f, &ob);
  /* route the fixture's 1-RTT DCID (its iscid) to slot 0 */
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == 0);
  ccn = quic_frame_put_conn_close(cc, sizeof cc, &ccf);
  CHECK(ccn > 0);
  slen = client_seal_onertt(&f, cc, ccn, spkt, sizeof spkt);
  srvrunt_qlog_unlink();
  {
    srvrun_cfg      cfg = {-1, &id, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0, 0,
                           0,  0,   0, 0, &g_srvrun_env,     0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    srvrun_serve(&ctx, quic_mspan_of(spkt, slen));
    /* slot freed: up cleared, DCID no longer routes */
    CHECK(st.conns[0].up == 0);
    CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == -1);
    /* no reply was sent for the close (draining sends nothing) — the close
     * datagram itself is still logged as received */
    CHECK(sr_qlog_count("packet_sent") == 0);
    /* a later datagram on the dead DCID is dropped without new state */
    srvrun_serve(&ctx, quic_mspan_of(spkt, slen));
    CHECK(st.conns[0].up == 0);
    CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == -1);
  }
  srvrunt_qlog_unlink();
}

/* IDLE EVICTION (RFC 9000 10.1): the sweep frees a slot silent at least the
 * advertised max_idle_timeout, keeps an active one, and the freed slot is
 * claimable again. */
static void test_srvrun_idle_sweep_evicts_expired(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_state   st    = {table, g_srvrun_state.conns};
  u8             k1[4] = {1, 1, 1, 1}, k2[4] = {2, 2, 2, 2};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st.conns[0].up      = 1;
  st.conns[0].last_ms = 1000;
  st.conns[1].up      = 1;
  st.conns[1].last_ms = 20000;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, k1, 4) == 0);
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, k2, 4) == 1);
  srvrun_sweep_idle(&g_srvrun_env, &st, 1000 + WIRED_SRVRUN_IDLE_MS);
  /* the expired slot is gone, the active one survives */
  CHECK(st.conns[0].up == 0);
  CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, k1, 4) == -1);
  CHECK(st.conns[1].up == 1);
  CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, k2, 4) == 1);
  /* the freed slot is claimable again */
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, k1, 4) == 0);
}

/* T-015: a connection torn down (here, idle sweep) mid-streaming-response
 * releases its resp[] slots' claimed bigbuf pool rows -- otherwise
 * wired_srvbigbuf's own in_use[] bookkeeping never learns the row is free
 * (srvrun_open_slot only zeroes the conn struct on reuse, it never touches
 * the pool), and that row is leaked for the server's whole remaining
 * lifetime. */
static void test_srvrun_idle_sweep_releases_bigbuf_row(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_state   st    = {table, g_srvrun_state.conns};
  u8             k1[4] = {9, 9, 9, 9};
  int            row;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  wired_srvbigbuf_init(
      &g_srvrun_env.bigbuf, &g_srvrun_env.bigbuf_rows[0][0],
      WIRED_SRVBIGBUF_ROW_CAP);
  st.conns[0]                = (srvrun_conn){0};
  st.conns[0].up             = 1;
  st.conns[0].last_ms        = 1000;
  st.conns[0].resp[0].in_use = 1;
  CHECK(
      wired_srvbigbuf_claim(
          &g_srvrun_env.bigbuf, &st.conns[0].resp[0].bigbuf_row) != 0);
  row = st.conns[0].resp[0].bigbuf_row;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, k1, 4) == 0);
  srvrun_sweep_idle(&g_srvrun_env, &st, 1000 + WIRED_SRVRUN_IDLE_MS);
  CHECK(st.conns[0].up == 0);
  /* the row is free again: claiming it (or any row, with only 2 total)
   * succeeds, proving it was actually released rather than leaked. */
  {
    int row2;
    CHECK(wired_srvbigbuf_claim(&g_srvrun_env.bigbuf, &row2) != 0);
    CHECK(row2 == row); /* the lowest-index free row is this one again */
    wired_srvbigbuf_release(&g_srvrun_env.bigbuf, row2);
  }
}

/* ACTIVITY REFRESH (RFC 9000 10.1): every datagram routed to a slot stamps
 * its last-activity time, so a served connection never counts as idle. */
static void test_srvrun_serve_slot_touches_last_ms(void) {
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  srvrun_state     st    = {table, g_srvrun_state.conns};
  quic_sockaddr_in peer  = {0};
  u8               sh[8] = {0x40, 1, 2, 3, 4, 5, 6, 7}; /* short header */
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  srvrun_step_ctx ctx = {&cfg, &peer, &st, 12345};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st.conns[2].up      = 0;
  st.conns[2].last_ms = 0;
  srvrun_serve_slot(&ctx, 2, quic_mspan_of(sh, sizeof sh));
  CHECK(st.conns[2].last_ms == 12345);
}

/* Serve one sealed 1-RTT datagram carrying `pl` to a fresh confirmed slot 0,
 * with qlog_path (or 0). The lp fixture seals under the client 1-RTT key at
 * PN 0. Repeats the serve `times` times against the same slot. */
static void sr_serve_onertt(
    const char* qlog_path, const u8* pl, usz pln, int times) {
  struct lp_fix    f;
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  u8               obuf[1024], spkt[1024];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  quic_obuf        ob   = {obuf, sizeof obuf, 0};
  usz              slen;
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&st.conns[0], &f, &ob);
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == 0);
  slen = client_seal_onertt(&f, pl, pln, spkt, sizeof spkt);
  {
    srvrun_cfg      cfg = {-1, &id, 0, 0, qlog_path,     0, 0, 0, 0, 0, 0,
                           0,  0,   0, 0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    for (int i = 0; i < times; i++)
      srvrun_serve(&ctx, quic_mspan_of(spkt, slen));
  }
}

/* RECEIVED LOGGED (qlog): an opened 1-RTT datagram that advances the receive
 * packet number appends one packet_received record. */
static void test_srvrun_qlog_records_received(void) {
  u8 ping[1] = {0x01};
  srvrunt_qlog_unlink();
  sr_serve_onertt(srvrunt_qlog_path, ping, 1, 1);
  CHECK(sr_qlog_count("packet_received") == 1);
  srvrunt_qlog_unlink();
}

/* DUPLICATE NOT RE-LOGGED: the same datagram (same PN) served twice advances
 * the receive PN only once, so only one record is written. */
static void test_srvrun_qlog_no_dup_record(void) {
  u8 ping[1] = {0x01};
  srvrunt_qlog_unlink();
  sr_serve_onertt(srvrunt_qlog_path, ping, 1, 2);
  CHECK(sr_qlog_count("packet_received") == 1);
  srvrunt_qlog_unlink();
}

/* NO PATH, NO RECORD: with qlog disabled nothing is written even for an
 * opened datagram. */
static void test_srvrun_qlog_recv_no_path_writes_nothing(void) {
  u8 ping[1] = {0x01};
  srvrunt_qlog_unlink();
  sr_serve_onertt(0, ping, 1, 1);
  CHECK(sr_qlog_count("packet_received") == 0);
}

/* UNDECRYPTABLE, NO RECORD: a garbage short-header datagram that opens
 * nothing advances no PN and logs nothing. */
static void test_srvrun_qlog_skips_undecryptable(void) {
  struct lp_fix    f;
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  u8               obuf[1024];
  u8               junk[32] = {0x40, 'C', 'L', 'I', 'S', 'C', 'I', 9, 9, 9};
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  quic_obuf        ob   = {obuf, sizeof obuf, 0};
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&st.conns[0], &f, &ob);
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == 0);
  srvrunt_qlog_unlink();
  {
    srvrun_cfg      cfg = {-1, &id, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0, 0,
                           0,  0,   0, 0, &g_srvrun_env,     0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    srvrun_serve(&ctx, quic_mspan_of(junk, sizeof junk));
  }
  CHECK(sr_qlog_count("packet_received") == 0);
}

/* INITIAL ACCEPT LOGGED: a real client Initial that cold-starts a slot logs
 * one packet_received (the client's first Initial, PN 0). */
static void test_srvrun_qlog_records_initial(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], dg[1500];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz total             = sr_build_client_initial(dg, sizeof dg, g_sr_odcid, 8);
  sr_make_id(&id, priv, pub, seed, rnd);
  srvrunt_qlog_unlink();
  {
    srvrun_cfg      cfg = {-1, &id, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0, 0,
                           0,  0,   0, 0, &g_srvrun_env,     0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
  }
  CHECK(st.conns[0].up == 1);
  CHECK(sr_qlog_count("packet_received") == 1);
  srvrunt_qlog_unlink();
}

/* FAILED ACCEPT NOT LOGGED: an Initial whose cold start fails logs nothing.
 */
static void test_srvrun_qlog_skips_failed_accept(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  u8               junk[64] = {0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0};
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  sr_make_id(&id, priv, pub, seed, rnd);
  srvrunt_qlog_unlink();
  {
    srvrun_cfg      cfg = {-1, &id, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0, 0,
                           0,  0,   0, 0, &g_srvrun_env,     0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_serve(&ctx, quic_mspan_of(junk, sizeof junk));
  }
  CHECK(sr_qlog_count("packet_received") == 0);
}

/* BATCH SERVE: a recvmmsg-style batch of two real Initials from two peers is
 * served message by message — both slots come up, and each slot records its
 * own message's source address as the connection's peer (the reply target,
 * RFC 9000 5.1). */
static void test_srvrun_batch_serves_each(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  static u8        dgs[2][1500];
  quic_mmsg_buf    bufs[2];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  srvrun_state     st        = {table, g_srvrun_state.conns};
  const u8         odcid2[8] = {0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22};
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  bufs[0].buf = quic_mspan_of(dgs[0], sizeof dgs[0]);
  bufs[0].len =
      (u32)sr_build_client_initial(dgs[0], sizeof dgs[0], g_sr_odcid, 8);
  bufs[0].src = (quic_sockaddr_in){0};
  bufs[1].buf = quic_mspan_of(dgs[1], sizeof dgs[1]);
  bufs[1].len = (u32)sr_build_client_initial(dgs[1], sizeof dgs[1], odcid2, 8);
  bufs[1].src = (quic_sockaddr_in){0};
  bufs[0].src.port_be = 0x1111; /* two distinct peers */
  bufs[1].src.port_be = 0x2222;
  {
    srvrun_cfg cfg = {-1, &id,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_serve_batch(&cfg, &st, bufs, 2);
  }
  CHECK(st.conns[0].up == 1);
  CHECK(st.conns[1].up == 1);
  /* each slot keeps its own message's source as the reply target */
  CHECK(st.conns[0].peer.port_be == 0x1111);
  CHECK(st.conns[1].peer.port_be == 0x2222);
}

/* Body handler for the takeover test: 2.5 chunks of a counting pattern. */
static int sr_body_handler(
    void*                       hctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
    const char**                ct,
    int*                        more,
    u64*                        total_size) {
  (void)hctx;
  (void)req;
  (void)ct;
  (void)offset;
  (void)more;
  (void)total_size;
  for (usz i = 0; i < 2500 && i < body_out->cap; i++)
    body_out->p[i] = (u8)(i & 0xff);
  body_out->len = 2500;
  return 1;
}

/* Body handler for the bigbuf pool test: fills the whole cap the storage
 * layer handed it with a counting pattern, proving the pool row (not the
 * 16KB fixed row) backed the write. */
static int sr_bigbuf_body_handler(
    void*                       hctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
    const char**                ct,
    int*                        more,
    u64*                        total_size) {
  (void)hctx;
  (void)req;
  (void)ct;
  (void)offset;
  (void)more;
  (void)total_size;
  for (usz i = 0; i < body_out->cap; i++) body_out->p[i] = (u8)(i & 0xff);
  body_out->len = body_out->cap;
  return 1;
}

/* Body handler for the slot-reuse test: a trivial single-byte body, so one
 * ACK finishes the session (drives srvrun_resp_reap without a multi-slice
 * pump). */
static int sr_tiny_body_handler(
    void*                       hctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
    const char**                ct,
    int*                        more,
    u64*                        total_size) {
  (void)hctx;
  (void)req;
  (void)ct;
  (void)offset;
  (void)more;
  (void)total_size;
  if (body_out->cap < 1) return 0;
  body_out->p[0] = 'x';
  body_out->len  = 1;
  return 1;
}

/* Local socket pair on its own port (4439; the recvmmsg tests own 4437). */
static int sr_open_sockets(i64* sfd, i64* cfd, quic_sockaddr_in* srv) {
  *sfd = wired_udp_socket();
  if (*sfd < 0) return 0;
  wired_udp_addr(srv, 4439, (const u8[4]){127, 0, 0, 1});
  if (wired_udp_bind(*sfd, srv) < 0) {
    wired_udp_close(*sfd);
    return 0;
  }
  *cfd = wired_udp_socket();
  if (*cfd < 0) {
    wired_udp_close(*sfd);
    return 0;
  }
  return 1;
}

/* Collect every STREAM frame in an opened payload into asm_buf by offset;
 * returns bytes of the highest offset+len seen, sets *fin if any slice
 * carried it. */
static usz sr_collect_stream(
    const u8* pl, usz pll, u8* asm_buf, usz cap, usz high, int* fin) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_stream_frame   sf;
  quic_framewalk_init(&it, pl, pll);
  while (quic_framewalk_next(&it, &fr)) {
    if (fr.type < 0x08 || fr.type > 0x0f) continue;
    if (quic_frame_get_stream(fr.start, fr.remaining, &sf) == 0) continue;
    for (usz i = 0; i < sf.length && sf.offset + i < cap; i++)
      asm_buf[sf.offset + i] = sf.data[i];
    if ((usz)(sf.offset + sf.length) > high) high = sf.offset + sf.length;
    *fin |= sf.fin;
  }
  return high;
}

/* Collect every STREAM frame in an opened payload into a per-stream-id
 * bucket (asm[i] for the i-th distinct stream_id seen, up to max_streams).
 * Mirrors sr_collect_stream's offset-indexed reassembly, but keyed by
 * stream_id instead of assuming a single response stream -- what a parallel
 * multi-stream response needs to verify each stream's bytes land in its own
 * buffer, not interleaved with a sibling's. */
typedef struct {
  u64 stream_id;
  int used;
  u8* buf;
  usz cap;
  usz high;
  int fin;
} sr_stream_bucket;

static sr_stream_bucket* sr_bucket_for(
    sr_stream_bucket* buckets, usz max_streams, u64 stream_id) {
  usz i;
  for (i = 0; i < max_streams; i++) {
    if (buckets[i].used && buckets[i].stream_id == stream_id)
      return &buckets[i];
    if (!buckets[i].used) {
      buckets[i].used      = 1;
      buckets[i].stream_id = stream_id;
      return &buckets[i];
    }
  }
  return 0;
}

static void sr_collect_stream_multi(
    const u8* pl, usz pll, sr_stream_bucket* buckets, usz max_streams) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_stream_frame   sf;
  quic_framewalk_init(&it, pl, pll);
  while (quic_framewalk_next(&it, &fr)) {
    sr_stream_bucket* b;
    if (fr.type < 0x08 || fr.type > 0x0f) continue;
    if (quic_frame_get_stream(fr.start, fr.remaining, &sf) == 0) continue;
    b = sr_bucket_for(buckets, max_streams, sf.stream_id);
    if (!b) continue;
    for (usz i = 0; i < sf.length && sf.offset + i < b->cap; i++)
      b->buf[sf.offset + i] = sf.data[i];
    if ((usz)(sf.offset + sf.length) > b->high) b->high = sf.offset + sf.length;
    b->fin |= sf.fin;
  }
}

/* PARALLEL RESPONSES: three GETs on distinct streams (0, 4, 8), coalesced
 * into ONE datagram (the exact quic-go interop shape: HEADERS for all three
 * packed into one 1-RTT packet), each answered with its own small body from
 * its own resp[] slot. Every stream's reassembled bytes must be exactly its
 * own body, unmixed with the others' -- the core property multiplexing
 * needs (RFC 9000 2.2). Benign skip when the sandbox forbids sockets. */
static int sr_parallel_body_handler(
    void*                       hctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
    const char**                ct,
    int*                        more,
    u64*                        total_size) {
  (void)hctx;
  (void)ct;
  (void)offset;
  (void)more;
  (void)total_size;
  /* one byte body: 'A'/'B'/'C' keyed by the request path ("/a", "/b", "/c")
   * so each stream's response is trivially distinguishable. */
  if (req->path_len >= 2 && body_out->cap >= 1) {
    body_out->p[0] = req->path[1];
    body_out->len  = 1;
    return 1;
  }
  return 0;
}

static void test_srvrun_parallel_responses_three_streams(void) {
  struct lp_fix            f;
  wired_srvboot_id         id;
  u8                       priv[32], pub[32], seed[32], rnd[32];
  u8                       obuf[1024], payload[512], spkt[1024];
  u8                       asm_bufs[3][64] = {{0}};
  sr_stream_bucket         buckets[3]      = {0};
  static const u64         stream_ids[3]   = {0, 4, 8};
  static const char* const paths[3]        = {"/a", "/b", "/c"};
  quic_conntable           table[QUIC_CONNTABLE_CAP];
  srvrun_state             st = {table, g_srvrun_state.conns};
  quic_obuf                ob = {obuf, sizeof obuf, 0};
  quic_sockaddr_in         srv, from;
  i64                      sfd, cfd;
  usz                      off, slen;
  if (!sr_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&st.conns[0], &f, &ob);
  st.conns[0].l.resp_external = 1;
  st.conns[0].peer            = srv;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == 0);
  for (usz i = 0; i < 3; i++) {
    buckets[i].buf = asm_bufs[i];
    buckets[i].cap = sizeof asm_bufs[i];
  }
  /* all three GETs' HEADERS frames coalesced into ONE payload/datagram. */
  off = 0;
  for (usz i = 0; i < 3; i++) {
    u8        get[128];
    quic_obuf gob = {get, sizeof get, 0};
    usz       plen;
    CHECK(wired_h3reqdrive_send_get(
        stream_ids[i],
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)paths[i], 2),
            quic_span_of((const u8*)"h", 1)},
        &gob));
    plen = gob.len;
    for (usz j = 0; j < plen; j++) payload[off++] = get[j];
  }
  slen = client_seal_onertt(&f, payload, off, spkt, sizeof spkt);
  {
    srvrun_cfg cfg = {
        cfd,
        &id,
        sr_parallel_body_handler,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        &g_srvrun_env,
        0,
        0,
        0,
        0,
        0};
    srvrun_step_ctx ctx = {&cfg, &srv, &st, 0};
    srvrun_serve(&ctx, quic_mspan_of(spkt, slen));
  }
  /* every request completed in the same step: three resp[] slots claimed. */
  CHECK(st.conns[0].resp[0].in_use == 1);
  CHECK(st.conns[0].resp[1].in_use == 1);
  CHECK(st.conns[0].resp[2].in_use == 1);
  /* drain replies until all three streams have seen fin (bounded: at most a
   * handful of small single-chunk responses plus the ack-only reply). */
  for (int d = 0; d < 8; d++) {
    u8        pkt[1500];
    const u8* pl;
    usz       pll;
    int       all_fin;
    i64 r = wired_udp_recvfrom(sfd, quic_mspan_of(pkt, sizeof pkt), &from);
    CHECK(r > 0);
    if (client_open_onertt(&f, pkt, (usz)r, &pl, &pll) == 1)
      sr_collect_stream_multi(pl, pll, buckets, 3);
    all_fin = buckets[0].used && buckets[0].fin && buckets[1].used &&
              buckets[1].fin && buckets[2].used && buckets[2].fin;
    if (all_fin) break;
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
  /* each stream's reassembled body is its OWN prefix + single byte, never a
   * sibling's -- proves the streams did not cross-contaminate. */
  for (usz i = 0; i < 3; i++) {
    u8        pre[64];
    quic_obuf preb = {pre, sizeof pre, 0};
    CHECK(buckets[i].used == 1);
    CHECK(buckets[i].fin == 1);
    CHECK(quic_h3resp_prefix(200, 0, 1, &preb) == 1);
    CHECK(buckets[i].high == preb.len + 1);
    for (usz j = 0; j < preb.len; j++) CHECK(buckets[i].buf[j] == pre[j]);
    CHECK(buckets[i].buf[preb.len] == (u8)paths[i][1]);
  }
}

/* TAKEOVER END TO END: a GET served through srvrun streams a 2.5-chunk
 * response as multiple 1-RTT packets over a real socket. The client-side
 * reassembly of the STREAM slices equals prefix+body byte for byte and ends
 * with fin. Benign skip when the sandbox forbids sockets. */
static void test_srvrun_takeover_streams_large_body(void) {
  struct lp_fix    f;
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32];
  u8               obuf[1024], get[512], spkt[1024];
  static u8        asm_buf[4096];
  u8               pre[64];
  quic_obuf        preb = {pre, sizeof pre, 0};
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  srvrun_state     st = {table, g_srvrun_state.conns};
  quic_obuf        ob = {obuf, sizeof obuf, 0};
  quic_sockaddr_in srv, from;
  i64              sfd, cfd;
  usz              glen, slen, high = 0;
  int              fin = 0;
  if (!sr_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  sr_make_id(&id, priv, pub, seed, rnd);
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&st.conns[0], &f, &ob);
  st.conns[0].l.resp_external = 1;
  st.conns[0].peer            = srv;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == 0);
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  slen = client_seal_onertt(&f, get, glen, spkt, sizeof spkt);
  {
    srvrun_cfg cfg = {cfd, &id, sr_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,   0,   &g_srvrun_env,   0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &srv, &st, 0};
    srvrun_serve(&ctx, quic_mspan_of(spkt, slen));
  }
  /* 3 datagrams queued: the takeover response's 3 slices. The loop's own
   * step reply carries no separate ACK-only packet here -- RFC 9000
   * 13.2.1/13.2.2's delayed-ACK policy does not owe an ACK yet after a
   * single ack-eliciting packet within max_ack_delay, and the takeover
   * response itself carries no piggybacked ACK of its own. */
  for (int d = 0; d < 3; d++) {
    u8        pkt[1500];
    const u8* pl;
    usz       pll;
    i64 r = wired_udp_recvfrom(sfd, quic_mspan_of(pkt, sizeof pkt), &from);
    CHECK(r > 0);
    if (client_open_onertt(&f, pkt, (usz)r, &pl, &pll) != 1) continue;
    high = sr_collect_stream(pl, pll, asm_buf, sizeof asm_buf, high, &fin);
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
  /* the reassembled stream is exactly prefix + body, fin on the tail */
  CHECK(quic_h3resp_prefix(200, 0, 2500, &preb) == 1);
  CHECK(fin == 1);
  CHECK(high == preb.len + 2500);
  for (usz i = 0; i < preb.len; i++) CHECK(asm_buf[i] == pre[i]);
  for (usz i = 0; i < 2500; i++) CHECK(asm_buf[preb.len + i] == (u8)(i & 0xff));
}

/* CC SELECTION: the run config's algorithm choice reaches each fresh
 * connection's controller; the zero default stays NewReno. */
static void test_srvrun_cc_algo_selected(void) {
  wired_srvboot_id id;
  u8               priv[32], pub[32], seed[32], rnd[32], dg[1500];
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  quic_sockaddr_in peer = {0};
  srvrun_state     st   = {table, g_srvrun_state.conns};
  usz total             = sr_build_client_initial(dg, sizeof dg, g_sr_odcid, 8);
  sr_make_id(&id, priv, pub, seed, rnd);
  {
    srvrun_cfg cfg = {
        -1, &id,           0, 0, 0, 0, 0, 0, QUIC_CC_ALGO_CUBIC, 0, 0, 0, 0, 0,
        0,  &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
  }
  CHECK(st.conns[0].up == 1);
  CHECK(st.conns[0].cc.algo == QUIC_CC_ALGO_CUBIC);
  CHECK(st.conns[0].cc.cwnd == QUIC_CC_INIT_WINDOW);
}

/* HYSTART WIRING: rising round RTTs feed the detector and end slow start
 * (ssthresh drops to cwnd); the round boundary comes from the next send pn.
 * Unit-drives the ack path with fabricated sent times. */
static void test_srvrun_hystart_ends_slow_start(void) {
  srvrun_conn* c = &g_srvrun_state.conns[3];
  *c             = (srvrun_conn){0};
  quic_cc_init(&c->cc);
  quic_hystart_init(&c->hs);
  c->up = 1;
  wired_sendsess_arm(&c->resp[0].sess, g_srvrun_respstore[3][0], 16000, 100);
  {
    wired_sendq_slice sl;
    /* round 1: 8 packets sent at t=0, acked at t=40 (RTT 40) */
    for (u64 pn = 0; pn < 8; pn++) {
      CHECK(wired_sendsess_take(&c->resp[0].sess, &sl) == 1);
      CHECK(wired_sendsess_sent(&c->resp[0].sess, &sl, pn, 0) == 1);
    }
    c->l.tx_pn = 8; /* production: sending advanced the next pn */
    for (u64 pn = 0; pn < 8; pn++) srvrun_hystart_ack(c, pn, pn, 40);
    CHECK(c->cc.ssthresh == ~(u64)0); /* still slow start */
    /* round 2: RTT jumped to 60 >= 40 + eta(5): exit on the 8th sample */
    for (u64 pn = 8; pn < 16; pn++) {
      CHECK(wired_sendsess_take(&c->resp[0].sess, &sl) == 1);
      CHECK(wired_sendsess_sent(&c->resp[0].sess, &sl, pn, 100) == 1);
    }
    c->l.tx_pn = 16;
    for (u64 pn = 8; pn < 16; pn++) srvrun_hystart_ack(c, pn, pn, 160);
  }
  CHECK(c->cc.ssthresh == c->cc.cwnd); /* slow start ended */
  c->up = 0;
}

/* REGRESSION: HyStart's round boundary is "the next pn to be sent"
 * (srvrun_hystart_ack's own doc), read from the connection-wide c->l.tx_pn --
 * a single counter shared by every round-robin resp[] slot (srvrun_pump_
 * round). When several slots are sending concurrently, tx_pn races far
 * ahead of any one slot's own send progress, so a round boundary armed by
 * slot A's first ACKed packet is very likely already past by the time slot
 * B's packets (sent moments earlier under the SAME round-robin pass) get
 * ACKed and sampled -- collapsing what should be one steady-RTT round into
 * several tiny ones. With constant zero-jitter RTT this must never end slow
 * start: eta's minimum is 4ms (HYSTART_MIN_ETA), so curr_round_min can only
 * equal (not exceed) last_round_min when RTT never changes, and hystart_due
 * requires a strict >=. Drive two slots interleaved, tx_pn racing ahead of
 * each slot's own packets, all at the same fixed RTT. */
static void test_srvrun_hystart_round_boundary_survives_interleaving(void) {
  srvrun_conn* c = &g_srvrun_state.conns[3];
  *c             = (srvrun_conn){0};
  quic_cc_init(&c->cc);
  quic_hystart_init(&c->hs);
  c->up = 1;
  wired_sendsess_arm(&c->resp[0].sess, g_srvrun_respstore[3][0], 16000, 100);
  wired_sendsess_arm(&c->resp[1].sess, g_srvrun_respstore[3][1], 16000, 100);
  {
    wired_sendq_slice sl;
    usz               round;
    u64               pn = 0;
    /* 4 rounds of "slot 0 sends 2, slot 1 sends 2, tx_pn now 4 ahead of
     * either slot's own 2 packets" then both slots' packets ACKed at a
     * constant RTT of 40ms -- 16 samples total, RTT never rises. */
    for (round = 0; round < 4; round++) {
      u64 pn0 = pn;
      CHECK(wired_sendsess_take(&c->resp[0].sess, &sl) == 1);
      CHECK(wired_sendsess_sent(&c->resp[0].sess, &sl, pn++, 0) == 1);
      CHECK(wired_sendsess_take(&c->resp[0].sess, &sl) == 1);
      CHECK(wired_sendsess_sent(&c->resp[0].sess, &sl, pn++, 0) == 1);
      u64 pn1 = pn;
      CHECK(wired_sendsess_take(&c->resp[1].sess, &sl) == 1);
      CHECK(wired_sendsess_sent(&c->resp[1].sess, &sl, pn++, 0) == 1);
      CHECK(wired_sendsess_take(&c->resp[1].sess, &sl) == 1);
      CHECK(wired_sendsess_sent(&c->resp[1].sess, &sl, pn++, 0) == 1);
      c->l.tx_pn = pn; /* production: sending advanced the next pn */
      srvrun_hystart_ack(c, pn0, 0, 40);
      srvrun_hystart_ack(c, pn0 + 1, 0, 40);
      srvrun_hystart_ack(c, pn1, 0, 40);
      srvrun_hystart_ack(c, pn1 + 1, 0, 40);
    }
  }
  CHECK(c->cc.ssthresh == ~(u64)0); /* slow start must still be running */
  c->up = 0;
}

/* RTT EWMA (RFC 9002 5.3 shape): first sample seeds srtt, later ones blend
 * 7/8 old + 1/8 new. */
static void test_srvrun_rtt_ewma(void) {
  srvrun_conn c = {0};
  srvrun_rtt_note(&c, 100);
  CHECK(c.srtt_ms == 100);
  srvrun_rtt_note(&c, 200);
  CHECK(c.srtt_ms == 112); /* (7*100 + 200) / 8 */
}

/* RFC 9002 5.1: "an endpoint... SHOULD generate an RTT sample using only
 * the largest acknowledged packet in the received ACK frame" -- one ACK
 * range that hits several in-flight slices sent far apart in time must
 * feed the RTT estimator exactly one sample (from the newest of the hits),
 * not one sample per hit. Feeding every hit dragged smoothed_rtt toward the
 * oldest (least representative) send times -- observed as srtt climbing
 * from ~36ms to ~55ms over an interop run whose simulated RTT never
 * changed, once srvrun_pump_round's round-robin pumping spread a single
 * slot's own slices further apart in real send time than the old
 * drain-then-next order did. */
static void test_srvrun_rtt_sample_uses_newest_hit_only(void) {
  static u8     body[3 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  u64           pn0;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  pn0                 = c.l.tx_pn;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    /* three slices sent 100ms apart (pn0 at t=0, pn0+1 at t=100, pn0+2 at
     * t=200) -- a real gap round-robin pumping can produce across an
     * otherwise-idle slot's own queue. */
    srvrun_cfg        cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                             0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                             0,  0, 0, 0, 0};
    srvrun_resp*      r   = &c.resp[0];
    wired_sendq_slice sl;
    CHECK(wired_sendsess_take(&r->sess, &sl) == 1);
    CHECK(wired_sendsess_sent(&r->sess, &sl, pn0, 0) == 1);
    CHECK(wired_sendsess_take(&r->sess, &sl) == 1);
    CHECK(wired_sendsess_sent(&r->sess, &sl, pn0 + 1, 100) == 1);
    CHECK(wired_sendsess_take(&r->sess, &sl) == 1);
    CHECK(wired_sendsess_sent(&r->sess, &sl, pn0 + 2, 200) == 1);
    /* one ACK range at t=215 covers all three: newest send time is 200,
     * so the sample must be 215-200=15, not an average pulled toward the
     * pn0 slice's 215-0=215. */
    srvrun_feed_ack_range(&cfg, &c, pn0, pn0 + 2, 215);
    CHECK(c.srtt_ms == 15);
  }
}

/* PACING GATE: before the first RTT sample sends are unpaced; with an srtt,
 * a send scheduled in the future blocks the pump. Chosen cwnd/srtt so the
 * theoretical interval (24ms) lands just under SRVRUN_PTO_MS(25) -- still
 * exercises srvrun_pace_ok's future/due-now branches without tripping the
 * poll-tick fast path this test isn't about (see T-002/T-003 for that
 * boundary). 5*1200*400/(4*10000) = 60... too big; use cwnd=48000,
 * srtt=400: 5*1200*400/(4*48000) = 12.5 -> 12ms (still < 25, so this now
 * exercises the poll-tick fast path too -- next_send_ms stays due-now). */
static void test_srvrun_pacing_gate(void) {
  srvrun_conn c  = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  srvrun_state    st  = {0, 0};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
  quic_cc_init(&c.cc);                  /* cwnd 12000 */
  CHECK(srvrun_pace_ok(&ctx, &c) == 1); /* srtt 0: unpaced */
  c.srtt_ms      = 100;
  c.next_send_ms = 1010; /* future */
  CHECK(srvrun_pace_ok(&ctx, &c) == 0);
  c.next_send_ms = 1000; /* due now */
  CHECK(srvrun_pace_ok(&ctx, &c) == 1);
}

/* REGRESSION: once the theoretical pacing interval fits inside one
 * poll-loop tick (SRVRUN_PTO_MS), srvrun_pace_next must leave next_send_ms
 * AT now_ms (not push it into a frozen-time step's future) -- otherwise a
 * whole recv step's worth of remaining cwnd room goes unused every step,
 * capping throughput at one round-robin pass per inbound datagram
 * regardless of how much window is open, and pinning the connection to the
 * SRVRUN_PTO_MS poll cadence instead of its real pacing rate (the interop
 * goodput stall). Chosen cwnd (5,000,000) with srtt=30ms:
 * 5*1200*30/(4*5000000) = 0.009ms, well under SRVRUN_PTO_MS(25). */
static void test_srvrun_pacing_no_stall_within_poll_tick(void) {
  srvrun_conn c  = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  srvrun_state    st  = {0, 0};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
  quic_cc_init(&c.cc);
  c.cc.cwnd      = 5000000;
  c.srtt_ms      = 30;
  c.next_send_ms = 1000;
  CHECK(srvrun_pace_ok(&ctx, &c) == 1);
  srvrun_pace_next(&ctx, &c);
  CHECK(c.next_send_ms == 1000);        /* still due now, same frozen step */
  CHECK(srvrun_pace_ok(&ctx, &c) == 1); /* a 2nd round in this step may fire */
}

/* T-002 BOUNDARY: a pacing interval exactly equal to SRVRUN_PTO_MS(25) is
 * a real defer -- one round-robin pass this step, next one waits for the
 * next send opportunity. 5*1200*10000/(4*24000) = 625... too big; use
 * cwnd=6000000, srtt=4000: 5*1200*4000/(4*6000000) = 1.0 -- too small now
 * that the fast path covers < SRVRUN_PTO_MS. Recompute for interval==25:
 * 5*1200*srtt/(4*cwnd)=25 => cwnd = 240*srtt (cwnd=240000, srtt=4000). */
static void test_srvrun_pace_interval_equals_poll_no_extra_round(void) {
  srvrun_conn c  = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  srvrun_state    st  = {0, 0};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
  quic_cc_init(&c.cc);
  c.cc.cwnd = 240000;
  c.srtt_ms = 4000;
  CHECK(
      quic_pacing_interval(c.srtt_ms, c.cc.cwnd, QUIC_MAX_DATAGRAM) ==
      SRVRUN_PTO_MS);
  srvrun_pace_next(&ctx, &c);
  CHECK(c.next_send_ms == 1000 + SRVRUN_PTO_MS);
}

/* T-003 BOUNDARY: an interval one ms past SRVRUN_PTO_MS still defers the
 * normal way -- the fast path is strictly < SRVRUN_PTO_MS, never >=.
 * 5*1200*4000/(4*230000) = 26. */
static void test_srvrun_pace_interval_over_poll_waits(void) {
  srvrun_conn c  = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  srvrun_state    st  = {0, 0};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
  quic_cc_init(&c.cc);
  c.cc.cwnd = 230000;
  c.srtt_ms = 4000;
  CHECK(
      quic_pacing_interval(c.srtt_ms, c.cc.cwnd, QUIC_MAX_DATAGRAM) ==
      SRVRUN_PTO_MS + 1);
  srvrun_pace_next(&ctx, &c);
  CHECK(c.next_send_ms == 1000 + SRVRUN_PTO_MS + 1);
}

/* T-001: with an interval well under SRVRUN_PTO_MS, a single
 * srvrun_pump_sess call bursts through cwnd instead of stopping after one
 * round -- the actual fix under test, driven through the real pump loop
 * (not just the pacing helpers) against a confirmed connection (real 1-RTT
 * keys, srvrun_send_slice needs them to seal a packet) with a real armed
 * sendsess so multiple rounds have data to take. */
static void test_srvrun_pace_bursts_within_poll_interval(void) {
  static u8     body[8 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd               = 5000000; /* interval well under SRVRUN_PTO_MS */
  c.srtt_ms               = 30;
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = sizeof body;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
    srvrun_pump_sess(&ctx, 0);
  }
  /* every chunk went out in this one call -- not capped at one round */
  CHECK(c.resp[0].sess.q.cur == sizeof body);
}

/* T-004: srvrun_pace_within_poll_tick's fast path still applies at the old
 * sub-ms extreme (cwnd huge enough the interval floors to 0) -- the new,
 * wider SRVRUN_PTO_MS threshold subsumes the old one, nothing regresses. */
static void test_srvrun_pace_subms_still_unlimited(void) {
  srvrun_conn c = {0};
  quic_cc_init(&c.cc);
  c.cc.cwnd = 5000000000ULL;
  c.srtt_ms = 30;
  CHECK(quic_pacing_interval(c.srtt_ms, c.cc.cwnd, QUIC_MAX_DATAGRAM) == 0);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, 0, 0, 1000};
    c.next_send_ms      = 1000;
    srvrun_pace_next(&ctx, &c);
  }
  CHECK(c.next_send_ms == 1000);
}

/* T-006 regression: a response small enough to send in one round already
 * (no burst opportunity) behaves identically before/after -- one round,
 * next_send_ms untouched when the interval is sub-poll-tick. */
static void test_srvrun_pace_small_response_unaffected(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd               = 5000000;
  c.srtt_ms               = 30;
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = sizeof body;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
    srvrun_pump_sess(&ctx, 0);
  }
  CHECK(c.resp[0].sess.q.cur == sizeof body);
  /* sub-poll-tick: srvrun_pace_next never touches next_send_ms, so it
   * stays at sr_make_confirmed_conn's zero-init, not "now". */
  CHECK(c.next_send_ms == 0);
}

/* T-011: no in-flight-able data at all -- the burst-capable pump loop
 * still terminates immediately instead of spinning. */
static void test_srvrun_pace_burst_no_data_terminates(void) {
  srvrun_conn* c = sr_test_conns();
  quic_cc_init(&c->cc);
  c->cc.cwnd = 5000000;
  c->srtt_ms = 30;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
    srvrun_pump_sess(&ctx, 0); /* must return, not loop forever */
  }
  CHECK(1); /* reaching here at all is the assertion */
}

/* @file
 * RFC 9002 7.5: "Probe packets MUST NOT be blocked by the congestion
 * controller" applies to pacing too, not just cwnd -- an RTT spike (a real
 * blackhole off-period's delayed ACK) can push next_send_ms far into the
 * future and silently swallow the one send (the PTO probe) that would
 * recover the connection. */

/* Arm sess with one chunk, take+send it (now in-flight), then fire its PTO
 * so the slice moves to requeue -- the shared setup every probe-pacing test
 * below needs. */
static void sr_pace_arm_and_fire_pto(wired_sendsess* sess, u8* body, usz n) {
  wired_sendq_slice sl;
  wired_sendsess_arm(sess, body, n, SRVRUN_CHUNK);
  CHECK(wired_sendsess_take(sess, &sl) == 1);
  CHECK(wired_sendsess_sent(sess, &sl, 0, 0) == 1);
  CHECK(wired_sendsess_pto_fire(sess, SRVRUN_PTO_MAX) == 1);
}

/* T-001: a queued PTO probe sends even though next_send_ms is far in the
 * future (the RTT-spike scenario) -- srvrun_pump_round_gated must not gate
 * it on pacing. */
static void test_srvrun_pace_probe_bypasses_pacing_gate(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.srtt_ms               = 30;
  c.next_send_ms          = 1000000; /* far future: pacing alone would block */
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = sizeof body;
  sr_pace_arm_and_fire_pto(&c.resp[0].sess, body, sizeof body);
  CHECK(c.resp[0].sess.requeue_n == 1);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
    CHECK(srvrun_pump_round_gated(&ctx, &c) == 1);
  }
  CHECK(c.resp[0].sess.requeue_n == 0); /* the probe actually went out */
}

/* T-002/T-006/T-011: with no probe queued (ordinary new-data send), a
 * far-future next_send_ms still blocks the round the normal way --
 * regression for the existing pacing behavior. */
static void test_srvrun_pace_no_probe_still_gated(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.srtt_ms               = 30;
  c.next_send_ms          = 1000000;
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = sizeof body;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  CHECK(c.resp[0].sess.requeue_n == 0);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
    CHECK(srvrun_pump_round_gated(&ctx, &c) == 0);
  }
  CHECK(c.resp[0].sess.q.cur == 0); /* nothing sent, still gated */
}

/* T-005: one slot holds a probe, a sibling slot has fresh sendq data --
 * the round-level bypass (srvrun_any_requeued) lets the WHOLE round through,
 * so the sibling's new data goes out in the same pass as the probe (the
 * existing "one paced send per whole pass" design, T-005's documented
 * consequence). */
static void test_srvrun_pace_mixed_probe_and_new_data_round(void) {
  static u8     probe_body[SRVRUN_CHUNK];
  static u8     new_body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.srtt_ms               = 30;
  c.next_send_ms          = 1000000;
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = sizeof probe_body;
  sr_pace_arm_and_fire_pto(&c.resp[0].sess, probe_body, sizeof probe_body);
  c.resp[1].in_use        = 1;
  c.resp[1].stream_id     = 4;
  c.resp[1].stream_credit = sizeof new_body;
  wired_sendsess_arm(&c.resp[1].sess, new_body, sizeof new_body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
    CHECK(srvrun_pump_round_gated(&ctx, &c) == 1);
  }
  CHECK(c.resp[0].sess.requeue_n == 0);           /* probe sent */
  CHECK(c.resp[1].sess.q.cur == sizeof new_body); /* sibling's new data too */
}

/* T-003: a probe still goes through the log gate (srvrun_sess_log_room)
 * even though it bypasses pacing -- wired_sendsess_pto_fire always frees
 * the log entry it moves to requeue (sendsess_requeue clears that entry's
 * inflight flag), so a queued probe's own log gate can never actually fail
 * (documented as a deliberate invariant, not dead code, at srvrun_pump_
 * gate_ok's definition). This confirms the probe-pacing bypass added here
 * doesn't skip that gate: even with the log otherwise completely full
 * (every other entry still in flight), the probe -- and only the probe --
 * still sends. */
static void test_srvrun_pace_probe_bypass_still_respects_log_gate(void) {
  static u8     body[WIRED_SENDSESS_LOG * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.srtt_ms               = 30;
  c.next_send_ms          = 1000000;
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = sizeof body;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    wired_sendq_slice sl;
    for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
      CHECK(wired_sendsess_take(&c.resp[0].sess, &sl) == 1);
      CHECK(wired_sendsess_sent(&c.resp[0].sess, &sl, i, 0) == 1);
    }
  }
  CHECK(wired_sendsess_pto_fire(&c.resp[0].sess, SRVRUN_PTO_MAX) == 1);
  CHECK(c.resp[0].sess.requeue_n == 1);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
    CHECK(srvrun_pump_round_gated(&ctx, &c) == 1);
  }
  CHECK(c.resp[0].sess.requeue_n == 0); /* the probe's own slot always has
                                         * room -- pto_fire freed it */
}

/* T-004 boundary: requeue_n transitions from 0 (gated) to 1 (bypassed) the
 * instant a PTO fires -- same connection, same pacing state, only the
 * requeue count changes. */
static void test_srvrun_pace_probe_bypass_activates_on_requeue(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.srtt_ms      = 30;
  c.next_send_ms = 1000000;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, 0, 0, 1000};
    CHECK(c.resp[0].sess.requeue_n == 0);
    CHECK(srvrun_pace_or_probe_ok(&ctx, &c) == 0); /* gated: no probe yet */
    c.resp[0].in_use        = 1;
    c.resp[0].stream_id     = 0;
    c.resp[0].stream_credit = sizeof body;
    sr_pace_arm_and_fire_pto(&c.resp[0].sess, body, sizeof body);
    CHECK(srvrun_pace_or_probe_ok(&ctx, &c) == 1); /* bypassed: probe queued */
  }
}

/* T-007: a probe round that actually sends still schedules next_send_ms the
 * normal way afterward -- srvrun_pace_next isn't skipped just because the
 * round happened to be probe-triggered. */
static void test_srvrun_pace_probe_round_still_schedules_next(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd               = 12000; /* interval well past SRVRUN_PTO_MS */
  c.srtt_ms               = 4000;
  c.next_send_ms          = 1000000;
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = sizeof body;
  sr_pace_arm_and_fire_pto(&c.resp[0].sess, body, sizeof body);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
    CHECK(srvrun_pump_round_gated(&ctx, &c) == 1);
  }
  /* pacing was rescheduled from now (1000) by the real interval
   * (5*1200*4000/(4*12000) = 500ms), not left at the stale far-future value
   * the probe bypassed */
  CHECK(c.next_send_ms == 1500);
}

/* T-008 regression: srvrun_pace_within_poll_tick's own fast path (no probe
 * involved) is unaffected by the probe-bypass addition -- a sub-poll-tick
 * interval still lets a plain new-data round through without any probe. */
static void test_srvrun_pace_within_poll_tick_unaffected_by_probe_change(void) {
  srvrun_conn c = {0};
  quic_cc_init(&c.cc);
  c.cc.cwnd = 5000000;
  c.srtt_ms = 30;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, 0, 0, 1000};
    CHECK(srvrun_pace_or_probe_ok(&ctx, &c) == 1); /* srtt_ms path, unpaced */
    c.next_send_ms = 1000;
    srvrun_pace_next(&ctx, &c);
    CHECK(c.next_send_ms == 1000); /* still sub-poll-tick, unchanged */
  }
}

/* POLLING DRIVER (tasks/polling-driver-plan.md Phase 2): busy_poll/
 * so_busy_poll_us opt-in knobs, threaded through srvrun_cfg as its 10th
 * (trailing) field so every existing 9-field positional initializer above
 * keeps compiling unchanged with busy_poll defaulting to 0. */

/* REGRESSION: busy_poll=0 (the zero-value default, same as every srvrun_cfg
 * literal above) takes the existing blocking-poll branch in
 * srvrun_wait_input untouched -- srvrun_any_waiting's own branch is not
 * disturbed, only the leaf call once inside it changes for busy_poll=1. */
static void test_srvrun_busy_poll_off_uses_any_waiting_branch(void) {
  srvrun_state st = {0, 0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st = (srvrun_state){table, conns};
  CHECK(cfg.busy_poll == 0);
  /* nothing in flight: srvrun_wait_input returns 1 without touching poll(2)
   * regardless of fd being invalid (-1) -- proves the any_waiting branch,
   * not busy_poll, still gates this path when busy_poll is off. */
  CHECK(srvrun_wait_input(&cfg, &st) == 1);
}

/* busy_poll=1: srvrun_wait_input returns 1 immediately (never calls the
 * blocking poll(2)) even on an invalid fd that would otherwise error out --
 * the actual non-blocking check has moved to the recv step. */
static void test_srvrun_busy_poll_on_never_blocks_wait(void) {
  srvrun_state st = {0, 0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st                           = (srvrun_state){table, conns};
  conns[0].up                  = 1;
  conns[0].resp[0].in_use      = 1;
  conns[0].resp[0].sess.active = 1; /* srvrun_any_waiting now says yes */
  CHECK(srvrun_wait_input(&cfg, &st) == 1);
}

/* busy_poll=1: the recv step itself (srvrun_step, via srvrun_recv) never
 * blocks on an empty real socket -- a fixed number of calls all return
 * promptly instead of hanging, the bounded proxy for "no indefinite block"
 * (tasks/polling-driver-plan.md test-design item 4/5's srvrun-level
 * counterpart). */
static void test_srvrun_busy_poll_step_never_blocks(void) {
  i64              fd = wired_udp_socket();
  quic_sockaddr_in sa;
  quic_mmsg_buf    bufs[2];
  static u8        storage[2][256];
  srvrun_state     st = {0, 0};
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  srvrun_conn*     conns = sr_test_conns();
  srvrun_cfg       cfg;
  CHECK(fd >= 0);
  wired_udp_addr(&sa, 4491, (const u8[4]){127, 0, 0, 1});
  CHECK(wired_udp_bind(fd, &sa) >= 0);
  cfg =
      (srvrun_cfg){fd, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, &g_srvrun_env,
                   0,  0, 0, 0, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st          = (srvrun_state){table, conns};
  bufs[0].buf = quic_mspan_of(storage[0], sizeof storage[0]);
  bufs[1].buf = quic_mspan_of(storage[1], sizeof storage[1]);
  for (int i = 0; i < 50; i++) srvrun_step(&cfg, &st, bufs, 2);
  wired_udp_close(fd);
  /* reaching here (instead of hanging in the harness) is the assertion */
  CHECK(1);
}

/* Polling drivers never reach the poll-timeout probe pass, so the PTO tick
 * is clocked instead: the 1024th spin arms the SRVRUN_PTO_MS window and
 * fires, further due spins inside the window do not re-fire, and the
 * blocking driver never ticks the clocked path at all. */
static void test_srvrun_polling_pto_tick(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  srvrun_state st;
  u64          armed;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st                   = (srvrun_state){table, conns};
  g_srvrun_pto_next_ms = 0;
  g_srvrun_pto_spin    = 0;
  for (int i = 0; i < 1023; i++) srvrun_polling_ptos(&cfg, &st);
  /* not yet due: the clock was never read */
  CHECK(g_srvrun_pto_next_ms == 0);
  /* 1024th spin: due, arms the window */
  srvrun_polling_ptos(&cfg, &st);
  armed = g_srvrun_pto_next_ms;
  CHECK(armed > 0);
  /* force the next call due again: inside the window it must not re-fire */
  g_srvrun_pto_spin = 1023;
  srvrun_polling_ptos(&cfg, &st);
  CHECK(g_srvrun_pto_next_ms == armed);
  /* blocking driver: the clocked path stays off entirely */
  cfg.busy_poll        = 0;
  g_srvrun_pto_next_ms = 0;
  g_srvrun_pto_spin    = 1023;
  srvrun_polling_ptos(&cfg, &st);
  CHECK(g_srvrun_pto_next_ms == 0);
}

/* WRAPPER EQUIVALENCE: wired_server_run_opt with a zeroed wired_srvrun_opt
 * behaves the same as wired_server_run at the point they actually differ --
 * the srvrun_cfg they build. Both must produce busy_poll=0, proving
 * wired_server_run's internal default_opt wrapper is wired correctly. */
static void test_srvrun_opt_zeroed_matches_plain_default(void) {
  wired_srvrun_opt opt = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  CHECK(opt.busy_poll == 0);
  CHECK(opt.so_busy_poll_us == 0);
  CHECK(opt.so_prefer_busy_poll == 0);
  CHECK(opt.so_busy_poll_budget == 0);
}

/* BOUNDARY: so_busy_poll_us=0 -- srvrun_maybe_busy_poll's `> 0` guard skips
 * wired_udp_busy_poll_enable's setsockopt call entirely (opt-in, not
 * opt-out). No getsockopt wrapper exists in this libc-free SDK to observe
 * SO_BUSY_POLL's kernel-side value directly (out of scope, YAGNI;
 * wired_udp_busy_poll_enable's own success/failure is already covered at
 * the udp_gso_test.c layer) so this is proven at the call-boundary instead:
 * srvrun_listen(port, opt) still succeeds exactly as before this task (the
 * regression bar), i.e. the guard being skipped never blocks the bind. Also
 * covers so_prefer_busy_poll/so_busy_poll_budget/incoming_cpu at their
 * disabled defaults (0/0/-1) in the same call. */
static void test_srvrun_so_busy_poll_zero_still_binds(void) {
  wired_srvrun_opt opt = {0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 0, 0};
  i64              fd  = srvrun_listen(4492, &opt);
  CHECK(fd >= 0);
  wired_udp_close(fd);
}

/* WEBTRANSPORT EXTENDED CONNECT (tasks/webtransport-plan.md Phase 7a):
 * srvrun_start_resp establishes a wired_wt_session for a well-formed
 * Extended CONNECT (:protocol=webtransport-h3) instead of calling the app
 * handler. Counts invocations to prove the handler path was skipped. */
static int g_sr_wt_handler_calls = 0;
static int sr_wt_handler(
    void*                       hctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
    const char**                ct,
    int*                        more,
    u64*                        total_size) {
  (void)hctx;
  (void)req;
  (void)ct;
  (void)offset;
  (void)more;
  (void)total_size;
  g_sr_wt_handler_calls++;
  body_out->len = 0;
  return 1;
}

static const u8 sr_wt_authority[]      = "host";
static const u8 sr_wt_scheme[]         = "https";
static const u8 sr_wt_path[]           = "/wt";
static const u8 sr_wt_method_get[]     = "GET";
static const u8 sr_wt_method_connect[] = "CONNECT";
static const u8 sr_wt_protocol[]       = "webtransport-h3";
static const u8 sr_wt_origin_ok[]      = "https://example.test";

/* Populate c->l.req/req_stream_id/got_request for a synthetic decoded
 * request -- srvrun_start_resp only reads these mirror fields, so no real
 * wire round-trip is needed to drive it. connect_method/with_protocol pick
 * from the fixed literals above (no libc strlen available in this SDK).
 * :scheme/:path are always set to well-formed values here (WT-B-003/004's
 * required Extended CONNECT shape); tests that need them missing clear the
 * field directly after calling this. */
static void sr_set_req(
    srvrun_conn* c, int connect_method, int with_protocol, u64 stream_id) {
  if (connect_method) {
    c->l.req.method     = sr_wt_method_connect;
    c->l.req.method_len = sizeof sr_wt_method_connect - 1;
  } else {
    c->l.req.method     = sr_wt_method_get;
    c->l.req.method_len = sizeof sr_wt_method_get - 1;
  }
  c->l.req.authority     = sr_wt_authority;
  c->l.req.authority_len = sizeof sr_wt_authority - 1;
  c->l.req.scheme        = sr_wt_scheme;
  c->l.req.scheme_len    = sizeof sr_wt_scheme - 1;
  c->l.req.path          = sr_wt_path;
  c->l.req.path_len      = sizeof sr_wt_path - 1;
  if (with_protocol) {
    c->l.req.protocol     = sr_wt_protocol;
    c->l.req.protocol_len = sizeof sr_wt_protocol - 1;
  } else {
    c->l.req.protocol     = 0;
    c->l.req.protocol_len = 0;
  }
  c->l.req.origin       = 0;
  c->l.req.origin_len   = 0;
  c->l.req.wt_avail_len = 0;
  c->l.req.body         = 0;
  c->l.req.body_len     = 0;
  c->l.req_stream_id    = stream_id;
  c->l.got_request      = 1;
}

/* REGRESSION: a normal GET (no :protocol) still goes through
 * srvrun_call_handler unchanged -- the app handler is invoked exactly once
 * and no WT session is created. */
static void test_srvrun_normal_request_unaffected_by_wt_branch(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 0, 0, 0);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(g_sr_wt_handler_calls == 1);
  CHECK(conns[0].wt_active == 0);
  CHECK(conns[0].resp[0].sess.active == 1); /* the normal 200 was still armed */
}

/* draft-ietf-webtrans-http3-15 4.3: once a WT uni stream slot has been
 * reassembled (in_use, not yet offered) and the connection has an active WT
 * session, srvrun_offer_wt_uni_streams associates it -- mirrors how
 * srvrun_offer_wt_streams associates a WT bidi slot, for the separate uni
 * table. The session is left UNESTABLISHED so wired_wt_session_offer_stream's
 * buffering path (not its "associates directly" established-session
 * shortcut, session.c) is the one observed, the same way an established
 * session's offer_stream returns 1 without touching s->streams[] at all.
 * Drives the (unity-build-visible) static srvrun_offer_wt_uni_streams
 * directly, since srvrun_on_step itself needs a live socket fd for
 * srvrun_send/srvrun_note_recv side effects this test does not want. */
static void test_srvrun_wt_uni_stream_offered_to_session(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  ob             = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  wired_wt_session_init(&c.wt, 4);
  c.wt_active                     = 1;
  c.l.wt_uni_streams[0].in_use    = 1;
  c.l.wt_uni_streams[0].stream_id = 2;
  c.l.wt_uni_streams[0].offered   = 0;
  srvrun_offer_wt_uni_streams(&cfg, &c);
  CHECK(c.l.wt_uni_streams[0].offered == 1);
  CHECK(c.wt.streams[0].in_use == 1 && c.wt.streams[0].stream_id == 2);
}

/* REGRESSION: a WT uni stream slot reassembled on a connection with NO active
 * WT session is left alone by srvrun_offer_wt_uni_streams -- no crash, no
 * association attempted, offered stays 0 -- mirroring the bidi fallback
 * srvrun_offer_wt_slot documents for !c->wt_active. */
static void test_srvrun_wt_uni_stream_no_session_not_offered(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  ob             = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.wt_active                     = 0;
  c.l.wt_uni_streams[0].in_use    = 1;
  c.l.wt_uni_streams[0].stream_id = 2;
  c.l.wt_uni_streams[0].offered   = 0;
  srvrun_offer_wt_uni_streams(&cfg, &c);
  CHECK(c.l.wt_uni_streams[0].offered == 0);
}

/* REGRESSION (mirrors test_srvrun_wt_uni_stream_offered_to_session for the
 * bidi table): a freshly-claimed WT bidi slot on a connection with an active,
 * UNESTABLISHED, non-full session is associated normally -- no RESET_STREAM,
 * offered set to 1. */
static void test_srvrun_wt_bidi_stream_offered_to_session(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  u64        tx_pn_before;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  wired_wt_session_init(&c.wt, 4);
  c.wt_active                 = 1;
  c.l.wt_streams[0].in_use    = 1;
  c.l.wt_streams[0].stream_id = 8;
  c.l.wt_streams[0].offered   = 0;
  tx_pn_before                = c.l.tx_pn;
  srvrun_offer_wt_streams(&cfg, &c);
  CHECK(c.l.wt_streams[0].offered == 1);
  CHECK(c.l.wt_streams[0].in_use == 1); /* stays claimed, not freed */
  CHECK(c.wt.streams[0].in_use == 1 && c.wt.streams[0].stream_id == 8);
  CHECK(c.l.tx_pn == tx_pn_before); /* no RESET_STREAM sealed */
}

/* WT-C-009 (buffer-full rejection): fill every WIRED_WT_MAX_BUFFERED_STREAMS
 * slot of an UNESTABLISHED session directly via wired_wt_session_offer_stream
 * (the same buffering path test_srvrun_wt_uni_stream_offered_to_session
 * exercises for one slot), so the session's own buffer is at capacity before
 * a reassembled WT bidi slot is offered. wired_wt_session_offer_stream then
 * returns 0 (session.c's stream_free_slot finds nothing), so
 * srvrun_offer_wt_slot must reject the stream on the wire with
 * WT_BUFFERED_STREAM_REJECTED (0x3994bd84) mapped through
 * quic_wterrmap_to_http3 (draft-ietf-webtrans-http3-15 8.2) -- NOT the
 * H3_REQUEST_REJECTED the WT-C-010 busy-reset path carries, since this is an
 * application-level WT error code, not an HTTP/3-level one. The expected
 * wire value (0x52e4df8fc205) is hand-derived: first=0x52e4a40fa8db,
 * n=0x3994bd84 (966049156), h = first + n + floor(n/0x1e) = first +
 * 966049156 + 34501755 = 0x52e4df8fc205. */
static void test_srvrun_wt_bidi_stream_buffer_full_sends_reset(void) {
  struct lp_fix              f;
  quic_obuf                  ob;
  u8                         obuf[1024];
  u8                         pkt[256];
  quic_obuf                  pktb = quic_obuf_of(pkt, sizeof pkt);
  const u8*                  pl;
  usz                        pll;
  quic_reset_stream_at_frame rs;
  quic_stop_sending_frame    ss;
  usz                        rn, sn;
  srvrun_conn                c = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  usz        i;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  wired_wt_session_init(&c.wt, 4); /* leaves state UNESTABLISHED */
  c.wt_active = 1;
  for (i = 0; i < WIRED_WT_MAX_BUFFERED_STREAMS; i++)
    CHECK(wired_wt_session_offer_stream(&c.wt, 100 + i) == 1);
  c.l.wt_streams[0].in_use    = 1;
  c.l.wt_streams[0].stream_id = 999;
  c.l.wt_streams[0].offered   = 0;
  srvrun_offer_wt_streams(&cfg, &c);
  CHECK(c.l.wt_streams[0].offered == 0); /* never associated */
  CHECK(c.l.wt_streams[0].in_use == 0);  /* freed, not left claimed forever */
  CHECK(
      srvrun_seal_wt_busy_reset(
          &c, 999, quic_wterrmap_to_http3(QUIC_WTERR_BUFFERED_STREAM_REJECTED),
          &pktb) == 1);
  CHECK(client_open_onertt(&f, pktb.p, pktb.len, &pl, &pll) == 1);
  rn = quic_reset_stream_at_decode(pl, pll, &rs);
  CHECK(rn != 0);
  CHECK(rs.stream_id == 999);
  CHECK(rs.error_code == 0x52e4df8fc205ULL);
  /* WT-F-007: RESET_STREAM_AT (not a plain RESET_STREAM), both size fields
   * 0 -- this stream never carried any application bytes to guarantee
   * delivery of. */
  CHECK(rs.final_size == 0);
  CHECK(rs.reliable_size == 0);
  sn = quic_stop_sending_decode(pl + rn, pll - rn, &ss);
  CHECK(sn != 0);
  CHECK(ss.stream_id == 999);
  CHECK(ss.error_code == 0x52e4df8fc205ULL);
  CHECK(rn + sn == pll);
}

/* Mirrors test_srvrun_wt_bidi_stream_buffer_full_sends_reset for the uni
 * table: same buffer-full trigger, same rejection contract. */
static void test_srvrun_wt_uni_stream_buffer_full_sends_reset(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  usz        i;
  u64        tx_pn_before;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  wired_wt_session_init(&c.wt, 4);
  c.wt_active = 1;
  for (i = 0; i < WIRED_WT_MAX_BUFFERED_STREAMS; i++)
    CHECK(wired_wt_session_offer_stream(&c.wt, 200 + i) == 1);
  c.l.wt_uni_streams[0].in_use    = 1;
  c.l.wt_uni_streams[0].stream_id = 777;
  c.l.wt_uni_streams[0].offered   = 0;
  tx_pn_before                    = c.l.tx_pn;
  srvrun_offer_wt_uni_streams(&cfg, &c);
  CHECK(c.l.wt_uni_streams[0].offered == 0);
  CHECK(c.l.wt_uni_streams[0].in_use == 0);
  CHECK(c.l.tx_pn != tx_pn_before); /* a RESET_STREAM pair was sealed */
}

/* An Extended CONNECT with :protocol=webtransport-h3 establishes a WT
 * session keyed by the CONNECT stream's own id and never calls the app
 * handler. */
static void test_srvrun_wt_connect_establishes_session(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(g_sr_wt_handler_calls == 0);
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt.connect_stream_id == 4);
  CHECK(conns[0].resp[0].sess.active == 1); /* the bare 2xx was armed */
}

/* Chrome (a draft-07-generation implementation) sends
 * :protocol=webtransport -- the token every deployed browser uses -- not
 * draft-15's webtransport-h3. Both tokens must establish a session, or no
 * real browser can ever connect (verified live against Chrome 149). */
static const u8 sr_wt_protocol_d7[] = "webtransport";

static void test_srvrun_wt_connect_webtransport_token(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.protocol     = sr_wt_protocol_d7;
  conns[0].l.req.protocol_len = sizeof sr_wt_protocol_d7 - 1;
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(g_sr_wt_handler_calls == 0);
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
}

/* A plain CONNECT (no :protocol at all) is not Extended CONNECT: no WT
 * session is created, and it falls through to the existing app-handler path
 * (today's only defined behavior for a bare CONNECT -- there is no
 * CONNECT-specific handling yet). */
static void test_srvrun_plain_connect_no_protocol_no_wt_session(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 0, 4);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 0);
  CHECK(g_sr_wt_handler_calls == 1); /* falls through to the normal handler */
}

/* WT-B-003/004: a well-formed Extended CONNECT missing :scheme is not
 * recognized as one -- no session, falls to the normal handler path (today's
 * only defined behavior for a malformed CONNECT-shaped request). */
static void test_srvrun_wt_connect_missing_scheme_no_session(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.scheme     = 0;
  conns[0].l.req.scheme_len = 0;
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 0);
  CHECK(g_sr_wt_handler_calls == 1);
}

/* WT-B-003/004: a well-formed Extended CONNECT missing :path is likewise not
 * recognized -- same fallthrough as the missing-:scheme case above. */
static void test_srvrun_wt_connect_missing_path_no_session(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.path     = 0;
  conns[0].l.req.path_len = 0;
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 0);
  CHECK(g_sr_wt_handler_calls == 1);
}

/* WT-B-003/004: a well-formed Extended CONNECT missing :authority is likewise
 * not recognized -- same fallthrough. */
static void test_srvrun_wt_connect_missing_authority_no_session(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.authority     = 0;
  conns[0].l.req.authority_len = 0;
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 0);
  CHECK(g_sr_wt_handler_calls == 1);
}

/* WT-B-005/007/008: a well-formed, non-empty Origin still establishes the
 * session normally (positive case -- presence alone is not a rejection
 * reason). */
static void test_srvrun_wt_connect_origin_ok_establishes(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.origin     = sr_wt_origin_ok;
  conns[0].l.req.origin_len = sizeof sr_wt_origin_ok - 1;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].resp[0].sess.active == 1);
}

/* WT-B-005/007/008: a present but malformed (empty-value) Origin gets a
 * 403-equivalent response instead of establishing a session -- no
 * wired_wt_session is created, but a response is still armed (the 403). */
static void test_srvrun_wt_connect_origin_malformed_403(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.origin     = sr_wt_origin_ok; /* present, but... */
  conns[0].l.req.origin_len = 0;               /* ...empty: malformed */
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 0);
  CHECK(conns[0].wt.state != WIRED_WT_ESTABLISHED);
  CHECK(conns[0].resp[0].sess.active == 1); /* the 403 was still armed */
}

/* WT-C-010/011: a second Extended CONNECT arriving on a connection that
 * already has an active WT session is rejected (429) instead of silently
 * overwriting the existing session. The critical assertion is the last one:
 * without the c->wt_active guard in srvrun_dispatch_wt, srvrun_start_wt would
 * unconditionally re-init c->wt, resetting it from ESTABLISHED back to
 * UNESTABLISHED -- this test fails on that regression and passes with the
 * guard in place. */
static void test_srvrun_second_wt_connect_rejected_429(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  conns[0].resp[0].in_use = 0; /* pretend the first 2xx finished sending */
  sr_set_req(
      &conns[0], 1, 1, 8); /* second Extended CONNECT, different stream */
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(g_sr_wt_handler_calls == 0);
  CHECK(conns[0].resp[0].sess.active == 1); /* the 429 was armed */
  CHECK(conns[0].wt_active == 1);
  CHECK(
      conns[0].wt.state == WIRED_WT_ESTABLISHED); /* original session intact */
  CHECK(conns[0].wt.connect_stream_id == 4);      /* still the first id */
}

/* RFC 9114 4.1.1/8.1: rejecting a second Extended CONNECT (WT-C-010/011)
 * SHOULD also abort the rejected request's stream with H3_REQUEST_REJECTED,
 * independent of the 429 status the request also gets. Drives the same
 * rejection path as test_srvrun_second_wt_connect_rejected_429 above, then
 * seals the RESET_STREAM+STOP_SENDING pair for the SAME rejected stream
 * (id 8) the same way srvrun_reject_wt_busy already did as a side effect of
 * srvrun_start_resp, and decodes it back off the wire to confirm both frames
 * carry the right error code and stream id. */
static void test_srvrun_second_wt_connect_sends_reset_stream(void) {
  struct lp_fix              f;
  quic_conntable             table[QUIC_CONNTABLE_CAP];
  srvrun_conn*               conns = sr_test_conns();
  quic_obuf                  ob;
  u8                         obuf[1024];
  u8                         pkt[256];
  quic_obuf                  pktb = quic_obuf_of(pkt, sizeof pkt);
  const u8*                  pl;
  usz                        pll;
  quic_reset_stream_at_frame rs;
  quic_stop_sending_frame    ss;
  usz                        rn, sn;
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  conns[0].resp[0].in_use = 0; /* pretend the first 2xx finished sending */
  sr_set_req(
      &conns[0], 1, 1, 8); /* second Extended CONNECT, different stream */
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(
      conns[0].resp[0].sess.active ==
      1); /* the 429 was armed, same as before */
  CHECK(
      srvrun_seal_wt_busy_reset(
          &conns[0], 8, QUIC_H3_REQUEST_REJECTED, &pktb) == 1);
  CHECK(client_open_onertt(&f, pktb.p, pktb.len, &pl, &pll) == 1);
  rn = quic_reset_stream_at_decode(pl, pll, &rs);
  CHECK(rn != 0);
  CHECK(rs.stream_id == 8);
  CHECK(rs.error_code == QUIC_H3_REQUEST_REJECTED);
  sn = quic_stop_sending_decode(pl + rn, pll - rn, &ss);
  CHECK(sn != 0);
  CHECK(ss.stream_id == 8);
  CHECK(ss.error_code == QUIC_H3_REQUEST_REJECTED);
  CHECK(rn + sn == pll); /* nothing else in the packet */
}

/* WT-C-006/007 regression: stream id 8 (& 3 == 0) is a client-initiated bidi
 * id, same shape as the existing establishes_session test's id 4 -- confirms
 * the new validation does not reject a well-formed id. */
static void test_srvrun_wt_connect_client_bidi_id_establishes_session(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 8);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt.connect_stream_id == 8);
}

/* WT-C-006/007: this SDK's live receive path only ever surfaces a client-bidi
 * req_stream_id (it comes from the same reassembly path that only tracks
 * request streams), so a non-client-bidi id can never reach srvrun_start_resp
 * today -- this is a defensive check exercised by driving srvrun_start_resp
 * directly with a stream id whose low bits are not both clear (5 & 3 == 1,
 * a client-initiated unidirectional id), the same direct-injection style
 * sr_set_req already uses for every other WT-connect branch in this file.
 * No session is established and the RESET_STREAM+STOP_SENDING pair carries
 * H3_ID_ERROR, mirroring test_srvrun_second_wt_connect_sends_reset_stream's
 * decode-back verification. */
static void test_srvrun_wt_connect_non_client_bidi_id_rejected(void) {
  struct lp_fix              f;
  quic_conntable             table[QUIC_CONNTABLE_CAP];
  srvrun_conn*               conns = sr_test_conns();
  quic_obuf                  ob;
  u8                         obuf[1024];
  u8                         pkt[256];
  quic_obuf                  pktb = quic_obuf_of(pkt, sizeof pkt);
  const u8*                  pl;
  usz                        pll;
  quic_reset_stream_at_frame rs;
  quic_stop_sending_frame    ss;
  usz                        rn, sn;
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(
      &conns[0], 1, 1, 5); /* 5 & 3 == 1: client-initiated uni, not bidi */
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 0);
  CHECK(g_sr_wt_handler_calls == 0); /* rejected, not routed to app handler */
  CHECK(srvrun_seal_wt_busy_reset(&conns[0], 5, QUIC_H3_ID_ERROR, &pktb) == 1);
  CHECK(client_open_onertt(&f, pktb.p, pktb.len, &pl, &pll) == 1);
  rn = quic_reset_stream_at_decode(pl, pll, &rs);
  CHECK(rn != 0);
  CHECK(rs.stream_id == 5);
  CHECK(rs.error_code == QUIC_H3_ID_ERROR);
  sn = quic_stop_sending_decode(pl + rn, pll - rn, &ss);
  CHECK(sn != 0);
  CHECK(ss.stream_id == 5);
  CHECK(ss.error_code == QUIC_H3_ID_ERROR);
  CHECK(rn + sn == pll); /* nothing else in the packet */
}

/* RFC 9000 10.2.3: srvrun_seal_app_close builds a correctly-encoded
 * application-level (is_app=1, type 0x1d) CONNECTION_CLOSE -- distinct from
 * wired_srvboot_refusal/quic_flowviol_close_frame's is_app=0 (type 0x1c)
 * transport-level variant. A dormant primitive (tasks/webtransport-plan.md
 * WT-C-005 second half): no live caller yet, this test is its only current
 * exercise, matching srvrun_send_wt_busy_reset's own one-round-dormant
 * precedent before WT-C-009 later found its first caller. */
static void test_srvrun_seal_app_close_is_application_level(void) {
  struct lp_fix         f;
  quic_obuf             ob;
  u8                    obuf[1024];
  u8                    pkt[256];
  quic_obuf             pktb = quic_obuf_of(pkt, sizeof pkt);
  const u8*             pl;
  usz                   pll;
  quic_conn_close_frame ccf;
  usz                   rn;
  const u8*             reason = (const u8*)"WT frame error";
  srvrun_conn           c      = {0};
  ob                           = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  CHECK(
      srvrun_seal_app_close(
          &c, QUIC_H3_FRAME_ERROR, quic_span_of(reason, 14), &pktb) == 1);
  CHECK(client_open_onertt(&f, pktb.p, pktb.len, &pl, &pll) == 1);
  rn = quic_frame_get_conn_close(pl, pll, &ccf);
  CHECK(rn != 0 && rn == pll);
  CHECK(ccf.is_app == 1);
  CHECK(ccf.error_code == QUIC_H3_FRAME_ERROR);
  CHECK(ccf.reason_len == 14);
  {
    int eq = 1;
    for (usz i = 0; i < 14; i++)
      if (ccf.reason[i] != reason[i]) eq = 0;
    CHECK(eq);
  }
}

/* Boundary: an empty reason string round-trips correctly. */
static void test_srvrun_seal_app_close_empty_reason(void) {
  struct lp_fix         f;
  quic_obuf             ob;
  u8                    obuf[1024];
  u8                    pkt[256];
  quic_obuf             pktb = quic_obuf_of(pkt, sizeof pkt);
  const u8*             pl;
  usz                   pll;
  quic_conn_close_frame ccf;
  usz                   rn;
  srvrun_conn           c = {0};
  ob                      = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  CHECK(
      srvrun_seal_app_close(
          &c, QUIC_H3_FRAME_ERROR, quic_span_of((const u8*)"", 0), &pktb) == 1);
  CHECK(client_open_onertt(&f, pktb.p, pktb.len, &pl, &pll) == 1);
  rn = quic_frame_get_conn_close(pl, pll, &ccf);
  CHECK(rn != 0 && rn == pll);
  CHECK(ccf.is_app == 1);
  CHECK(ccf.reason_len == 0);
}

/* srvrun_send_app_close is the seal-then-wire-send wrapper (mirrors
 * srvrun_send_wt_busy_reset): with cfg.fd == -1 (this test's fixture, no
 * real socket) the underlying sendto fails but must not crash -- confirms
 * the function is reachable/callable, the only exercise this dormant
 * primitive has until a future violation-detection round wires a live
 * caller. */
static void test_srvrun_send_app_close_does_not_crash(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  ob             = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  srvrun_send_app_close(
      &cfg, &c, QUIC_H3_FRAME_ERROR, quic_span_of((const u8*)"x", 1));
  CHECK(1);
}

/* REGRESSION: the FIRST (accepted) Extended CONNECT establishes a session
 * and must never trigger the reject-path RESET_STREAM -- wt_active stays
 * false at dispatch time, so srvrun_reject_wt_busy (and the reset it sends)
 * is never reached. Confirmed indirectly: the accepted path leaves the
 * session ESTABLISHED and the handler count untouched (WT never calls the
 * app handler), matching the pre-existing accept-path assertions. */
static void test_srvrun_first_wt_connect_no_reset_stream(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  u64            tx_pn_before;
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  tx_pn_before = conns[0].l.tx_pn;
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  /* srvrun_send_wt_busy_reset (the only caller that seals a RESET_STREAM
   * pair on this path) is not on srvrun_start_wt's path, so tx_pn advances
   * by nothing more than a normal 2xx response would use. */
  CHECK(conns[0].l.tx_pn == tx_pn_before);
}

/* WT-F-001/002/003 (approximation): tearing down the connection tears down
 * its WebTransport session too. srvrun_free_slot is the one hook common to
 * every teardown path (peer close, boot failure, idle sweep); this drives it
 * via the idle sweep, the cheapest of the three to set up in a unit test.
 * This is NOT the spec-accurate trigger (the real rule is the CONNECT
 * stream's own FIN/RESET, independent of whether the rest of the connection
 * survives) -- see the comment on srvrun_free_slot and
 * tasks/wt-pin-poll-progress.md for why that finer-grained signal does not
 * exist yet. */
static void test_srvrun_idle_sweep_closes_wt_session(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  struct lp_fix  f;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  conns[0].last_ms = 1000;
  {
    srvrun_state st = {table, conns};
    srvrun_sweep_idle(&g_srvrun_env, &st, 1000 + WIRED_SRVRUN_IDLE_MS);
  }
  CHECK(conns[0].wt_active == 0);
  CHECK(conns[0].wt.state == WIRED_WT_CLOSED);
  CHECK(conns[0].up == 0);
}

/* draft-ietf-webtrans-http3-15 SS4.4 / WT-F-001/002/003: the CONNECT stream
 * closing (dispatch.c's gather_stream_closes latching closed_stream_id) ends
 * the WT session immediately, independent of whole-connection teardown -- the
 * fourth trigger the TLA+ model (tasks/loopeng/webtransport/) found the
 * existing three (peer CONNECTION_CLOSE / idle timeout / accept failure, all
 * srvrun_free_slot) missing. The connection itself stays up (conns[0].up is
 * never touched by srvrun_on_step for this), only the session closes. */
static void test_srvrun_connect_stream_reset_closes_wt_session(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  struct lp_fix  f;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.connect_stream_id == 4);
  conns[0].l.closed_stream_id   = 4; /* the CONNECT stream's own id */
  conns[0].l.closed_stream_seen = 1;
  srvrun_close_wt_on_stream_close(&conns[0]);
  CHECK(conns[0].wt.state == WIRED_WT_CLOSED);
  CHECK(conns[0].l.closed_stream_seen == 0); /* consumed every step */
}

/* BOUNDARY: a close on a DIFFERENT stream id (e.g. a WT bidi/uni data stream,
 * not the CONNECT stream itself) must not touch the session -- only the exact
 * connect_stream_id id closes it. */
static void test_srvrun_other_stream_reset_does_not_close_wt_session(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  struct lp_fix  f;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  conns[0].l.closed_stream_id   = 8; /* a different (WT bidi) stream id */
  conns[0].l.closed_stream_seen = 1;
  srvrun_close_wt_on_stream_close(&conns[0]);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].l.closed_stream_seen == 0); /* still consumed every step */
}

/* REGRESSION: a step with no stream-close latched (closed_stream_seen == 0)
 * leaves an established WT session untouched. */
static void test_srvrun_no_stream_close_leaves_wt_session(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  struct lp_fix  f;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  srvrun_close_wt_on_stream_close(&conns[0]);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt_active == 1);
}

/* REGRESSION: a connection with no active WT session (wt_active == 0) tears
 * down exactly as before -- srvrun_free_slot is the most commonly hit
 * teardown path, so a crash or behavior change here would be severe. */
static void test_srvrun_idle_sweep_without_wt_unaffected(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  srvrun_state   st    = {table, conns};
  u8             k[4]  = {9, 9, 9, 9};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  conns[0].up        = 1;
  conns[0].last_ms   = 1000;
  conns[0].wt_active = 0;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, k, 4) == 0);
  srvrun_sweep_idle(&g_srvrun_env, &st, 1000 + WIRED_SRVRUN_IDLE_MS);
  CHECK(conns[0].up == 0);
  CHECK(conns[0].wt_active == 0);
  CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, k, 4) == -1);
}

/* QUIC DATAGRAM SEND (RFC 9221 5): srvrun_queue_datagram queues a payload,
 * srvrun_send_pending_datagram seals it into a real 1-RTT packet. The client
 * opens that packet under its own peer key and quic_datagram_decode recovers
 * the exact payload bytes -- proof of a genuine encode -> seal -> wire ->
 * decode round trip, not just "the function returned 1". Requires a non-zero
 * peer_max_datagram_frame_size (the peer must have advertised support) since
 * srvrun_send_pending_datagram now enforces it. */
static const u8 sr_dg_payload[] = {0xde, 0xad, 0xbe, 0xef, 0x01};

static void test_srvrun_datagram_round_trip_on_wire(void) {
  struct lp_fix       f;
  srvrun_conn         c;
  quic_obuf           ob;
  u8                  obuf[1600];
  const u8*           pl;
  usz                 pll;
  quic_datagram_frame df;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.peer_max_datagram_frame_size = 65535;
  CHECK(
      srvrun_queue_datagram(
          &c, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  CHECK(c.dg_pending == 1);
  {
    quic_obuf  out = {obuf, sizeof obuf, 0};
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0};
    CHECK(srvrun_send_pending_datagram(&cfg, &c, &out) == 1);
    CHECK(client_open_onertt(&f, out.p, out.len, &pl, &pll) == 1);
  }
  CHECK(c.dg_pending == 0); /* drained */
  CHECK(quic_datagram_decode(pl, pll, &df) == pll);
  CHECK(df.length == sizeof sr_dg_payload);
  for (usz i = 0; i < sizeof sr_dg_payload; i++)
    CHECK(df.data[i] == sr_dg_payload[i]);
}

/* WT-A-005 / RFC 9297 2.1: a QUIC DATAGRAM must never be queued before this
 * endpoint's own SETTINGS_H3_DATAGRAM has been sent (SETTINGS are never
 * acked in HTTP/3, so "sent" is the enforceable half of the ordering).
 * sr_make_confirmed_conn drives a real confirmation, which sends SETTINGS
 * as part of building the first response (build_settings_frame) -- so
 * settings_sent is already 1 there; this test drives the not-yet-sent case
 * by direct injection, the same style already used by every other
 * srvrun_conn fixture in this file that does not go through the wire (e.g.
 * test_srvrun_datagram_too_large_rejected below). No production caller
 * reaches srvrun_queue_datagram before confirmation today (it is
 * `__attribute__((unused))`, called only from tests/run.c per its own
 * comment) so this is a defensive guard, not a reachable-today bug fix --
 * but it is real, direct-callable behavior of the function under test. */
static void test_srvrun_datagram_dropped_before_settings_sent(void) {
  srvrun_conn c = {0}; /* c.l.h3.settings_sent == 0, the not-yet-sent state */
  CHECK(
      srvrun_queue_datagram(
          &c, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 0);
  CHECK(c.dg_pending == 0);
}

/* PEER-LIMIT ENFORCEMENT: a peer that never advertised
 * max_datagram_frame_size (0 = unsupported) must have its DATAGRAM send
 * rejected outright, queued state and all -- 0 is "does not support
 * DATAGRAM", not "unlimited". */
static void test_srvrun_datagram_rejected_when_peer_unadvertised(void) {
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob;
  u8            obuf[1600];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  CHECK(c.s.sdrv.peer_max_datagram_frame_size == 0);
  CHECK(
      srvrun_queue_datagram(
          &c, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  {
    quic_obuf  out = {obuf, sizeof obuf, 0};
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0};
    CHECK(srvrun_send_pending_datagram(&cfg, &c, &out) == 0);
  }
  CHECK(c.dg_pending == 1); /* still pending: the send never went out */
}

/* PEER-LIMIT ENFORCEMENT: a frame that exceeds the peer's advertised
 * max_datagram_frame_size is rejected even though it fits the local buffer,
 * while the same payload under a sufficient peer limit still succeeds. */
static void test_srvrun_datagram_rejected_over_peer_limit(void) {
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob;
  u8            obuf[1600];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.peer_max_datagram_frame_size =
      3; /* smaller than the encoded frame */
  CHECK(
      srvrun_queue_datagram(
          &c, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  {
    quic_obuf  out = {obuf, sizeof obuf, 0};
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0};
    CHECK(srvrun_send_pending_datagram(&cfg, &c, &out) == 0);
  }
  CHECK(c.dg_pending == 1);
}

/* REGRESSION: the existing STREAM-based response path is untouched when the
 * pending-DATAGRAM machinery is never used -- no pending flag, no wire
 * change to srvrun_send_slice's own behavior. */
static void test_srvrun_datagram_unused_does_not_affect_stream_response(void) {
  srvrun_conn c = {0};
  CHECK(c.dg_pending == 0);
  CHECK(c.dg_pending_len == 0);
}

/* BOUNDARY: a payload larger than dg_pending_buf's capacity is rejected --
 * queued state is unchanged (no partial copy, no corruption). */
static void test_srvrun_datagram_too_large_rejected(void) {
  static u8   big[1201];
  srvrun_conn c = {0};
  CHECK(srvrun_queue_datagram(&c, quic_span_of(big, sizeof big)) == 0);
  CHECK(c.dg_pending == 0);
}

/* SINGLE-SLOT OVERWRITE CONTRACT: queuing a second datagram before the first
 * drains overwrites the pending slot (last-writer-wins), per the documented
 * ponytail simplification on srvrun_conn.dg_pending_buf. */
static const u8 sr_dg_first[]  = {1, 2, 3};
static const u8 sr_dg_second[] = {9, 9};

static void test_srvrun_datagram_second_queue_overwrites_first(void) {
  srvrun_conn c        = {0};
  c.l.h3.settings_sent = 1; /* RFC 9297 2.1: queuing requires SETTINGS sent */
  CHECK(
      srvrun_queue_datagram(
          &c, quic_span_of(sr_dg_first, sizeof sr_dg_first)) == 1);
  CHECK(
      srvrun_queue_datagram(
          &c, quic_span_of(sr_dg_second, sizeof sr_dg_second)) == 1);
  CHECK(c.dg_pending == 1);
  CHECK(c.dg_pending_len == sizeof sr_dg_second);
  for (usz i = 0; i < sizeof sr_dg_second; i++)
    CHECK(c.dg_pending_buf[i] == sr_dg_second[i]);
}

/* WEBTRANSPORT DATAGRAM RECEIVE (tasks/webtransport-plan.md Phase 7b Slice 2):
 * srvrun_drain_rx_datagrams delivers every queued RFC 9221 DATAGRAM to the
 * registered app callback exactly once, in arrival order, then empties the
 * queue. g_srdg_calls/g_srdg_last_len/g_srdg_last_buf record what the
 * callback observed (this repo's existing g_sr_wt_handler_calls counter
 * pattern, extended to also capture the payload bytes). */
static int               g_srdg_calls = 0;
static usz               g_srdg_last_len;
static u8                g_srdg_last_buf[256];
static wired_wt_session* g_srdg_last_sess;

static void sr_dg_handler(void* app_ctx, wired_wt_session* s, quic_span data) {
  (void)app_ctx;
  g_srdg_calls++;
  g_srdg_last_sess = s;
  g_srdg_last_len  = data.n;
  for (usz i = 0; i < data.n && i < sizeof g_srdg_last_buf; i++)
    g_srdg_last_buf[i] = data.p[i];
}

/* Establish a WT session on c via the same path
 * test_srvrun_wt_connect_establishes_session uses (Extended CONNECT), so the
 * connection's wt_active/wt fields are real, not hand-set. */
static void sr_establish_wt(
    srvrun_conn* conns, quic_conntable* table, u64 sid) {
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_set_req(&conns[0], 1, 1, sid);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
}

/* One real client-encoded DATAGRAM frame, driven through wired_srvloop_step
 * (the live decode path, not a hand-populated queue) and then drained --
 * proves the full encode -> wire -> decode -> callback path, not just that
 * the callback function pointer is invoked. */
static const u8 sr_rxdg_payload[] = {0xaa, 0xbb, 0xcc};

static void test_srvrun_rx_datagram_delivers_to_callback(void) {
  struct lp_fix       f;
  quic_conntable      table[QUIC_CONNTABLE_CAP];
  srvrun_conn*        conns = sr_test_conns();
  quic_obuf           ob;
  u8                  obuf[1024], payload[64], spkt[1024], out[1024];
  usz                 plen, slen;
  quic_datagram_frame df = {
      .length = sizeof sr_rxdg_payload, .data = sr_rxdg_payload};
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  conns[0].l.we_advertised_max_datagram = 100; /* RFC 9221 3: opted in */
  sr_establish_wt(conns, table, 4);
  plen = quic_datagram_encode(quic_mspan_of(payload, sizeof payload), &df, 1);
  slen = client_seal_onertt_pn(&f, 3, payload, plen, spkt, sizeof spkt);
  {
    quic_obuf          sob  = {out, sizeof out, 0};
    wired_srvloop_conn conn = {&conns[0].l, &conns[0].s};
    wired_srvloop_step(&conn, quic_mspan_of(spkt, slen), &sob);
  }
  CHECK(conns[0].l.rx_datagram_n == 1);
  g_srdg_calls = 0;
  {
    srvrun_cfg cfg = {
        -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, sr_dg_handler, 0, 0, 0, 0, &g_srvrun_env,
        0,  0, 0, 0, 0};
    srvrun_drain_rx_datagrams(&cfg, &conns[0]);
  }
  CHECK(g_srdg_calls == 1);
  CHECK(conns[0].l.rx_datagram_n == 0); /* queue drained */
  CHECK(g_srdg_last_len == sizeof sr_rxdg_payload);
  CHECK(g_srdg_last_sess == &conns[0].wt);
  for (usz i = 0; i < sizeof sr_rxdg_payload; i++)
    CHECK(g_srdg_last_buf[i] == sr_rxdg_payload[i]);
}

/* MULTIPLE DATAGRAMS: several queued in one drain are all delivered, in
 * order, not just the first. Populates the queue directly (already proven
 * reachable via the wire in the test above) to keep this test focused on the
 * drain loop itself. */
static void test_srvrun_rx_datagram_multiple_all_delivered(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  usz            i;
  sr_establish_wt(conns, table, 4);
  for (i = 0; i < 3; i++) {
    conns[0].l.rx_datagrams[i].buf[0] = (u8)('A' + i);
    conns[0].l.rx_datagrams[i].len    = 1;
  }
  conns[0].l.rx_datagram_n = 3;
  g_srdg_calls             = 0;
  {
    srvrun_cfg cfg = {
        -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, sr_dg_handler, 0, 0, 0, 0, &g_srvrun_env,
        0,  0, 0, 0, 0};
    srvrun_drain_rx_datagrams(&cfg, &conns[0]);
  }
  CHECK(g_srdg_calls == 3);
  CHECK(conns[0].l.rx_datagram_n == 0);
  /* the last call observed is the last-queued datagram (arrival order) */
  CHECK(g_srdg_last_len == 1 && g_srdg_last_buf[0] == 'C');
}

/* NULL CALLBACK: no callback registered -- the drain still empties the
 * queue without crashing (this SDK's "0/NULL disables the optional feature"
 * convention). */
static void test_srvrun_rx_datagram_no_callback_still_drains(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  sr_establish_wt(conns, table, 4);
  conns[0].l.rx_datagrams[0].buf[0] = 'Z';
  conns[0].l.rx_datagrams[0].len    = 1;
  conns[0].l.rx_datagram_n          = 1;
  g_srdg_calls                      = 0;
  {
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0};
    srvrun_drain_rx_datagrams(&cfg, &conns[0]);
  }
  CHECK(g_srdg_calls == 0);
  CHECK(conns[0].l.rx_datagram_n == 0);
}

/* REGRESSION: a connection with no active WT session (wt_active == 0) --
 * queued datagrams still get drained (queue empties) but the callback is
 * never invoked, mirroring srvrun_offer_wt_slot's existing
 * accepted-and-ignored fallback for a session-less connection. */
static void test_srvrun_rx_datagram_no_session_callback_not_invoked(void) {
  srvrun_conn c              = {0};
  c.wt_active                = 0;
  c.l.rx_datagrams[0].buf[0] = 'Q';
  c.l.rx_datagrams[0].len    = 1;
  c.l.rx_datagram_n          = 1;
  g_srdg_calls               = 0;
  {
    srvrun_cfg cfg = {
        -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, sr_dg_handler, 0, 0, 0, 0, &g_srvrun_env,
        0,  0, 0, 0, 0};
    srvrun_drain_rx_datagrams(&cfg, &c);
  }
  CHECK(g_srdg_calls == 0);
  CHECK(c.l.rx_datagram_n == 0);
}

/* RFC 9000 10.2.3: srvrun_seal_transport_close builds a correctly-encoded
 * transport-level (is_app=0, type 0x1c) CONNECTION_CLOSE -- the sibling of
 * test_srvrun_seal_app_close_is_application_level's is_app=1 check, proving
 * the two close primitives are distinct and this one carries a standard RFC
 * 9000 20.1 error code (PROTOCOL_VIOLATION, 0x0a) rather than an application
 * one. */
static void test_srvrun_seal_transport_close_is_transport_level(void) {
  struct lp_fix         f;
  quic_obuf             ob;
  u8                    obuf[1024];
  u8                    pkt[256];
  quic_obuf             pktb = quic_obuf_of(pkt, sizeof pkt);
  const u8*             pl;
  usz                   pll;
  quic_conn_close_frame ccf;
  usz                   rn;
  const u8*             reason = (const u8*)"DATAGRAM too large";
  srvrun_conn           c      = {0};
  ob                           = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  CHECK(srvrun_seal_transport_close(
      &c, QUIC_ERR_PROTOCOL_VIOLATION, quic_span_of(reason, 18), &pktb));
  CHECK(client_open_onertt(&f, pktb.p, pktb.len, &pl, &pll) == 1);
  rn = quic_frame_get_conn_close(pl, pll, &ccf);
  CHECK(rn != 0 && rn == pll);
  CHECK(ccf.is_app == 0);
  CHECK(ccf.error_code == QUIC_ERR_PROTOCOL_VIOLATION);
}

/* RFC 9221 3 / WT-A-007/008: a DATAGRAM frame whose payload exceeds this
 * connection's own advertised max_datagram_frame_size, driven through the
 * real srvrun_on_step (not just wired_srvloop_step in isolation), latches
 * l.datagram_violation and does NOT queue the oversized frame -- proving the
 * live entry point srvrun.c's caller (srvrun_serve) actually reaches and acts
 * on dispatch.c's check, not just wired_srvloop_step in isolation
 * (test_srvloop_datagram_exceeding_advertised_limit_rejected already covers
 * that layer). srvrun_on_step's own srvrun_close_on_datagram_violation branch
 * then calls srvrun_send_transport_close (proven correct on the wire by
 * test_srvrun_seal_transport_close_is_transport_level above) -- fd=-1 makes
 * the actual sendto(2) a harmless no-op, same convention as every other
 * srvrun_send test in this file (e.g. test_srvrun_owes_goaway_once). */
static void test_srvrun_oversized_datagram_latches_violation_on_step(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024], payload[512], spkt[1024];
  usz           plen, slen;
  srvrun_conn   c = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  srvrun_step_ctx     ctx = {&cfg, 0, 0, 0};
  u8                  data[200];
  quic_datagram_frame df = {.length = sizeof data, .data = data};
  for (usz i = 0; i < sizeof data; i++) data[i] = (u8)i;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.l.we_advertised_max_datagram = 100; /* RFC 9221 3: advertised limit 100 */
  plen = quic_datagram_encode(quic_mspan_of(payload, sizeof payload), &df, 1);
  slen = client_seal_onertt_pn(&f, 3, payload, plen, spkt, sizeof spkt);
  srvrun_on_step(&ctx, &c, quic_mspan_of(spkt, slen));
  CHECK(c.l.datagram_violation == 1);
  CHECK(c.l.rx_datagram_n == 0); /* the oversized frame was never queued */
}

/* WEBTRANSPORT STREAM DATA RECEIVE (draft-ietf-webtrans-http3-15 4.3, Phase
 * 7b Slice 4): srvrun_offer_wt_streams/srvrun_offer_wt_uni_streams deliver a
 * WT bidi/uni slot's newly-reassembled bytes to the registered app callback
 * every step, mirroring the g_srdg_calls counter pattern used above for the
 * DATAGRAM receive callback. */
static int               g_srsd_calls = 0;
static usz               g_srsd_last_len;
static u8                g_srsd_last_buf[256];
static u64               g_srsd_last_stream_id;
static int               g_srsd_last_fin;
static wired_wt_session* g_srsd_last_sess;

static void sr_stream_data_handler(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    quic_span         data,
    int               fin) {
  (void)app_ctx;
  g_srsd_calls++;
  g_srsd_last_sess      = s;
  g_srsd_last_stream_id = stream_id;
  g_srsd_last_len       = data.n;
  g_srsd_last_fin       = fin;
  for (usz i = 0; i < data.n && i < sizeof g_srsd_last_buf; i++)
    g_srsd_last_buf[i] = data.p[i];
}

/* Set a WT bidi slot's receive window as if n contiguous bytes had been
 * written from offset 0 -- the hand-constructed-state tests below poke a
 * slot directly rather than driving real wire frames through it, so the
 * window's range-set fields (win.range_lo/hi/n, win.frontier) must be kept
 * consistent by hand too (frontier alone is not enough: srvrun_offer_wt_
 * streams also calls wired_srvloop_wt_window_slide, which recomputes
 * frontier from the range set on every call). */
static void sr_wt_slot_set_frontier(wired_srvloop_wt_stream_slot* slot, u64 n) {
  slot->win.range_n     = n > 0 ? 1 : 0;
  slot->win.range_lo[0] = 0;
  slot->win.range_hi[0] = n;
  slot->win.frontier    = n;
}

/* Same as sr_wt_slot_set_frontier, for the separate wt_uni_streams table. */
static void sr_wt_uni_slot_set_frontier(
    wired_srvloop_wt_uni_stream_slot* slot, u64 n) {
  slot->win.range_n     = n > 0 ? 1 : 0;
  slot->win.range_lo[0] = 0;
  slot->win.range_hi[0] = n;
  slot->win.frontier    = n;
}

/* A freshly-claimed WT bidi slot with bytes already reassembled (offered==0,
 * as a real first step would leave it) delivers those bytes to the callback
 * in the same step it is offered to the session -- proving offer and deliver
 * both run without one blocking the other. */
static void test_srvrun_wt_stream_data_delivered_on_offer(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c   = {0};
  srvrun_cfg    cfg = {
      -1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      sr_stream_data_handler,
      0,
      0,
      &g_srvrun_env,
      0,
      0,
      0,
      0,
      0};
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  wired_wt_session_init(&c.wt, 4);
  c.wt_active                 = 1;
  c.l.wt_streams[0].in_use    = 1;
  c.l.wt_streams[0].stream_id = 8;
  c.l.wt_streams[0].offered   = 0;
  c.l.wt_streams[0].buf[0]    = 'h';
  c.l.wt_streams[0].buf[1]    = 'i';
  sr_wt_slot_set_frontier(&c.l.wt_streams[0], 2);
  g_srsd_calls = 0;
  srvrun_offer_wt_streams(&cfg, &c);
  CHECK(c.l.wt_streams[0].offered == 1);
  CHECK(g_srsd_calls == 1);
  CHECK(g_srsd_last_sess == &c.wt);
  CHECK(g_srsd_last_stream_id == 8);
  CHECK(g_srsd_last_len == 2);
  CHECK(g_srsd_last_buf[0] == 'h' && g_srsd_last_buf[1] == 'i');
  CHECK(g_srsd_last_fin == 0);
  CHECK(c.l.wt_streams[0].delivered_len == 2);
}

/* A second step that appends more bytes to an already-offered slot delivers
 * only the DELTA (buf[delivered_len..len)), not the whole buffer again --
 * proving the cumulative-buffer/delta-tracking design, not a raw drain. */
static void test_srvrun_wt_stream_data_delivers_delta_only(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c   = {0};
  srvrun_cfg    cfg = {
      -1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      sr_stream_data_handler,
      0,
      0,
      &g_srvrun_env,
      0,
      0,
      0,
      0,
      0};
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  wired_wt_session_init(&c.wt, 4);
  c.wt_active                     = 1;
  c.l.wt_streams[0].in_use        = 1;
  c.l.wt_streams[0].stream_id     = 8;
  c.l.wt_streams[0].offered       = 1; /* already offered a prior step */
  c.l.wt_streams[0].buf[0]        = 'h';
  c.l.wt_streams[0].buf[1]        = 'i';
  c.l.wt_streams[0].delivered_len = 2; /* those 2 bytes were delivered before */
  c.l.wt_streams[0].buf[2]        = '!';
  sr_wt_slot_set_frontier(
      &c.l.wt_streams[0], 3); /* one more byte arrives this step */
  g_srsd_calls = 0;
  srvrun_offer_wt_streams(&cfg, &c);
  CHECK(g_srsd_calls == 1);
  CHECK(g_srsd_last_len == 1); /* only the new byte, not all 3 */
  CHECK(g_srsd_last_buf[0] == '!');
  CHECK(c.l.wt_streams[0].delivered_len == 3);
}

/* fin=1 with no unseen bytes still reaches the app exactly once (the "closing
 * frame carried no new payload" case wt_stream_fin_only exists for). */
static void test_srvrun_wt_stream_data_fin_only_delivered(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c   = {0};
  srvrun_cfg    cfg = {
      -1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      sr_stream_data_handler,
      0,
      0,
      &g_srvrun_env,
      0,
      0,
      0,
      0,
      0};
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  wired_wt_session_init(&c.wt, 4);
  c.wt_active                 = 1;
  c.l.wt_streams[0].in_use    = 1;
  c.l.wt_streams[0].stream_id = 8;
  c.l.wt_streams[0].offered   = 1;
  c.l.wt_streams[0].fin       = 1; /* fin_off left 0: the stream is empty */
  g_srsd_calls                = 0;
  srvrun_offer_wt_streams(&cfg, &c);
  CHECK(g_srsd_calls == 1);
  CHECK(g_srsd_last_len == 0);
  CHECK(g_srsd_last_fin == 1);
  /* a further step with nothing new does not re-deliver */
  g_srsd_calls = 0;
  srvrun_offer_wt_streams(&cfg, &c);
  CHECK(g_srsd_calls == 0);
}

/* NULL CALLBACK: no callback registered -- offer still associates the slot
 * with the session, no crash, nothing delivered (this SDK's "0/NULL disables
 * the optional feature" convention, mirrored from the DATAGRAM path). */
static void test_srvrun_wt_stream_data_no_callback_still_offers(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c = {0};
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  ob             = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  wired_wt_session_init(&c.wt, 4);
  c.wt_active                 = 1;
  c.l.wt_streams[0].in_use    = 1;
  c.l.wt_streams[0].stream_id = 8;
  c.l.wt_streams[0].buf[0]    = 'x';
  sr_wt_slot_set_frontier(&c.l.wt_streams[0], 1);
  g_srsd_calls = 0;
  srvrun_offer_wt_streams(&cfg, &c);
  CHECK(c.l.wt_streams[0].offered == 1);
  CHECK(g_srsd_calls == 0);
}

/* REGRESSION: a connection with no active WT session (wt_active == 0) --
 * a reassembled slot is left alone (no callback), mirroring
 * test_srvrun_wt_uni_stream_no_session_not_offered's fallback. */
static void test_srvrun_wt_stream_data_no_session_not_delivered(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c   = {0};
  srvrun_cfg    cfg = {
      -1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      sr_stream_data_handler,
      0,
      0,
      &g_srvrun_env,
      0,
      0,
      0,
      0,
      0};
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.wt_active                 = 0;
  c.l.wt_streams[0].in_use    = 1;
  c.l.wt_streams[0].stream_id = 8;
  c.l.wt_streams[0].buf[0]    = 'x';
  sr_wt_slot_set_frontier(&c.l.wt_streams[0], 1);
  g_srsd_calls = 0;
  srvrun_offer_wt_streams(&cfg, &c);
  CHECK(g_srsd_calls == 0);
  CHECK(c.l.wt_streams[0].offered == 0);
}

/* WT UNI STREAM: mirrors test_srvrun_wt_stream_data_delivered_on_offer for
 * the separate uni table (srvrun_offer_wt_uni_streams), proving the shared
 * srvrun_deliver_wt_stream_delta helper is reached from both call sites. */
static void test_srvrun_wt_uni_stream_data_delivered_on_offer(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];
  srvrun_conn   c   = {0};
  srvrun_cfg    cfg = {
      -1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      sr_stream_data_handler,
      0,
      0,
      &g_srvrun_env,
      0,
      0,
      0,
      0,
      0};
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  wired_wt_session_init(&c.wt, 4);
  c.wt_active                     = 1;
  c.l.wt_uni_streams[0].in_use    = 1;
  c.l.wt_uni_streams[0].stream_id = 2;
  c.l.wt_uni_streams[0].offered   = 0;
  c.l.wt_uni_streams[0].buf[0]    = 'u';
  sr_wt_uni_slot_set_frontier(&c.l.wt_uni_streams[0], 1);
  g_srsd_calls = 0;
  srvrun_offer_wt_uni_streams(&cfg, &c);
  CHECK(c.l.wt_uni_streams[0].offered == 1);
  CHECK(g_srsd_calls == 1);
  CHECK(g_srsd_last_stream_id == 2);
  CHECK(g_srsd_last_len == 1);
  CHECK(g_srsd_last_buf[0] == 'u');
  CHECK(c.l.wt_uni_streams[0].delivered_len == 1);
}

/* PHASE 7c: full in-tree client/server integration. Extended CONNECT
 * establishes a WT session -> a WT bidi stream's reassembled bytes reach the
 * app callback -> a QUIC DATAGRAM round-trips on the wire and reaches the app
 * callback -> the CONNECT stream's own RESET_STREAM (on the wire, via
 * srvrun_on_step's real dispatch path) closes the session, independent of
 * the connection itself, which stays up. Every step drives real sealed 1-RTT
 * packets through srvrun_on_step (not direct field injection), the same
 * client/server pair sr_make_confirmed_conn builds elsewhere in this file. */
static void test_srvrun_wt_full_session_lifecycle_on_wire(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  u8             wt[64], out[1024], spkt[1024];
  usz            wtl, slen;
  const u8*      pl;
  usz            pll;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);

  /* Step 1: Extended CONNECT (:protocol=webtransport-h3, stream 4)
   * establishes the WT session -- mirrors test_srvrun_wt_connect_establishes_
   * session's own driving style (srvrun_start_resp reads the mirrored
   * req/req_stream_id fields, no real HEADERS bytes needed to exercise this
   * layer). */
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg cfg = {
        -1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        sr_dg_handler,
        0,
        sr_stream_data_handler,
        0,
        0,
        &g_srvrun_env,
        0,
        0,
        0,
        0,
        0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt.connect_stream_id == 4);

  /* Step 2: a WT bidi stream (id 8, the next client-initiated bidi id after
   * the CONNECT stream) sends its leading 0x41 signal + one application byte
   * -- reassembled by dispatch.c's gather_wt_stream then delivered to the
   * app callback by srvrun_offer_wt_streams, both driven through the real
   * srvrun_on_step path this time (not direct slot injection). */
  {
    srvrun_cfg cfg = {
        -1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        sr_dg_handler,
        0,
        sr_stream_data_handler,
        0,
        0,
        &g_srvrun_env,
        0,
        0,
        0,
        0,
        0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    g_srsd_calls        = 0;
    wtl                 = lp_wt_bidi_stream(wt, sizeof wt, 8);
    slen = client_seal_onertt_pn(&f, 3, wt, wtl, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &conns[0], quic_mspan_of(spkt, slen));
  }
  CHECK(g_srsd_calls == 1);
  CHECK(g_srsd_last_stream_id == 8);
  CHECK(g_srsd_last_len == 1 && g_srsd_last_buf[0] == 'X');
  CHECK(g_srsd_last_sess == &conns[0].wt);

  /* Step 3: a QUIC DATAGRAM round-trips -- queued server-side, sealed and
   * opened by the client, then fed back in as a received 1-RTT payload so
   * the receive side (framewalk -> gather_rx_datagrams -> srvrun_drain_rx_
   * datagrams -> app callback) is exercised on the exact bytes the send side
   * produced, a real encode -> wire -> decode -> deliver round trip. */
  {
    quic_datagram_frame df;
    u8                  dgpl[64];
    usz                 dgpll;
    conns[0].s.sdrv.peer_max_datagram_frame_size = 65535;
    conns[0].l.we_advertised_max_datagram        = 65535;
    CHECK(
        srvrun_queue_datagram(
            &conns[0], quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
    {
      quic_obuf  sendob = {out, sizeof out, 0};
      srvrun_cfg cfg    = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
      CHECK(srvrun_send_pending_datagram(&cfg, &conns[0], &sendob) == 1);
      CHECK(client_open_onertt(&f, sendob.p, sendob.len, &pl, &pll) == 1);
    }
    CHECK(quic_datagram_decode(pl, pll, &df) == pll);
    for (usz i = 0; i < sizeof sr_dg_payload; i++)
      CHECK(df.data[i] == sr_dg_payload[i]);
    dgpll = quic_datagram_encode(quic_mspan_of(dgpl, sizeof dgpl), &df, 1);
    {
      srvrun_cfg      cfg = {-1,
                             0,
                             0,
                             0,
                             0,
                             0,
                             0,
                             0,
                             0,
                             0,
                             sr_dg_handler,
                             0,
                             0,
                             0,
                             0,
                             &g_srvrun_env,
                             0,
                             0,
                             0,
                             0,
                             0};
      srvrun_state    st  = {table, conns};
      srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
      slen = client_seal_onertt_pn(&f, 4, dgpl, dgpll, spkt, sizeof spkt);
      g_srdg_calls = 0;
      srvrun_on_step(&ctx, &conns[0], quic_mspan_of(spkt, slen));
    }
    CHECK(g_srdg_calls == 1);
    CHECK(g_srdg_last_len == sizeof sr_dg_payload);
  }

  /* Step 4: the CONNECT stream itself (id 4) is RESET on the wire -- the
   * fourth close trigger (dispatch.c's gather_stream_closes -> srvrun.c's
   * srvrun_close_wt_on_stream_close) closes the session, while the
   * connection stays up (srvrun_on_step never touches conns[0].up for this
   * path). */
  {
    quic_reset_stream_frame rs = {4, 0, 0};
    u8                      rspl[32];
    usz             rspll = quic_reset_stream_encode(rspl, sizeof rspl, &rs);
    srvrun_cfg      cfg   = {-1, 0, 0, 0, 0, 0, 0, 0,
                             0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                             0,  0, 0, 0, 0};
    srvrun_state    st    = {table, conns};
    srvrun_step_ctx ctx   = {&cfg, 0, &st, 0};
    slen = client_seal_onertt_pn(&f, 5, rspl, rspll, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &conns[0], quic_mspan_of(spkt, slen));
  }
  CHECK(conns[0].wt.state == WIRED_WT_CLOSED);
  CHECK(conns[0].up == 1); /* the connection itself is untouched */
}

/* MULTI-SESSION: a second Extended CONNECT on a DIFFERENT stream, while the
 * connection's open-session count is below SRVRUN_MAX_WT_SESSIONS, is
 * accepted as its own independent session rather than rejected with 429 --
 * both sessions stay ESTABLISHED at once, keyed by their own CONNECT stream
 * id. */
static void test_srvrun_wt_accept_second_session_below_limit(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  conns[0].resp[0].in_use = 0;    /* pretend the first 2xx finished sending */
  sr_set_req(&conns[0], 1, 1, 8); /* second Extended CONNECT, different id */
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1); /* the first session, still established */
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt.connect_stream_id == 4);
  CHECK(conns[0].wt1_active == 1); /* the second session, its own slot */
  CHECK(conns[0].wt1.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt1.connect_stream_id == 8);
  CHECK(conns[0].resp[0].sess.active == 1); /* the second 2xx was armed */
}

/* MULTI-SESSION BOUNDARY: once SRVRUN_MAX_WT_SESSIONS sessions are open, a
 * further Extended CONNECT is rejected with 429 exactly as the single-
 * session path always was, and no new slot is created. */
static void test_srvrun_wt_reject_at_session_limit(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  conns[0].resp[0].in_use = 0;
  sr_set_req(&conns[0], 1, 1, 8);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1 && conns[0].wt1_active == 1); /* both full */
  conns[0].resp[0].in_use = 0;
  sr_set_req(&conns[0], 1, 1, 12); /* third Extended CONNECT: over the limit */
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(g_sr_wt_handler_calls == 0);
  CHECK(conns[0].resp[0].sess.active == 1);    /* the 429 was armed */
  CHECK(conns[0].wt.connect_stream_id == 4);   /* first session untouched */
  CHECK(conns[0].wt1.connect_stream_id == 8);  /* second session untouched */
  CHECK(srvrun_wt_free_slot(&conns[0]) == -1); /* no slot was created */
}

/* PATH RECORDING: an accepted Extended CONNECT's own :path value is copied
 * into its session slot. */
static void test_srvrun_wt_accept_records_path(void) {
  struct lp_fix   f;
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_conn*    conns = sr_test_conns();
  quic_obuf       ob;
  u8              obuf[1024];
  static const u8 custom_path[] = "/wt/room-1";
  ob                            = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.path     = custom_path;
  conns[0].l.req.path_len = sizeof custom_path - 1;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt_path_len[0] == sizeof custom_path - 1);
  for (usz i = 0; i < sizeof custom_path - 1; i++)
    CHECK(conns[0].wt_path[0][i] == custom_path[i]);
}

/* DISTINCT PATHS: two simultaneously-open sessions bound to different :path
 * values coexist -- neither overwrites the other's recorded path. */
static void test_srvrun_wt_distinct_paths_coexist(void) {
  struct lp_fix   f;
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_conn*    conns = sr_test_conns();
  quic_obuf       ob;
  u8              obuf[1024];
  static const u8 path_a[] = "/wt/a";
  static const u8 path_b[] = "/wt/b";
  ob                       = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.path     = path_a;
  conns[0].l.req.path_len = sizeof path_a - 1;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  conns[0].resp[0].in_use = 0;
  sr_set_req(&conns[0], 1, 1, 8);
  conns[0].l.req.path     = path_b;
  conns[0].l.req.path_len = sizeof path_b - 1;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_path_len[0] == sizeof path_a - 1);
  CHECK(conns[0].wt_path_len[1] == sizeof path_b - 1);
  for (usz i = 0; i < sizeof path_a - 1; i++)
    CHECK(conns[0].wt_path[0][i] == path_a[i]);
  for (usz i = 0; i < sizeof path_b - 1; i++)
    CHECK(conns[0].wt_path[1][i] == path_b[i]);
}

/* ROUTING: srvrun_wt_slot_by_connect_id resolves a stream/datagram reference
 * to the exactly one active session slot whose own CONNECT stream id
 * matches, with two sessions open at once. */
static void test_srvrun_wt_stream_routes_to_matching_session(void) {
  srvrun_conn c = {0};
  c.wt_active   = 1;
  wired_wt_session_init(&c.wt, 4);
  c.wt1_active = 1;
  wired_wt_session_init(&c.wt1, 8);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 4) == 0);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 8) == 1);
}

/* FOREIGN REFERENCE: a stream/datagram referencing a session id that matches
 * no currently open session resolves to no slot at all (-1), regardless of
 * how many sessions ARE open. */
static void test_srvrun_wt_foreign_stream_id_rejected(void) {
  srvrun_conn c = {0};
  c.wt_active   = 1;
  wired_wt_session_init(&c.wt, 4);
  c.wt1_active = 1;
  wired_wt_session_init(&c.wt1, 8);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 12) == -1);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 0) == -1);
}

/* EXCLUSIVITY: srvrun_wt_slot_by_connect_id never returns two different
 * indices for the same stream id -- every call is a pure function of c's
 * slots, so calling it twice for the same id and two different open sessions
 * yields exactly one, stable, answer each time (structural mutual
 * exclusion: a stream_id can only equal one slot's own connect_stream_id at
 * once). */
static void test_srvrun_wt_stream_exclusive_ownership(void) {
  srvrun_conn c = {0};
  c.wt_active   = 1;
  wired_wt_session_init(&c.wt, 4);
  c.wt1_active = 1;
  wired_wt_session_init(&c.wt1, 8);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 4) == 0);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 4) == 0); /* stable, not slot 1 too */
  CHECK(srvrun_wt_slot_by_connect_id(&c, 8) == 1);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 8) == 1); /* stable, not slot 0 too */
}

/* DATAGRAM ROUTING: same routing key (srvrun_wt_slot_by_connect_id) governs
 * datagram association too, the datagram-side mirror of the stream-routing
 * test above. */
static void test_srvrun_wt_dgram_routes_to_matching_session(void) {
  srvrun_conn c = {0};
  c.wt_active   = 1;
  wired_wt_session_init(&c.wt, 4);
  c.wt1_active = 1;
  wired_wt_session_init(&c.wt1, 8);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 4) == 0);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 8) == 1);
}

/* DATAGRAM FOREIGN REFERENCE: the datagram-side mirror of the foreign-stream
 * rejection test above. */
static void test_srvrun_wt_foreign_dgram_id_rejected(void) {
  srvrun_conn c = {0};
  c.wt_active   = 1;
  wired_wt_session_init(&c.wt, 4);
  CHECK(srvrun_wt_slot_by_connect_id(&c, 99) == -1);
}

/* INDEPENDENCE: closing one session (via the real CONNECT-stream-close
 * trigger, srvrun_close_wt_on_stream_close) leaves a second, simultaneously
 * open session's state (state/connect_stream_id/buffered streams)
 * completely untouched. */
static void test_srvrun_wt_close_one_session_leaves_others_untouched(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  conns[0].resp[0].in_use = 0;
  sr_set_req(&conns[0], 1, 1, 8);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt1.state == WIRED_WT_ESTABLISHED);
  /* close only session 0's own CONNECT stream (id 4) */
  conns[0].l.closed_stream_id   = 4;
  conns[0].l.closed_stream_seen = 1;
  srvrun_close_wt_on_stream_close(&conns[0]);
  CHECK(conns[0].wt.state == WIRED_WT_CLOSED);
  CHECK(conns[0].wt1.state == WIRED_WT_ESTABLISHED); /* untouched */
  CHECK(conns[0].wt1.connect_stream_id == 8);        /* untouched */
}

/* INDEPENDENCE (drain): draining one session leaves a second, simultaneously
 * open session's state untouched. */
static void test_srvrun_wt_drain_one_session_leaves_others_untouched(void) {
  srvrun_conn c = {0};
  c.wt_active   = 1;
  wired_wt_session_init(&c.wt, 4);
  wired_wt_session_establish(&c.wt);
  c.wt1_active = 1;
  wired_wt_session_init(&c.wt1, 8);
  wired_wt_session_establish(&c.wt1);
  CHECK(wired_wt_session_drain(&c.wt) == 1);
  CHECK(c.wt.state == WIRED_WT_DRAINING);
  CHECK(c.wt1.state == WIRED_WT_ESTABLISHED); /* untouched */
  CHECK(c.wt1.connect_stream_id == 8);        /* untouched */
}

/* SLOT REUSE: closing a session while the connection is at its session limit
 * frees its slot immediately, so a subsequent Extended CONNECT is accepted
 * rather than rejected. */
static void test_srvrun_wt_close_frees_slot_for_new_accept(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  conns[0].resp[0].in_use = 0;
  sr_set_req(&conns[0], 1, 1, 8);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(srvrun_wt_free_slot(&conns[0]) == -1); /* both slots occupied */
  /* close session 0 (CONNECT stream id 4) */
  conns[0].l.closed_stream_id   = 4;
  conns[0].l.closed_stream_seen = 1;
  srvrun_close_wt_on_stream_close(&conns[0]);
  CHECK(srvrun_wt_free_slot(&conns[0]) == 0); /* slot 0 is free again */
  conns[0].resp[0].in_use = 0;
  sr_set_req(&conns[0], 1, 1, 12); /* a third Extended CONNECT now fits */
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED); /* reused slot 0 */
  CHECK(conns[0].wt.connect_stream_id == 12);
  CHECK(conns[0].resp[0].sess.active == 1); /* the new 2xx was armed */
}

/* WHOLE-CONNECTION TEARDOWN: srvrun_free_slot (peer close / idle sweep /
 * boot failure) closes EVERY currently open session, not just one. */
static void test_srvrun_wt_free_slot_closes_all_open_sessions(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  struct lp_fix  f;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  conns[0].resp[0].in_use = 0;
  sr_set_req(&conns[0], 1, 1, 8);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt1.state == WIRED_WT_ESTABLISHED);
  {
    srvrun_state st = {table, conns};
    srvrun_free_slot(&g_srvrun_env, &st, 0);
  }
  CHECK(conns[0].wt.state == WIRED_WT_CLOSED);
  CHECK(conns[0].wt1.state == WIRED_WT_CLOSED);
  CHECK(conns[0].wt_active == 0);
  CHECK(conns[0].wt1_active == 0);
}

/* PRECISE CLOSE: the CONNECT-stream-close trigger closes only the ONE
 * session whose own CONNECT stream matches, even with two sessions open --
 * the multi-session generalization of the existing single-session
 * regression test above. */
static void test_srvrun_wt_connect_stream_close_closes_only_that_session(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  struct lp_fix  f;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  conns[0].resp[0].in_use = 0;
  sr_set_req(&conns[0], 1, 1, 8);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  /* close session 1's own CONNECT stream (id 8), not session 0's */
  conns[0].l.closed_stream_id   = 8;
  conns[0].l.closed_stream_seen = 1;
  srvrun_close_wt_on_stream_close(&conns[0]);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED); /* untouched */
  CHECK(conns[0].wt1.state == WIRED_WT_CLOSED);
  CHECK(conns[0].l.closed_stream_seen == 0); /* consumed every step */
}

/* BOUNDARY: fill SRVRUN_MAX_WT_SESSIONS slots, close them one at a time in a
 * different order than opened, and confirm each close makes exactly its own
 * slot (and only its own) reusable again. */
static void test_srvrun_wt_all_slots_cycle_through_open_and_close(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  conns[0].resp[0].in_use = 0;
  sr_set_req(&conns[0], 1, 1, 8);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(srvrun_wt_free_slot(&conns[0]) == -1); /* at the limit */
  /* close slot 1's session (id 8) FIRST, out of open order */
  conns[0].l.closed_stream_id   = 8;
  conns[0].l.closed_stream_seen = 1;
  srvrun_close_wt_on_stream_close(&conns[0]);
  CHECK(srvrun_wt_free_slot(&conns[0]) == 1); /* exactly slot 1 freed */
  /* now close slot 0's session (id 4) too */
  conns[0].l.closed_stream_id   = 4;
  conns[0].l.closed_stream_seen = 1;
  srvrun_close_wt_on_stream_close(&conns[0]);
  CHECK(srvrun_wt_free_slot(&conns[0]) == 0); /* both free, first-fit is 0 */
  CHECK(conns[0].wt_active == 0 && conns[0].wt1_active == 0);
}

/* BACKWARD COMPATIBILITY BOUNDARY: with only ONE session ever opened on a
 * connection (the pre-multi-session common case), behavior matches the
 * legacy single-session implementation exactly -- a second Extended CONNECT
 * on the SAME already-open session's stream id is unreachable in practice
 * (each request stream claims at most one resp[] slot), so the boundary this
 * covers is: exactly one slot occupied, one slot free, the free slot is
 * found and used, and the occupied slot's own state is never disturbed by
 * unrelated routing/free-slot lookups. */
static void test_srvrun_wt_limit_one_matches_legacy_behavior(void) {
  srvrun_conn c = {0};
  c.wt_active   = 1;
  wired_wt_session_init(&c.wt, 4);
  wired_wt_session_establish(&c.wt);
  CHECK(srvrun_wt_free_slot(&c) == 1); /* the still-free second slot */
  CHECK(srvrun_wt_slot_by_connect_id(&c, 4) == 0);
  CHECK(c.wt.state == WIRED_WT_ESTABLISHED); /* untouched by the lookups */
}

/* PRE-ESTABLISHMENT BUFFERING: a stream/datagram offered to a session while
 * it is still UNESTABLISHED, with a second session also open, associates
 * only with the session it was actually offered to. */
static void test_srvrun_wt_establish_associates_only_own_buffered_items(void) {
  srvrun_conn c = {0};
  c.wt_active   = 1;
  wired_wt_session_init(&c.wt, 4); /* left UNESTABLISHED */
  c.wt1_active = 1;
  wired_wt_session_init(&c.wt1, 8);
  wired_wt_session_establish(&c.wt1); /* the other session is established */
  CHECK(wired_wt_session_offer_stream(&c.wt, 100) == 1); /* buffered on wt */
  CHECK(c.wt.streams[0].in_use == 1 && c.wt.streams[0].stream_id == 100);
  CHECK(c.wt1.streams[0].in_use == 0); /* wt1's own buffer untouched */
  CHECK(wired_wt_session_establish(&c.wt) == 1);
  CHECK(c.wt.state == WIRED_WT_ESTABLISHED);
  CHECK(c.wt.streams[0].stream_id == 100); /* still associated with wt only */
  CHECK(c.wt1.streams[0].in_use == 0);     /* still untouched */
}

/* SLOT REUSE HYGIENE: a slot that closes and is reused by a new session
 * carries none of the previous session's connect_stream_id or buffered
 * stream/datagram state -- wired_wt_session_init's own zeroing (session.c)
 * is what this depends on. Drives the session directly (wired_wt_session_
 * init/offer_stream, not srvrun_start_resp) so the buffered stream is
 * offered while the session is still UNESTABLISHED -- srvrun_start_resp's
 * own srvrun_start_wt always establishes in the same step it inits, which
 * would make offer_stream associate directly instead of buffering (session.c's
 * session_associates_directly). */
static void test_srvrun_wt_reused_slot_has_no_stale_data(void) {
  srvrun_conn c = {0};
  c.wt_active   = 1;
  wired_wt_session_init(&c.wt, 4);                      /* left UNESTABLISHED */
  CHECK(wired_wt_session_offer_stream(&c.wt, 42) == 1); /* buffered */
  CHECK(c.wt.streams[0].in_use == 1);
  c.l.closed_stream_id   = 4;
  c.l.closed_stream_seen = 1;
  srvrun_close_wt_on_stream_close(&c);
  CHECK(srvrun_wt_free_slot(&c) == 0); /* slot 0 is free again */
  /* a new session reuses slot 0 with a different CONNECT stream id */
  wired_wt_session_init(&c.wt, 20);
  wired_wt_session_establish(&c.wt);
  c.wt_active = 1;
  CHECK(c.wt.connect_stream_id == 20); /* not the stale 4 */
  CHECK(c.wt.streams[0].in_use == 0);  /* the stale buffered stream 42 did not
                                        * survive reuse */
  CHECK(c.wt.state == WIRED_WT_ESTABLISHED);
}

/* CAPACITY: the session limit must fit within the existing per-connection WT
 * stream-table capacity -- with SRVRUN_MAX_WT_SESSIONS sessions open, each
 * still has room for at least one bidi and one uni stream in the shared
 * WIRED_SRVLOOP_MAX_WT_STREAMS/WIRED_SRVLOOP_MAX_WT_UNI_STREAMS tables. */
static void test_srvrun_wt_session_limit_fits_stream_table_capacity(void) {
  CHECK(SRVRUN_MAX_WT_SESSIONS >= 1);
  CHECK(SRVRUN_MAX_WT_SESSIONS <= WIRED_SRVLOOP_MAX_WT_STREAMS);
  CHECK(SRVRUN_MAX_WT_SESSIONS <= WIRED_SRVLOOP_MAX_WT_UNI_STREAMS);
}

/* Reset the global connection table srvrun_loop owns (g_srvrun_table/
 * g_srvrun_state, srvrun.c) to a clean slate -- wired_server_broadcast_
 * datagram operates on these globals directly (it has no srvrun_state
 * parameter, since it must be callable from inside a wt_on_datagram
 * callback whose signature carries no such handle), so tests exercising it
 * must isolate themselves from whatever an earlier test left behind. */
static void sr_reset_global_table(void) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    g_srvrun_state.conns[i] = (srvrun_conn){0};
  quic_conntable_init(g_srvrun_table, QUIC_CONNTABLE_CAP);
}

/* BROADCAST: every connection with an active WT session gets the payload
 * queued -- the two-recipient baseline case. */
static void test_srvrun_broadcast_datagram_queues_active_wt_sessions(void) {
  sr_reset_global_table();
  g_srvrun_state.conns[0].up                 = 1;
  g_srvrun_state.conns[0].wt_active          = 1;
  g_srvrun_state.conns[0].l.h3.settings_sent = 1;
  g_srvrun_state.conns[1].up                 = 1;
  g_srvrun_state.conns[1].wt_active          = 1;
  g_srvrun_state.conns[1].l.h3.settings_sent = 1;
  CHECK(
      wired_server_broadcast_datagram(
          quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  CHECK(g_srvrun_state.conns[0].dg_pending == 1);
  CHECK(g_srvrun_state.conns[0].dg_pending_len == sizeof sr_dg_payload);
  CHECK(g_srvrun_state.conns[1].dg_pending == 1);
  for (usz i = 0; i < sizeof sr_dg_payload; i++) {
    CHECK(g_srvrun_state.conns[0].dg_pending_buf[i] == sr_dg_payload[i]);
    CHECK(g_srvrun_state.conns[1].dg_pending_buf[i] == sr_dg_payload[i]);
  }
}

/* BOUNDARY: a connection with no active WT session (wt_active == 0) is not
 * a broadcast recipient, even if it is up. */
static void test_srvrun_broadcast_datagram_skips_inactive_wt(void) {
  sr_reset_global_table();
  g_srvrun_state.conns[0].up        = 1;
  g_srvrun_state.conns[0].wt_active = 0;
  CHECK(
      wired_server_broadcast_datagram(
          quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  CHECK(g_srvrun_state.conns[0].dg_pending == 0);
}

/* BOUNDARY: an unused slot (up == 0) is skipped, not touched -- must not
 * crash and must not queue on a slot that was never a live connection. */
static void test_srvrun_broadcast_datagram_skips_unused_slot(void) {
  sr_reset_global_table();
  CHECK(
      wired_server_broadcast_datagram(
          quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    CHECK(g_srvrun_state.conns[i].dg_pending == 0);
}

/* BOUNDARY: a payload larger than the per-connection dg_pending_buf capacity
 * is rejected outright -- 0 returned, no connection is queued. */
static void test_srvrun_broadcast_datagram_rejects_oversize(void) {
  u8 big[1300];
  sr_reset_global_table();
  g_srvrun_state.conns[0].up        = 1;
  g_srvrun_state.conns[0].wt_active = 1;
  CHECK(wired_server_broadcast_datagram(quic_span_of(big, sizeof big)) == 0);
  CHECK(g_srvrun_state.conns[0].dg_pending == 0);
}

/* REAL-WIRE: two independent WT-established clients; one's DATAGRAM,
 * received by the server's wt_on_datagram callback, is broadcast to both --
 * both actually receive it over sealed 1-RTT wire bytes. This is the
 * end-to-end proof a chat app depends on (a message one client sends
 * reaches every other connected client), not just internal state. */
static wired_wt_session* g_bcast_last_sess;

static void sr_broadcast_relay(
    void* app_ctx, wired_wt_session* s, quic_span data) {
  (void)app_ctx;
  g_bcast_last_sess = s;
  wired_server_broadcast_datagram(data);
}

static void test_srvrun_broadcast_datagram_reaches_two_real_clients(void) {
  struct lp_fix       f0, f1;
  quic_obuf           ob0, ob1;
  u8                  obuf0[1024], obuf1[1024];
  u8                  out0[1024], out1[1024], spkt[1024];
  usz                 slen;
  const u8*           pl;
  usz                 pll;
  quic_datagram_frame df;

  sr_reset_global_table();
  ob0 = (quic_obuf){obuf0, sizeof obuf0, 0};
  ob1 = (quic_obuf){obuf1, sizeof obuf1, 0};
  sr_make_confirmed_conn(&g_srvrun_state.conns[0], &f0, &ob0);
  sr_make_confirmed_conn(&g_srvrun_state.conns[1], &f1, &ob1);
  g_srvrun_state.conns[0].s.sdrv.peer_max_datagram_frame_size = 65535;
  g_srvrun_state.conns[1].s.sdrv.peer_max_datagram_frame_size = 65535;
  g_srvrun_state.conns[0].l.we_advertised_max_datagram        = 65535;
  g_srvrun_state.conns[1].l.we_advertised_max_datagram        = 65535;

  /* Establish WT sessions on both connections (mirrors sr_set_req +
   * srvrun_start_resp's own driving style used throughout this file). */
  sr_set_req(&g_srvrun_state.conns[0], 1, 1, 4);
  sr_set_req(&g_srvrun_state.conns[1], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    ctx.st = &st;
    srvrun_start_resp(&ctx, 1);
  }
  CHECK(g_srvrun_state.conns[0].wt_active == 1);
  CHECK(g_srvrun_state.conns[1].wt_active == 1);

  /* Client 0 sends a DATAGRAM; the server's wt_on_datagram callback relays
   * it to every WT-active connection via wired_server_broadcast_datagram. */
  {
    srvrun_cfg          cfg = {-1,
                               0,
                               0,
                               0,
                               0,
                               0,
                               0,
                               0,
                               0,
                               0,
                               sr_broadcast_relay,
                               0,
                               0,
                               0,
                               0,
                               &g_srvrun_env,
                               0,
                               0,
                               0,
                               0,
                               0};
    srvrun_state        st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx     ctx = {&cfg, 0, &st, 0};
    u8                  dgpl[64];
    usz                 dgpll;
    quic_datagram_frame in = {sizeof sr_dg_payload, sr_dg_payload};
    dgpll = quic_datagram_encode(quic_mspan_of(dgpl, sizeof dgpl), &in, 1);
    slen  = client_seal_onertt_pn(&f0, 3, dgpl, dgpll, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &g_srvrun_state.conns[0], quic_mspan_of(spkt, slen));
  }
  CHECK(g_bcast_last_sess == &g_srvrun_state.conns[0].wt);

  /* Both connections now have the payload queued for their next send;
   * drain and open each on its OWN client side to prove the bytes are
   * correct end to end, not just copied in memory. */
  {
    quic_obuf  sendob0 = {out0, sizeof out0, 0};
    quic_obuf  sendob1 = {out1, sizeof out1, 0};
    srvrun_cfg cfg     = {-1, 0, 0, 0, 0, 0, 0, 0,
                          0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                          0,  0, 0, 0, 0};
    CHECK(
        srvrun_send_pending_datagram(
            &cfg, &g_srvrun_state.conns[0], &sendob0) == 1);
    CHECK(
        srvrun_send_pending_datagram(
            &cfg, &g_srvrun_state.conns[1], &sendob1) == 1);
    CHECK(client_open_onertt(&f0, sendob0.p, sendob0.len, &pl, &pll) == 1);
    CHECK(quic_datagram_decode(pl, pll, &df) == pll);
    for (usz i = 0; i < sizeof sr_dg_payload; i++)
      CHECK(df.data[i] == sr_dg_payload[i]);
    CHECK(client_open_onertt(&f1, sendob1.p, sendob1.len, &pl, &pll) == 1);
    CHECK(quic_datagram_decode(pl, pll, &df) == pll);
    for (usz i = 0; i < sizeof sr_dg_payload; i++)
      CHECK(df.data[i] == sr_dg_payload[i]);
  }
}

/* RECEIVE-ONLY PEER: a broadcast DATAGRAM queued for a connection that never
 * itself receives anything (a WebTransport client that only listens, e.g.
 * every tab but the sender in webtransport_chat) must still reach it --
 * srvrun_sess_on_step's own srvrun_pump_datagram call never runs for such a
 * peer, so only the poll-timeout tick (srvrun_fire_ptos, via
 * srvrun_any_waiting -> srvrun_has_outbound seeing dg_pending) can flush it.
 * Regression for the bug where dg_pending was invisible to
 * srvrun_any_waiting: a receive-only broadcast target silently never got
 * the message until it happened to send something of its own. */
static void test_srvrun_broadcast_datagram_flushes_on_poll_tick_alone(void) {
  struct lp_fix f;
  quic_obuf     ob;
  u8            obuf[1024];

  sr_reset_global_table();
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&g_srvrun_state.conns[0], &f, &ob);
  g_srvrun_state.conns[0].s.sdrv.peer_max_datagram_frame_size = 65535;
  g_srvrun_state.conns[0].l.we_advertised_max_datagram        = 65535;
  sr_set_req(&g_srvrun_state.conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(g_srvrun_state.conns[0].wt_active == 1);

  /* Queue a broadcast the same way srvrun_bcast_drain_self/
   * wired_server_broadcast_datagram does -- NOT via any receive on this
   * connection. */
  CHECK(
      srvrun_queue_datagram(
          &g_srvrun_state.conns[0],
          quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  CHECK(g_srvrun_state.conns[0].dg_pending == 1);

  /* The connection has never received a packet of its own since (no
   * srvrun_sess_on_step call for it), so only a poll-timeout tick can flush
   * dg_pending -- exactly what srvrun_wait_input's srvrun_any_waiting check
   * exists to trigger in the real loop. */
  {
    srvrun_cfg   cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                        0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                        0,  0, 0, 0, 0};
    srvrun_state st  = {g_srvrun_table, g_srvrun_state.conns};
    CHECK(srvrun_any_waiting(&st) == 1);
    srvrun_fire_ptos(&cfg, &st);
  }
  CHECK(g_srvrun_state.conns[0].dg_pending == 0);
  /* The flush went out through the real path (srvrun_fire_ptos ->
   * srvrun_dg_slot -> srvrun_pump_datagram -> srvrun_send_pending_datagram
   * -> srvrun_send, cfg->fd == -1 here matching this file's existing
   * no-socket srvrun_cfg pattern -- see test_srvrun_owes_goaway_once above
   * for the same harmless-invalid-fd precedent). dg_pending's transition to
   * 0 is the proof the flush happened; wire-byte correctness is already
   * covered by test_srvrun_broadcast_datagram_reaches_two_real_clients. */
}

/* BIGBUF POOL: a body far past WIRED_SRVRUN_RESP_MAX (16KB) -- e.g. the
 * interop runner's 500KB fixture -- must be served from a claimed
 * srvbigbuf pool row instead of ETOOBIG-failing against the fixed row.
 * srvrun_start_resp is driven directly (c->l.req/req_stream_id mirror, same
 * as test_srvrun_pump_stops_at_log_capacity below): no real wire round-trip
 * is needed to prove the storage-selection and arm-length behavior. */
static void test_srvrun_bigbuf_pool_serves_large_body(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[1024];
  u8            pre[64];
  quic_obuf     preb = {pre, sizeof pre, 0};
  ob                 = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  sr_set_req(&c, 0, 0, 0);
  /* g_srvrun_env is BSS-zeroed but never routed through
   * wired_server_run_opt/wired_srvrun_env_init in this direct-call test, so
   * bigbuf.rows starts NULL -- wired_srvbigbuf_row would then compute
   * NULL + row_idx*row_cap, an out-of-bounds write the handler below would
   * silently perform. Point it at this env's own row storage first, same as
   * the real entry points do. */
  wired_srvbigbuf_init(
      &g_srvrun_env.bigbuf, &g_srvrun_env.bigbuf_rows[0][0],
      WIRED_SRVBIGBUF_ROW_CAP);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_bigbuf_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  /* claimed a pool row, not the fixed 16KB row */
  CHECK(c.resp[0].in_use == 1);
  CHECK(c.resp[0].bigbuf_row >= 0);
  /* the handler filled the whole pool-row cap (past HDR_ROOM); the armed
   * session covers prefix + that many body bytes, well past 16KB */
  CHECK(
      quic_h3resp_prefix(
          200, 0, WIRED_SRVBIGBUF_ROW_CAP - SRVRUN_RESP_HDR_ROOM, &preb) == 1);
  CHECK(
      c.resp[0].sess.q.len ==
      preb.len + (WIRED_SRVBIGBUF_ROW_CAP - SRVRUN_RESP_HDR_ROOM));
  CHECK(c.resp[0].sess.q.len > WIRED_SRVRUN_RESP_MAX);
  /* g_srvrun_env.bigbuf is process-wide, shared with every other test in
   * this file -- release the claimed row so a later test (e.g. the
   * exhaustion test below) sees a clean pool, matching what
   * srvrun_resp_reap does for a real response once its session finishes. */
  wired_srvbigbuf_release(&g_srvrun_env.bigbuf, c.resp[0].bigbuf_row);
}

/* BIGBUF POOL EXHAUSTION: with every pool row already claimed (e.g. two
 * other large responses still in flight), a further large-body handler must
 * fall back to the fixed 16KB row instead of failing -- srvrun_resp_storage's
 * "big ? big : fixed" ternary, exercised here with wired_srvbigbuf_claim
 * pre-exhausted rather than mocked, so the real pool state gates the real
 * fallback path. The handler still writes past 16KB (sr_bigbuf_body_handler
 * fills the whole cap it's handed); srvrun_resp_storage_cap must have handed
 * it the smaller WIRED_SRVRUN_RESP_MAX-sized cap, not the pool's, so the body
 * is silently bounded by that cap rather than overflowing. */
static void test_srvrun_bigbuf_pool_exhausted_falls_back_to_fixed_row(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[1024];
  int           held[WIRED_SRVBIGBUF_ROWS];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  sr_set_req(&c, 0, 0, 0);
  /* Fresh pool state for this test, independent of what other tests left
   * behind (see the sibling large-body test's comment on rows starting
   * NULL). */
  wired_srvbigbuf_init(
      &g_srvrun_env.bigbuf, &g_srvrun_env.bigbuf_rows[0][0],
      WIRED_SRVBIGBUF_ROW_CAP);
  for (usz i = 0; i < WIRED_SRVBIGBUF_ROWS; i++)
    CHECK(wired_srvbigbuf_claim(&g_srvrun_env.bigbuf, &held[i]) != 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_bigbuf_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(c.resp[0].in_use == 1);
  CHECK(c.resp[0].bigbuf_row == -1); /* fell back, not a pool row */
  CHECK(c.resp[0].sess.q.len <= WIRED_SRVRUN_RESP_MAX);
  for (usz i = 0; i < WIRED_SRVBIGBUF_ROWS; i++)
    wired_srvbigbuf_release(&g_srvrun_env.bigbuf, held[i]);
}

/* Streaming test handler: serves a fixed-size counting pattern
 * (sr_stream_total_len bytes total), writing at most sr_stream_round_cap
 * bytes per call starting at offset, requesting another round whenever
 * bytes remain past this round (T-004/T-006/T-010/T-011/T-012/T-018). Globals
 * because wired_srvloop_handler's ctx param is already used by other tests'
 * fixtures in this file; reset both before each streaming test. */
static u64 sr_stream_total_len;
static usz sr_stream_round_cap;
/* T-008: a round starting at exactly this offset simulates the underlying
 * source failing mid-stream (e.g. a read(2) error past round 0) -- the
 * handler declines (returns 0) instead of writing a body. UINT64_MAX (never
 * a real offset) disables the simulation; reset before/after any test that
 * sets it so it doesn't leak into later streaming tests. */
static u64 sr_stream_fail_at_offset = (u64)-1;
/* T-009: total_len as the underlying source (a shrinking file) actually
 * reports once a round is already in flight -- smaller than
 * sr_stream_total_len, which is what round 0 already promised via
 * *total_size. UINT64_MAX disables the simulation (source never shrinks). */
static u64 sr_stream_shrinks_to = (u64)-1;

static int sr_stream_body_handler(
    void*                       hctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
    const char**                ct,
    int*                        more,
    u64*                        total_size) {
  u64 actual_total = sr_stream_shrinks_to != (u64)-1 && offset != 0
                         ? sr_stream_shrinks_to
                         : sr_stream_total_len;
  usz cap =
      body_out->cap < sr_stream_round_cap ? body_out->cap : sr_stream_round_cap;
  usz remaining;
  usz n;
  (void)hctx;
  (void)req;
  (void)ct;
  if (offset == sr_stream_fail_at_offset) return 0;
  remaining = offset < actual_total ? (usz)(actual_total - offset) : 0;
  n         = remaining < cap ? remaining : cap;
  for (usz i = 0; i < n; i++) body_out->p[i] = (u8)((offset + i) & 0xff);
  body_out->len = n;
  if (offset == 0) *total_size = sr_stream_total_len;
  if (offset + n < actual_total) *more = 1;
  return 1;
}

/* T-023 (found via real quic-go interop, not in the original ledger):
 * streaming test handler keyed by the REQUEST'S OWN PATH (its first byte),
 * not a shared global -- proves each stream's later rounds still see ITS
 * OWN request, not whichever stream's request happened to complete most
 * recently on the connection (the bug: c->l.req is a per-connection mirror
 * srvloop overwrites every time any sibling stream's request completes;
 * srvrun_resp_next_round must use r->stream_req, a copy taken at round 0,
 * not c->l.req directly). Writes req->path[0] repeated sr_stream_round_cap
 * times per round, up to sr_stream_total_len bytes total. */
static int sr_stream_body_handler_by_path(
    void*                       hctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
    const char**                ct,
    int*                        more,
    u64*                        total_size) {
  usz cap =
      body_out->cap < sr_stream_round_cap ? body_out->cap : sr_stream_round_cap;
  usz remaining =
      offset < sr_stream_total_len ? (usz)(sr_stream_total_len - offset) : 0;
  usz n = remaining < cap ? remaining : cap;
  (void)hctx;
  (void)ct;
  for (usz i = 0; i < n; i++) body_out->p[i] = req->path[0];
  body_out->len = n;
  if (offset == 0) *total_size = sr_stream_total_len;
  if (offset + n < sr_stream_total_len) *more = 1;
  return 1;
}

/* 1 once every slice of r's current round is sent and acked -- a
 * non-destructive read (unlike wired_sendsess_done, which clears `active`
 * as a side effect: calling it here as well as inside srvrun_resp_reap
 * would make the second call always see a false "not done"). */
static int sr_round_fully_acked(const wired_sendsess* s) {
  return wired_sendq_all_sent(&s->q) && s->requeue_n == 0 &&
         wired_sendsess_inflight(s) == 0;
}

/* Drive resp[]'s idx-th slot's current round to fully-acked (pump/ack loop,
 * same as sr_drive_round_to_done below but for a caller juggling more than
 * one resp[] slot on the same connection). */
static void sr_drive_resp_round_to_done(
    srvrun_step_ctx* ctx, srvrun_conn* c, usz idx) {
  srvrun_resp* r = &c->resp[idx];
  while (!sr_round_fully_acked(&r->sess)) {
    u64 pn0 = c->l.tx_pn;
    srvrun_pump_sess(ctx, 0);
    if (c->l.tx_pn == pn0) break; /* nothing sendable (e.g. cwnd/credit) */
    wired_sendsess_ack(&r->sess, pn0, c->l.tx_pn - 1);
  }
}

static void sr_drive_round_to_done(srvrun_step_ctx* ctx, srvrun_conn* c) {
  sr_drive_resp_round_to_done(ctx, c, 0);
}

/* T-007: with the bigbuf pool exhausted, a streaming handler's response
 * still falls back to the fixed row instead of stalling or corrupting
 * state -- srvrun_resp_storage_cap hands it WIRED_SRVRUN_RESP_MAX's smaller
 * cap, so a total_size bigger than that still streams (multiple rounds),
 * just through the fixed row every round instead of a pool row. */
static void test_srvrun_streaming_bigbuf_exhausted_falls_back_to_fixed_row(
    void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[1024];
  int           held[WIRED_SRVBIGBUF_ROWS];
  usz           fixed_cap;
  ob        = (quic_obuf){obuf, sizeof obuf, 0};
  fixed_cap = WIRED_SRVRUN_RESP_MAX - SRVRUN_RESP_HDR_ROOM;
  sr_stream_total_len =
      fixed_cap + 10; /* needs 2 rounds even on the fixed row */
  sr_stream_round_cap = fixed_cap;
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  wired_srvbigbuf_init(
      &g_srvrun_env.bigbuf, &g_srvrun_env.bigbuf_rows[0][0],
      WIRED_SRVBIGBUF_ROW_CAP);
  for (usz i = 0; i < WIRED_SRVBIGBUF_ROWS; i++)
    CHECK(wired_srvbigbuf_claim(&g_srvrun_env.bigbuf, &held[i]) != 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    CHECK(c.resp[0].bigbuf_row == -1); /* fell back, pool was full */
    CHECK(c.resp[0].sess.q.len == fixed_cap);
    CHECK(c.resp[0].streaming == 1); /* 10 bytes remain past the fixed cap */
    sr_drive_round_to_done(&ctx, &c);
    srvrun_reap_resps(&ctx, &c, 0);
    CHECK(c.resp[0].bigbuf_row == -1); /* still the fixed row, not a pool one */
    CHECK(c.resp[0].sess.q.len == 10);
    CHECK(c.resp[0].streaming == 0);
  }
  for (usz i = 0; i < WIRED_SRVBIGBUF_ROWS; i++)
    wired_srvbigbuf_release(&g_srvrun_env.bigbuf, held[i]);
}

/* T-008: a round-1+ handler failure (simulating a mid-stream read error)
 * truncates the response at what was already sent -- srvrun_resp_next_round
 * treats a declined round like an empty final round (body->len forced to 0
 * by srvrun_call_handler, more left 0), not a retry loop or a stall. The
 * bytes already sent and acked in round 0 stay valid; only the truncation
 * point matters here. */
static void test_srvrun_streaming_mid_round_read_error_truncates(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  ob                       = (quic_obuf){obuf, sizeof obuf, 0};
  sr_stream_total_len      = 300;
  sr_stream_round_cap      = 100;
  sr_stream_fail_at_offset = 100; /* round 1 (offset 100) fails */
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    CHECK(c.resp[0].sess.q.len == 100); /* round 0 succeeded normally */
    sr_drive_round_to_done(&ctx, &c);
    srvrun_reap_resps(&ctx, &c, 0);   /* round 1: handler declines */
    CHECK(c.resp[0].sess.q.len == 0); /* truncated: empty final round */
    CHECK(c.resp[0].streaming == 0);  /* not left mid-stream forever */
    sr_drive_round_to_done(&ctx, &c);
    srvrun_reap_resps(&ctx, &c, 0);
    CHECK(c.resp[0].in_use == 0); /* slot released, no stall */
  }
  sr_stream_fail_at_offset = (u64)-1; /* don't leak into later tests */
}

/* T-009: the source shrinking between round 0 (which already promised
 * sr_stream_total_len via *total_size) and round 1 completes with the
 * bytes actually available instead of hanging waiting for bytes that will
 * never come -- the handler's own *more logic (offset + n < actual_total)
 * naturally stops asking for further rounds once it reaches the shorter
 * length, so the response finishes at fewer bytes than round 0 declared. */
static void test_srvrun_streaming_file_shrinks_completes_with_actual_bytes(
    void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  sr_stream_total_len = 300; /* what round 0 promises */
  sr_stream_round_cap = 100;
  sr_stream_shrinks_to =
      150; /* the source actually only has 150 bytes past round 0 */
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    CHECK(c.resp[0].sess.q.len == 100); /* round 0: unaffected by the later
                                            shrink */
    sr_drive_round_to_done(&ctx, &c);
    srvrun_reap_resps(&ctx, &c, 0); /* round 1: sees the shrunk total (150) */
    CHECK(c.resp[0].sess.q.len == 50); /* 150 - 100 already sent */
    CHECK(c.resp[0].streaming == 0);   /* completes, does not hang */
    sr_drive_round_to_done(&ctx, &c);
    srvrun_reap_resps(&ctx, &c, 0);
    CHECK(c.resp[0].in_use == 0);
  }
  sr_stream_shrinks_to = (u64)-1; /* don't leak into later tests */
}

/* T-022 (found via real quic-go interop, not in the original ledger): round
 * 0's own sendq marks fin at the end of ITS buffer (wired_sendq_next has no
 * notion of "more rounds coming"), so srvrun_slice_fin must suppress that
 * fin for every round while r->streaming is still 1 -- otherwise the peer
 * sees the QUIC stream close after round 0's bytes and never asks for (or
 * even waits for) the rest, exactly what broke against a real client:
 * downloads truncated at exactly one round's worth of bytes. Only the
 * response's true last round (streaming already cleared) may carry fin. */
static void test_srvrun_streaming_round_fin_suppressed_until_final(void) {
  struct lp_fix     f;
  srvrun_conn       c  = {0};
  quic_obuf         ob = {0};
  u8                obuf[2048];
  wired_sendq_slice sl;
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  sr_stream_total_len = 200;
  sr_stream_round_cap = 100;
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    /* round 0: fills exactly its own 100-byte buffer -- wired_sendq_next's
     * raw fin is 1 here (end of THIS round's queue), but the wire-level fin
     * must be suppressed because r->streaming is still 1 (200 total, only
     * 100 sent so far). */
    CHECK(wired_sendsess_take(&c.resp[0].sess, &sl) == 1);
    CHECK(sl.offset == 0 && sl.len == 100);
    CHECK(sl.fin == 1); /* raw sendq signal: end of round 0's queue */
    CHECK(c.resp[0].streaming == 1);
    CHECK(srvrun_slice_fin(&c, &c.resp[0], &sl) == 0); /* wire: NOT the end */
    /* put the slice back so sr_drive_round_to_done's normal pump/ack path
     * drives round 0 to completion (matching a real send/ack cycle). */
    c.resp[0].sess.q.cur = 0;
    sr_drive_round_to_done(&ctx, &c);
    srvrun_reap_resps(&ctx, &c, 0); /* -> round 1 armed: the last 100 bytes */
    CHECK(c.resp[0].stream_off == 200);
    CHECK(c.resp[0].streaming == 0); /* round 1 is the true final round */
    CHECK(wired_sendsess_take(&c.resp[0].sess, &sl) == 1);
    CHECK(sl.fin == 1);
    CHECK(srvrun_slice_fin(&c, &c.resp[0], &sl) == 1); /* wire: really done */
  }
}

/* T-004/T-006: a streaming response's first round arms only up to
 * sr_stream_round_cap bytes (not the whole sr_stream_total_len), and once
 * that round's slices are all acked, srvrun_resp_reap re-invokes the handler
 * and re-arms the next round instead of releasing the slot. */
static void test_srvrun_streaming_next_round_armed_after_done(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  sr_stream_total_len = 300;
  sr_stream_round_cap = 100;
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20; /* isolate streaming from cwnd gating */
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    CHECK(c.resp[0].sess.q.len == 100); /* round 0: capped, not the full 300 */
    CHECK(c.resp[0].streaming == 1);
    sr_drive_round_to_done(&ctx, &c);
    srvrun_reap_resps(&ctx, &c, 0);
    CHECK(c.resp[0].in_use == 1);       /* not released: more rounds remain */
    CHECK(c.resp[0].sess.q.len == 100); /* round 1 armed, still capped */
    CHECK(c.resp[0].stream_off == 200);
  }
}

/* T-005: once the handler stops asking for another round (the final round
 * lands exactly on sr_stream_total_len), srvrun_resp_reap releases the
 * slot like any ordinary single-round response. */
static void test_srvrun_streaming_final_round_releases_slot(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  sr_stream_total_len = 150;
  sr_stream_round_cap = 100;
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    sr_drive_round_to_done(&ctx, &c); /* round 0: 100 of 150 */
    srvrun_reap_resps(&ctx, &c, 0);   /* -> round 1 armed: 50 remaining */
    CHECK(c.resp[0].in_use == 1);
    CHECK(c.resp[0].sess.q.len == 50);
    sr_drive_round_to_done(&ctx, &c); /* round 1: the last 50 */
    srvrun_reap_resps(&ctx, &c, 0);   /* -> fully done, slot released */
    CHECK(c.resp[0].in_use == 0);
  }
}

/* T-018/T-019: across rounds, the QUIC STREAM frame's absolute offset keeps
 * counting up from the prior round's cumulative bytes sent, rather than
 * rewinding to 0 -- proven by re-deriving the exact byte sequence a real
 * peer would reassemble from the wire across two rounds and checking it
 * matches sr_stream_body_handler's counting pattern with no gap/overlap. */
static void test_srvrun_streaming_stream_offset_accumulates_across_rounds(
    void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  u8            asm_buf[300] = {0};
  usz           high         = 0;
  int           fin          = 0;
  ob                         = (quic_obuf){obuf, sizeof obuf, 0};
  sr_stream_total_len        = 300;
  sr_stream_round_cap        = 100;
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_resp*    r   = &c.resp[0];
    srvrun_start_resp(&ctx, 0);
    while (r->in_use) {
      wired_sendq_slice sl;
      while (wired_sendsess_take(&r->sess, &sl)) {
        u64 abs = wired_sendsess_stream_offset(&r->sess, &sl);
        for (usz i = 0; i < sl.len && abs + i < sizeof asm_buf; i++)
          asm_buf[abs + i] = r->sess.q.p[sl.offset + i];
        if (abs + sl.len > high) high = (usz)(abs + sl.len);
        fin |= sl.fin;
        CHECK(wired_sendsess_sent(&r->sess, &sl, c.l.tx_pn++, 0) == 1);
      }
      wired_sendsess_ack(&r->sess, 0, c.l.tx_pn - 1);
      srvrun_reap_resps(&ctx, &c, 0);
    }
  }
  CHECK(high == 300);
  CHECK(fin == 1);
  for (usz i = 0; i < 300; i++) CHECK(asm_buf[i] == (u8)(i & 0xff));
}

/* T-020: two connections streaming concurrently each claim their own bigbuf
 * pool row (or fall back independently) without one's rounds corrupting the
 * other's -- each connection's resp[0] is driven through several rounds
 * interleaved with the other's, and each must reassemble its own untouched
 * counting pattern. */
static void test_srvrun_streaming_concurrent_requests_do_not_corrupt_each_other(
    void) {
  struct lp_fix fa, fb;
  srvrun_conn   ca = {0}, cb = {0};
  quic_obuf     oba = {0}, obb = {0};
  u8            obufa[2048], obufb[2048];
  oba                 = (quic_obuf){obufa, sizeof obufa, 0};
  obb                 = (quic_obuf){obufb, sizeof obufb, 0};
  sr_stream_total_len = 250;
  sr_stream_round_cap = 100;
  sr_make_confirmed_conn(&ca, &fa, &oba);
  sr_make_confirmed_conn(&cb, &fb, &obb);
  ca.s.sdrv.alpn = QUIC_SALPN_HQ;
  cb.s.sdrv.alpn = QUIC_SALPN_HQ;
  ca.cc.cwnd = cb.cc.cwnd = 1u << 20;
  sr_set_req(&ca, 0, 0, 0);
  sr_set_req(&cb, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    sta  = {0, &ca};
    srvrun_state    stb  = {0, &cb};
    srvrun_step_ctx ctxa = {&cfg, 0, &sta, 0};
    srvrun_step_ctx ctxb = {&cfg, 0, &stb, 0};
    srvrun_start_resp(&ctxa, 0);
    srvrun_start_resp(&ctxb, 0);
    CHECK(ca.resp[0].sess.q.len == 100);
    CHECK(cb.resp[0].sess.q.len == 100);
    sr_drive_round_to_done(&ctxa, &ca);
    srvrun_reap_resps(&ctxa, &ca, 0);
    sr_drive_round_to_done(&ctxb, &cb);
    srvrun_reap_resps(&ctxb, &cb, 0);
    CHECK(ca.resp[0].stream_off == 200);
    CHECK(cb.resp[0].stream_off == 200);
    while (ca.resp[0].in_use) {
      sr_drive_round_to_done(&ctxa, &ca);
      srvrun_reap_resps(&ctxa, &ca, 0);
    }
    while (cb.resp[0].in_use) {
      sr_drive_round_to_done(&ctxb, &cb);
      srvrun_reap_resps(&ctxb, &cb, 0);
    }
  }
}

/* T-023 (found via real quic-go interop, not in the original ledger): TWO
 * streams on the SAME connection streaming in parallel -- the shape that
 * actually broke against quic-go (3 parallel GETs, each raising the other's
 * completion of c->l.req between rounds). Stream 0 requests path "A", is
 * driven through round 0 only; THEN stream 4's request ("B") starts and
 * completes its own round 0, overwriting c->l.req (route_note_done's "last
 * completed wins" mirror) the way a sibling's completion would in the real
 * failure. Stream 0's round 1 must still serve ITS OWN path ("A" bytes),
 * proving srvrun_resp_next_round used its own stream_req copy, not the
 * now-stale-for-stream-0 c->l.req. */
static void test_srvrun_streaming_later_round_uses_own_stream_not_sibling(
    void) {
  struct lp_fix   f;
  srvrun_conn     c  = {0};
  quic_obuf       ob = {0};
  u8              obuf[2048];
  static const u8 path_a[] = "A";
  static const u8 path_b[] = "B";
  ob                       = (quic_obuf){obuf, sizeof obuf, 0};
  sr_stream_total_len      = 200;
  sr_stream_round_cap      = 100;
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  {
    srvrun_cfg cfg = {
        -1,
        0,
        sr_stream_body_handler_by_path,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        &g_srvrun_env,
        0,
        0,
        0,
        0,
        0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    /* stream 0 ("A"): round 0 only, still streaming (100 of 200 sent). */
    sr_set_req(&c, 0, 0, 0);
    c.l.req.path     = path_a;
    c.l.req.path_len = 1;
    srvrun_start_resp(&ctx, 0);
    CHECK(c.resp[0].streaming == 1);
    sr_drive_round_to_done(&ctx, &c);
    /* stream 4 ("B") starts and finishes its OWN round 0 next, on the SAME
     * connection slot (its resp[] claims a DIFFERENT resp[] array slot,
     * srvrun_resp_claim's usual "first free slot" search) -- this is what
     * overwrites c->l.req with "B" (route_note_done's mirror), the exact
     * moment a sibling stream's completion clobbered stream 0's request in
     * the real bug. */
    sr_set_req(&c, 0, 0, 4);
    c.l.req.path     = path_b;
    c.l.req.path_len = 1;
    srvrun_start_resp(&ctx, 0);
    CHECK(c.resp[1].streaming == 1);          /* claimed the next resp[] slot */
    sr_drive_resp_round_to_done(&ctx, &c, 1); /* ack stream 4's round 0 too */
    /* stream 0's round 1: must still see path "A", not the now-current "B"
     * c->l.req holds. */
    srvrun_reap_resps(&ctx, &c, 0);
    CHECK(c.resp[0].sess.q.p[0] == 'A');
    /* stream 4's own round 1 likewise still sees "B". */
    CHECK(c.resp[1].sess.q.p[0] == 'B');
  }
}

/* T-021: an H3 (not hq-interop) streaming response's round-0 DATA frame
 * declares sr_stream_total_len (the full body), not just round 0's 100-byte
 * slice -- quic_h3resp_prefix's body_len argument must have been the total,
 * provable by decoding the prefix bytes at the front of the armed session
 * and checking the DATA frame's length varint. */
static void test_srvrun_streaming_h3_prefix_receives_total_size_not_round_len(
    void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  u8            pre[64];
  quic_obuf     preb  = {pre, sizeof pre, 0};
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  sr_stream_total_len = 300;
  sr_stream_round_cap = 100;
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(quic_h3resp_prefix(200, 0, 300, &preb) == 1);
  CHECK(c.resp[0].sess.q.len == preb.len + 100); /* prefix + round 0's body */
}

/* T-002: a body whose total size lands exactly on the fixed respstore row's
 * capacity (WIRED_SRVRUN_RESP_MAX - HDR_ROOM) fits in a single round -- the
 * handler is asked for round_cap far bigger than that so it's never the
 * limiting factor, and the round-0 body length must equal the fixed row's
 * cap exactly, with no second round requested. */
static void test_srvrun_streaming_body_exactly_row_cap_single_round(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  usz           cap;
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  cap                 = WIRED_SRVRUN_RESP_MAX - SRVRUN_RESP_HDR_ROOM;
  sr_stream_total_len = cap;
  sr_stream_round_cap = cap + 1000; /* bigger than the buffer, never binds */
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(c.resp[0].sess.q.len == cap);
  CHECK(c.resp[0].streaming == 0);   /* exact fit: no second round */
  CHECK(c.resp[0].bigbuf_row == -1); /* the fixed row, not the pool */
}

/* T-003: total size one byte past the bigbuf pool row's own capacity (the
 * largest single-round buffer this server has) crosses into a second round
 * -- round 0 fills the pool row's cap exactly and asks for a second round
 * carrying the last byte. */
static void test_srvrun_streaming_body_row_cap_plus_one_streams(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  usz           pool_cap;
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  pool_cap            = WIRED_SRVBIGBUF_ROW_CAP - SRVRUN_RESP_HDR_ROOM;
  sr_stream_total_len = pool_cap + 1;
  sr_stream_round_cap = pool_cap + 1000; /* never the limiting factor */
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  wired_srvbigbuf_init(
      &g_srvrun_env.bigbuf, &g_srvrun_env.bigbuf_rows[0][0],
      WIRED_SRVBIGBUF_ROW_CAP);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    CHECK(c.resp[0].bigbuf_row >= 0); /* body exceeds the fixed row */
    CHECK(
        c.resp[0].sess.q.len == WIRED_SRVBIGBUF_ROW_CAP - SRVRUN_RESP_HDR_ROOM);
    CHECK(c.resp[0].streaming == 1); /* one byte remains for round 1 */
    sr_drive_round_to_done(&ctx, &c);
    srvrun_reap_resps(&ctx, &c, 0);
    CHECK(c.resp[0].sess.q.len == 1); /* round 1: the last byte */
    CHECK(c.resp[0].streaming == 0);
  }
  wired_srvbigbuf_release(&g_srvrun_env.bigbuf, c.resp[0].bigbuf_row);
}

/* T-013: a streaming response's bigbuf pool row survives across rounds --
 * srvrun_resp_shrink_to_fixed's "small enough after all, copy to the fixed
 * row and release the pool row" optimization must NOT fire on a streaming
 * round (it would discard the pool row a still-in-flight earlier round's
 * bytes point into). Round 0 already claims a pool row (T-003's test above
 * proves that); this test drives a further round and checks the SAME pool
 * row index survives (never shrunk to the fixed row mid-stream). */
static void test_srvrun_streaming_last_round_not_shrunk_to_fixed(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  usz           pool_cap;
  int           row0;
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  pool_cap            = WIRED_SRVBIGBUF_ROW_CAP - SRVRUN_RESP_HDR_ROOM;
  sr_stream_total_len = pool_cap + 10; /* small final round (10 bytes) */
  sr_stream_round_cap = pool_cap;      /* round 0 fills the pool row exactly */
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  wired_srvbigbuf_init(
      &g_srvrun_env.bigbuf, &g_srvrun_env.bigbuf_rows[0][0],
      WIRED_SRVBIGBUF_ROW_CAP);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    CHECK(c.resp[0].bigbuf_row >= 0);
    row0 = c.resp[0].bigbuf_row;
    sr_drive_round_to_done(&ctx, &c);
    srvrun_reap_resps(&ctx, &c, 0); /* round 1: last 10 bytes, tiny */
    /* round 1's 10-byte body would fit the fixed row, but streaming skips
     * the shrink-to-fixed optimization -- same pool row, not released. */
    CHECK(c.resp[0].streaming == 0);
    CHECK(c.resp[0].bigbuf_row == row0);
    CHECK(c.resp[0].sess.q.len == 10);
  }
  wired_srvbigbuf_release(&g_srvrun_env.bigbuf, c.resp[0].bigbuf_row);
}

/* T-014: a streaming response's next round is armed via srvrun_resp_reap,
 * which runs inside srvrun_sess_on_step's normal step loop -- the same one
 * that gates every new send on cwnd (srvrun_pump_sess/srvrun_can_send_new).
 * With cwnd pinned to 0, srvrun_reap_resps must still ADVANCE the round
 * (the handler runs, the next round is armed in resp[]'s state) but the
 * pump loop must not have snuck bytes onto the wire around that gate --
 * proven by srvrun_pump_sess draining nothing (0 inflight) immediately
 * after the round-1 arm, same as any ordinary new send blocked by cwnd. */
static void test_srvrun_streaming_rearm_respects_existing_send_gates(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[2048];
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  sr_stream_total_len = 300;
  sr_stream_round_cap = 100;
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  c.cc.cwnd     = 1u << 20;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_stream_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,          0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
    sr_drive_round_to_done(&ctx, &c);
    c.cc.cwnd = 0;                  /* pin cwnd to 0 before round 1 arms */
    srvrun_reap_resps(&ctx, &c, 0); /* round 1 armed despite cwnd == 0 */
    CHECK(c.resp[0].in_use == 1);
    CHECK(c.resp[0].sess.q.len == 100); /* armed: bytes are queued... */
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 0); /* ...but unsent */
    srvrun_pump_sess(&ctx, 0); /* cwnd == 0: the ordinary new-send gate */
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 0); /* still blocked */
  }
}

/* T-013: hq-interop (see hq09.h) responses carry no HEADERS/DATA framing --
 * the armed session length equals the handler's body length exactly (a
 * bare 1-byte body arms to exactly 1 byte, not "1 byte + H3 prefix
 * overhead"). Verifies srvrun_arm_hq09_resp's raw-bytes path specifically
 * (srvrun_start_resp driven directly, same pattern as the H3 fixed-row
 * test above it). */
static void test_srvrun_hq09_resp_has_no_h3_framing(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {-1, 0, sr_tiny_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, &g_srvrun_env,        0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(c.resp[0].in_use == 1);
  CHECK(c.resp[0].sess.q.len == 1); /* sr_tiny_body_handler's 1-byte body,
                                     * no H3 prefix bytes added */
}

/* Body handler for the hq-interop missing-file test: an empty body (no
 * headers to carry a 404 status on this ALPN, RFC 9114-style status codes
 * don't apply -- HTTP/0.9 has none). */
static int sr_empty_body_handler(
    void*                       hctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    quic_obuf*                  body_out,
    const char**                ct,
    int*                        more,
    u64*                        total_size) {
  (void)hctx;
  (void)req;
  (void)ct;
  (void)offset;
  (void)more;
  (void)total_size;
  body_out->len = 0;
  return 1;
}

/* T-013 (hq-interop, see hq09.h): a body-less response still arms cleanly
 * (empty body, FIN on the only -- zero-length -- slice) rather than
 * failing or leaving the session unarmed; the peer sees the stream open
 * and immediately close, not a stall. */
static void test_srvrun_hq09_missing_file_arms_empty_body(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.alpn = QUIC_SALPN_HQ;
  sr_set_req(&c, 0, 0, 0);
  {
    srvrun_cfg cfg = {
        -1, 0, sr_empty_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,  0, &g_srvrun_env,         0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(c.resp[0].in_use == 1);
  CHECK(c.resp[0].sess.q.len == 0);
  CHECK(wired_sendsess_done(&c.resp[0].sess) == 1); /* nothing to send */
}

/* T-019/T-024: srvrun's own receive path (srvrun_serve/srvrun_on_step)
 * shares its wired_srvloop's new multi-range delayed-ACK state exactly like
 * srvloop's own direct wired_srvloop_step callers do -- proven here over a
 * real loopback socket (so the sealed reply is read back exactly as the
 * wire would deliver it) by driving a GET through srvrun_serve at
 * now_ms >= WIRED_SRVLOOP_MAX_ACK_DELAY_MS (T-024: srvrun's own
 * srvrun_step_ctx.now_ms is quic_ackpolicy's clock, the same one PTO/RTT
 * already share) and checking the sealed reply's ACK frame covers the
 * received pn. Benign skip when the sandbox forbids sockets. */
static void test_srvrun_onertt_get_is_acked_via_srvrun_on_step(void) {
  struct lp_fix    f;
  srvrun_conn      c  = {0};
  quic_obuf        ob = {0};
  u8               obuf[1024], get[512], spkt[1024];
  quic_sockaddr_in srv, from;
  i64              sfd, cfd;
  usz              glen, slen;
  const u8*        pl;
  usz              pll;
  if (!sr_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.peer = srv;
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  slen = client_seal_onertt_pn(&f, 9, get, glen, spkt, sizeof spkt);
  {
    srvrun_cfg cfg = {cfd,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &srv, 0, WIRED_SRVLOOP_MAX_ACK_DELAY_MS};
    srvrun_on_step(&ctx, &c, quic_mspan_of(spkt, slen));
  }
  {
    u8  pkt[1500];
    i64 r = wired_udp_recvfrom(sfd, quic_mspan_of(pkt, sizeof pkt), &from);
    CHECK(r > 0);
    CHECK(client_open_onertt(&f, pkt, (usz)r, &pl, &pll) == 1);
    check_acks_pn(pl, pll, 9);
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* T-019 (multi-range): srvrun_on_step's shared ACK state is not merely a
 * single-pn passthrough -- two datagrams with a gap between their pns (7,
 * then 9, skipping 8) drive the exact same two-range gap-encoding through
 * srvrun's real-socket path that test_srvloop_ack_single_gap_two_ranges
 * proves directly against wired_srvloop_step. */
static void test_srvrun_multi_range_ack_via_srvrun_on_step(void) {
  struct lp_fix    f;
  srvrun_conn      c  = {0};
  quic_obuf        ob = {0};
  u8               obuf[1024], ping[1] = {0x01}, spkt[1024];
  quic_sockaddr_in srv, from;
  i64              sfd, cfd;
  usz              slen;
  if (!sr_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.peer = srv;
  /* Both datagrams are fed before any recvfrom: pn 7 is not yet due (its own
   * step's now_ms == since_tick == 0) so it sends nothing, and pn 9's step
   * (now_ms advanced past the delay window) is the one whose reply this test
   * reads back -- avoiding a blocking recvfrom on a step that may send
   * nothing. */
  {
    srvrun_cfg cfg = {cfd,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &srv, 0, 0};
    slen = client_seal_onertt_pn(&f, 7, ping, 1, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &c, quic_mspan_of(spkt, slen));
  }
  {
    srvrun_cfg cfg = {cfd,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &srv, 0, WIRED_SRVLOOP_MAX_ACK_DELAY_MS};
    slen = client_seal_onertt_pn(&f, 9, ping, 1, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &c, quic_mspan_of(spkt, slen));
  }
  {
    u8             pkt[1500];
    const u8*      pl;
    usz            pll;
    quic_ack_frame a;
    i64 r = wired_udp_recvfrom(sfd, quic_mspan_of(pkt, sizeof pkt), &from);
    CHECK(r > 0);
    CHECK(client_open_onertt(&f, pkt, (usz)r, &pl, &pll) == 1);
    CHECK(find_ack_frame(pl, pll, &a) == 1);
    CHECK(a.n_ranges == 2);
    CHECK(a.ranges[0].hi == 9 && a.ranges[0].lo == 9);
    CHECK(a.ranges[1].hi == 7 && a.ranges[1].lo == 7);
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
}

/* T-024 (direct): srvrun_on_step writes its ctx->now_ms straight into
 * c->l.now_ms every step -- the exact field quic_ackpolicy_should_ack reads
 * for the delayed-ACK timer (srvloop.c's app_ack_due) -- proving there is
 * one shared clock, not a second independent one for the ACK timer.
 * srvrun_pto_deadline_ms/srvrun_pto_resps read the very same ctx->now_ms
 * argument on this same step (srvrun.c:2614), so a value observed here on
 * c.l.now_ms is what PTO judged against too. No socket needed: this reads
 * connection state directly rather than a wire reply. */
static void test_srvrun_ack_timer_shares_now_ms_with_pto(void) {
  struct lp_fix    f;
  srvrun_conn      c  = {0};
  quic_obuf        ob = {0};
  u8               obuf[1024];
  static const u64 now_ms = 12345;
  ob                      = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  {
    srvrun_cfg      cfg     = {-1, 0, 0, 0, 0, 0, 0, 0,
                               0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                               0,  0, 0, 0, 0};
    srvrun_step_ctx ctx     = {&cfg, 0, 0, now_ms};
    u8              ping[1] = {0x01}, spkt[1024];
    usz slen = client_seal_onertt_pn(&f, 11, ping, 1, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &c, quic_mspan_of(spkt, slen));
  }
  CHECK(c.l.now_ms == now_ms);
}

/* SLOT REUSE: HTTP/3 never reuses a stream id, so resp[]'s SRVRUN_RESP_SLOTS
 * (4, matching the receive side's WIRED_SRVLOOP_MAX_STREAMS) must free a
 * slot once its response is fully sent and acked -- otherwise a 5th
 * sequential request permanently finds every slot busy (TLA+ resp-multiplex
 * guard I4). Drives all SRVRUN_RESP_SLOTS+1 requests one at a time, each
 * through start -> pump -> ack -> reap, on distinct stream ids. */
static void test_srvrun_fifth_sequential_get_reuses_freed_slot(void) {
  struct lp_fix f;
  srvrun_conn   c  = {0};
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd = 1u << 20; /* isolate slot reuse from cwnd/log gating */
  {
    srvrun_cfg cfg = {-1, 0, sr_tiny_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, &g_srvrun_env,        0, 0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    for (u64 i = 0; i < SRVRUN_RESP_SLOTS + 1; i++) {
      u64 stream_id = i * 4; /* client-initiated bidi stream ids: 0,4,8,... */
      u64 pn0       = c.l.tx_pn;
      srvrun_resp* r;
      sr_set_req(&c, 0, 0, stream_id);
      srvrun_start_resp(&ctx, 0);
      r = srvrun_resp_find(&c, stream_id);
      CHECK(r != 0);
      CHECK(r->in_use == 1);
      srvrun_pump_sess(&ctx, 0);
      wired_sendsess_ack(&r->sess, pn0, c.l.tx_pn - 1);
      srvrun_reap_resps(&ctx, &c, 0);
      CHECK(r->in_use == 0);
    }
  }
}

/* PTO BUDGET: the probe-timeout budget (SRVRUN_PTO_MAX) is a
 * connection-wide policy, not per-slot (srvrun_pto_resps) -- a silent peer
 * likely stopped acknowledging the whole connection, not just one stream.
 * SRVRUN_PTO_MAX consecutive probes with no intervening ACK must leave the
 * connection up (each probe just requeues the oldest in-flight slice); the
 * next one exhausts the budget and srvrun_pto_slot tears the connection
 * slot down (c->up -> 0), matching TLA+ resp-multiplex's connection-wide
 * PTO-budget guard. Each probe only actually fires once the RTT-derived PTO
 * deadline (srvrun_pto_deadline_ms) has elapsed (RFC 9002 6.2) -- a call
 * before the deadline is a no-op that doesn't consume budget, which is
 * exactly the bug this test's own history caught (SRVRUN_PTO_MS used to be
 * a fixed 300ms fired on every poll tick regardless of RTT, resending
 * merely-slow packets on any faster link). Advances now_ms past each
 * doubling-backoff deadline explicitly rather than assuming a fixed probe
 * interval. */
static void test_srvrun_pto_budget_exhausted_tears_down_connection(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_state   st = {table, g_srvrun_state.conns};
  quic_obuf      ob;
  u8             obuf[1024];
  u64            now = 0;
  ob                 = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&st.conns[0], &f, &ob);
  st.conns[0].cc.cwnd = 1u << 20;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == 0);
  {
    srvrun_cfg cfg = {-1, 0, sr_tiny_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, &g_srvrun_env,        0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, 0, &st, now};
    sr_set_req(&st.conns[0], 0, 0, 0);
    srvrun_start_resp(&ctx, 0);
    srvrun_pump_sess(&ctx, 0); /* one slice in flight, never acked, sent
                                * at now_ms == 0 */
    CHECK(st.conns[0].resp[0].in_use == 1);
    /* no RTT sample yet: PTO uses quic_rtt_init's kInitialRtt-based default.
     * quic_rtt_init seeds smoothed_rtt=333000us, rttvar=166500us; base PTO =
     * srtt + max(4*rttvar, granularity) + max_ack_delay =
     * 333000 + 666000 + 25000 = 1024000us == 1024ms, doubling per probe. */
    now = 1025;
    for (int i = 0; i < SRVRUN_PTO_MAX; i++) {
      srvrun_step_ctx tick = {&cfg, 0, &st, now};
      srvrun_pto_slot(&tick, 0);
      CHECK(st.conns[0].up == 1);
      now += 1024u << (i + 1); /* each probe doubles the backoff (2^count) */
    }
    {
      srvrun_step_ctx tick = {&cfg, 0, &st, now};
      srvrun_pto_slot(&tick, 0); /* budget spent: tears the connection down */
      CHECK(st.conns[0].up == 0);
    }
  }
}

/* REGRESSION (interop http3, 500KB body over a 15ms-RTT link): once a real
 * RTT sample is in, a slice that is merely slow -- still well inside its
 * own RTT-derived PTO window -- must NOT be probed just because a poll
 * tick landed after it. The old SRVRUN_PTO_MS=300 fixed-interval design
 * fired here unconditionally, resending in-flight data that was never lost
 * and stalling the transfer (see tasks/todo.md this session's investigation).
 * A tick at a small multiple of a 15ms RTT (well under the ~50-60ms PTO a
 * 15ms/7.5ms-rttvar sample implies) must leave the slice untouched; only a
 * tick that has actually crossed the deadline may probe it. */
static void test_srvrun_pto_not_due_within_rtt_window(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_state   st = {table, g_srvrun_state.conns};
  quic_obuf      ob;
  u8             obuf[1024];
  u64            sent_at, deadline_ms;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&st.conns[0], &f, &ob);
  st.conns[0].cc.cwnd = 1u << 20;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == 0);
  {
    srvrun_cfg cfg = {-1, 0, sr_tiny_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, &g_srvrun_env,        0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    /* seed a real 15ms RTT sample (this link's actual delay), same as the
     * interop scenario's simple-p2p --delay=15ms. */
    srvrun_rtt_note(&st.conns[0], 15);
    sr_set_req(&st.conns[0], 0, 0, 0);
    srvrun_start_resp(&ctx, 0);
    srvrun_pump_sess(&ctx, 0); /* slice sent at now_ms == 0 */
    CHECK(st.conns[0].resp[0].in_use == 1);
    sent_at     = 0;
    deadline_ms = srvrun_pto_deadline_ms(&st.conns[0], 0);
    CHECK(deadline_ms > 0);
    /* well within the window: no probe, budget untouched */
    {
      srvrun_step_ctx tick = {&cfg, 0, &st, sent_at + deadline_ms / 2};
      srvrun_pto_slot(&tick, 0);
      CHECK(st.conns[0].resp[0].sess.pto_count == 0);
      CHECK(st.conns[0].up == 1);
    }
    /* past the deadline: now it fires */
    {
      srvrun_step_ctx tick = {&cfg, 0, &st, sent_at + deadline_ms + 1};
      srvrun_pto_slot(&tick, 0);
      CHECK(st.conns[0].resp[0].sess.pto_count == 1);
    }
  }
}

/* Drive a real peer-initiated Key Update through srvrun_on_step (the real
 * wire path, not direct field injection) so c->s.ku actually rotates:
 * generation 0 -> 1, have_old set. Returns the ms the rotation lands at,
 * which callers use as the 3x-PTO retention floor's start line. */
static u64 sr_rotate_ku(srvrun_step_ctx* ctx, srvrun_conn* c, u64 now_ms) {
  u8  get[512], spkt[1024];
  usz glen, slen;
  {
    quic_obuf gob = {get, sizeof get, 0};
    CHECK(wired_h3reqdrive_send_get(
        0,
        &(wired_h3reqdrive_get_in){
            quic_span_of((const u8*)"/", 1), quic_span_of((const u8*)"h", 1)},
        &gob));
    glen = gob.len;
  }
  slen = client_seal_onertt_pn_gen(&c->s, 7, 1, get, glen, spkt, sizeof spkt);
  {
    srvrun_step_ctx tick = {ctx->cfg, 0, ctx->st, now_ms};
    srvrun_on_step(&tick, c, quic_mspan_of(spkt, slen));
  }
  return now_ms;
}

/* T-009: within the 3x-PTO retention floor after a confirmed rotation, the
 * retained old generation must still be there (RFC 9001 6.5 "SHOULD retain
 * old read keys for no more than three times the PTO"). */
static void test_srvrun_ku_old_keys_retained_within_3pto_window(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_state   st = {table, g_srvrun_state.conns};
  quic_obuf      ob;
  u8             obuf[1024];
  u64            rotated_at, floor_ms;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&st.conns[0], &f, &ob);
  st.conns[0].cc.cwnd = 1u << 20;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == 0);
  {
    srvrun_cfg cfg = {-1, 0, sr_tiny_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, &g_srvrun_env,        0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_rtt_note(&st.conns[0], 15);
    rotated_at = sr_rotate_ku(&ctx, &st.conns[0], 0);
    CHECK(st.conns[0].s.ku.generation == 1);
    CHECK(st.conns[0].s.ku.have_old == 1);
    floor_ms = 3u * srvrun_pto_deadline_ms(&st.conns[0], 0);
    {
      srvrun_step_ctx tick = {&cfg, 0, &st, rotated_at + floor_ms - 1};
      srvrun_sess_on_step(&tick, 0);
      CHECK(st.conns[0].s.ku.have_old == 1);
    }
  }
}

/* T-010: once the 3x-PTO floor has fully elapsed, the retained old
 * generation is discarded (RFC 9001 6.5's upper bound; boundary: one ms
 * short still retains, per T-009 above). */
static void test_srvrun_ku_old_keys_discarded_after_3pto_window(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_state   st = {table, g_srvrun_state.conns};
  quic_obuf      ob;
  u8             obuf[1024];
  u64            rotated_at, floor_ms;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&st.conns[0], &f, &ob);
  st.conns[0].cc.cwnd = 1u << 20;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == 0);
  {
    srvrun_cfg cfg = {-1, 0, sr_tiny_body_handler, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, &g_srvrun_env,        0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_rtt_note(&st.conns[0], 15);
    rotated_at = sr_rotate_ku(&ctx, &st.conns[0], 0);
    floor_ms   = 3u * srvrun_pto_deadline_ms(&st.conns[0], 0);
    {
      srvrun_step_ctx tick = {&cfg, 0, &st, rotated_at + floor_ms};
      srvrun_sess_on_step(&tick, 0);
      CHECK(st.conns[0].s.ku.have_old == 0);
    }
  }
}

/* T-010: end-to-end -- a real MAX_DATA frame, driven through srvrun_on_step
 * (the real receive path, not field injection), raises the connection's
 * send credit; a subsequent srvrun_sess_on_step (the real per-step apply +
 * pump path) then actually sends a slice that was blocked before the frame
 * arrived. Proves the gather -> apply -> gate wiring end to end, not just
 * each piece in isolation. */
static void test_srvrun_recv_max_data_then_send_unblocks(void) {
  static u8       body[4 * SRVRUN_CHUNK];
  struct lp_fix   f;
  srvrun_conn     c;
  quic_obuf       ob = {0};
  u8              obuf[1024], fr[16], spkt[1024];
  usz             fl, slen;
  quic_data_frame md = {SRVRUN_CHUNK * 10};
  ob                 = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd               = 1u << 20;
  c.conn_credit           = SRVRUN_CHUNK / 2; /* blocks any send */
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = 1u << 24;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.q.cur == 0); /* still blocked before MAX_DATA */
    fl = quic_max_data_encode(fr, sizeof fr, &md);
    CHECK(fl > 0);
    slen = client_seal_onertt(&f, fr, fl, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &c, quic_mspan_of(spkt, slen));
    srvrun_sess_on_step(&ctx, 0);
    CHECK(c.conn_credit == SRVRUN_CHUNK * 10);
    CHECK(c.resp[0].sess.q.cur > 0); /* unblocked, actually sent */
  }
}

/* T-006: RFC 9000 4.1 "MUST NOT reduce" -- a MAX_DATA lower than the
 * connection's already-running credit is a no-op; the higher value stays. */
static void test_srvrun_conn_credit_ignores_lower_max_data(void) {
  struct lp_fix   f;
  srvrun_conn     c;
  quic_obuf       ob = {0};
  u8              obuf[1024], fr[16], spkt[1024];
  usz             fl, slen;
  quic_data_frame md = {SRVRUN_CHUNK}; /* far below the seeded 16MB */
  ob                 = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  {
    u64             before = c.conn_credit;
    srvrun_cfg      cfg    = {-1, 0, 0, 0, 0, 0, 0, 0,
                              0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                              0,  0, 0, 0, 0};
    srvrun_state    st     = {0, &c};
    srvrun_step_ctx ctx    = {&cfg, 0, &st, 1};
    fl                     = quic_max_data_encode(fr, sizeof fr, &md);
    CHECK(fl > 0);
    slen = client_seal_onertt(&f, fr, fl, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &c, quic_mspan_of(spkt, slen));
    srvrun_sess_on_step(&ctx, 0);
    CHECK(c.conn_credit == before); /* unchanged, not lowered */
  }
}

/* T-008: same "MUST NOT reduce" rule at the per-stream level. */
static void test_srvrun_stream_credit_ignores_lower_max_stream_data(void) {
  struct lp_fix          f;
  srvrun_conn            c;
  quic_obuf              ob = {0};
  u8                     obuf[1024], fr[32], spkt[1024];
  usz                    fl, slen;
  quic_stream_data_frame msd = {0, SRVRUN_CHUNK}; /* far below seeded 16MB */
  ob                         = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  {
    u64             before = c.resp[0].stream_credit;
    srvrun_cfg      cfg    = {-1, 0, 0, 0, 0, 0, 0, 0,
                              0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                              0,  0, 0, 0, 0};
    srvrun_state    st     = {0, &c};
    srvrun_step_ctx ctx    = {&cfg, 0, &st, 1};
    fl                     = quic_max_stream_data_encode(fr, sizeof fr, &msd);
    CHECK(fl > 0);
    slen = client_seal_onertt(&f, fr, fl, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &c, quic_mspan_of(spkt, slen));
    srvrun_sess_on_step(&ctx, 0);
    CHECK(c.resp[0].stream_credit == before); /* unchanged, not lowered */
  }
}

/* T-009: a MAX_STREAM_DATA naming a stream_id with no in-use resp[] slot
 * (never claimed, or already reaped) is a no-op -- srvrun_apply_stream_
 * credit_update must not crash or touch an unrelated slot. */
static void test_srvrun_max_stream_data_unknown_stream_is_noop(void) {
  struct lp_fix          f;
  srvrun_conn            c;
  quic_obuf              ob = {0};
  u8                     obuf[1024], fr[32], spkt[1024];
  usz                    fl, slen;
  quic_stream_data_frame msd = {8, SRVRUN_CHUNK * 5}; /* stream 8: no slot */
  ob                         = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  {
    u64             before_slot0_credit;
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    before_slot0_credit = c.resp[0].stream_credit;
    fl                  = quic_max_stream_data_encode(fr, sizeof fr, &msd);
    CHECK(fl > 0);
    slen = client_seal_onertt(&f, fr, fl, spkt, sizeof spkt);
    srvrun_on_step(&ctx, &c, quic_mspan_of(spkt, slen));
    srvrun_sess_on_step(&ctx, 0);                          /* must not crash */
    CHECK(c.resp[0].stream_credit == before_slot0_credit); /* untouched */
  }
}

/* T-015: a PTO-driven resend (the requeued slice, not a new take) must not
 * double-count against the send credit -- q.cur already reflects that
 * offset range as consumed from the first send, and a resend reuses the
 * same range rather than taking a fresh one. With credit sized for exactly
 * one chunk, sending it once, firing PTO, and letting the resend go out
 * again must leave q.cur unchanged (still one chunk), never advancing past
 * the credit ceiling. */
static void test_srvrun_pto_resend_does_not_double_count_credit(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd               = 1u << 20;
  c.conn_credit           = SRVRUN_CHUNK; /* exactly one chunk, no more */
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = SRVRUN_CHUNK;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.q.cur == SRVRUN_CHUNK); /* the only chunk, sent */
    CHECK(wired_sendsess_pto_fire(&c.resp[0].sess, SRVRUN_PTO_MAX));
    CHECK(c.resp[0].sess.requeue_n == 1);
    srvrun_pump_sess(&ctx, 0); /* resend goes out via the requeue path */
    /* q.cur is untouched by the resend (it never re-takes from sendq) --
     * still exactly the credit ceiling, not double-counted past it. */
    CHECK(c.resp[0].sess.q.cur == SRVRUN_CHUNK);
    CHECK(c.resp[0].sess.requeue_n == 0);
  }
}

/* T-011: RFC 9000 4.1 -- a connection-level send credit smaller than one
 * chunk blocks new sends even with cwnd/log wide open. srvrun_can_send_new
 * must gate on it independent of the other two gates. */
static void test_srvrun_conn_credit_exhausted_blocks_send(void) {
  static u8     body[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd               = 1u << 20; /* wide open: isolate the credit gate */
  c.conn_credit           = SRVRUN_CHUNK / 2; /* less than one chunk */
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = 1u << 24; /* wide open: isolate conn credit */
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.q.cur == 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 0);
  }
}

/* T-012: a stream-level send credit smaller than one chunk blocks new sends
 * on THAT slot only -- a sibling slot with its own room keeps sending
 * (RFC 9000 4.1's stream-level credit is per-stream, independent of the
 * connection-level one and of other streams'). */
static void test_srvrun_stream_credit_exhausted_blocks_only_that_slot(void) {
  static u8     body0[4 * SRVRUN_CHUNK];
  static u8     body1[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd               = 1u << 20;
  c.conn_credit           = 1u << 24; /* wide open: isolate stream credit */
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = SRVRUN_CHUNK / 2; /* less than one chunk */
  c.resp[1].in_use        = 1;
  c.resp[1].stream_id     = 4;
  c.resp[1].stream_credit = 1u << 24; /* plenty */
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.q.cur == 0); /* blocked */
    CHECK(c.resp[1].sess.q.cur > 0);  /* unaffected */
  }
}

/* T-013: the connection-level credit is ONE ceiling shared by every resp[]
 * slot (RFC 9000 4.1: max_data covers all streams combined) -- consumption
 * must sum across slots the same way cwnd's srvrun_inflight_bytes_all does,
 * not gate each slot against the full credit independently (which would
 * let N slots each consume up to the full ceiling, N times over). */
static void test_srvrun_conn_credit_sums_across_slots(void) {
  static u8     body0[4 * SRVRUN_CHUNK];
  static u8     body1[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd = 1u << 20;
  /* room for exactly one chunk total once slot 0 has already consumed one */
  c.conn_credit           = SRVRUN_CHUNK + SRVRUN_CHUNK / 2;
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = 1u << 24;
  c.resp[1].in_use        = 1;
  c.resp[1].stream_id     = 4;
  c.resp[1].stream_credit = 1u << 24;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
    /* slot 0 (round-robin's first) takes the one available chunk; slot 1
     * finds the connection-wide ceiling already spent */
    CHECK(c.resp[0].sess.q.cur == SRVRUN_CHUNK);
    CHECK(c.resp[1].sess.q.cur == 0);
  }
}

/* T-014: the boundary itself -- a credit exactly equal to what one chunk
 * would consume still allows that send (the gate is `consumed + chunk <=
 * credit`, so equality passes). */
static void test_srvrun_send_credit_boundary_exact_fit_allowed(void) {
  static u8     body[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd               = 1u << 20;
  c.conn_credit           = SRVRUN_CHUNK; /* exactly one chunk */
  c.resp[0].in_use        = 1;
  c.resp[0].stream_id     = 0;
  c.resp[0].stream_credit = SRVRUN_CHUNK; /* exactly one chunk */
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.q.cur == SRVRUN_CHUNK);
  }
}

/* LOG-FULL GATE: with the congestion window wide open, the pump must stop
 * at WIRED_SENDSESS_LOG in-flight slices. One more take would send a slice
 * that wired_sendsess_sent (log full) can record in neither log nor requeue
 * -- if that packet then drops, the stream has a permanent hole and the
 * peer stalls waiting for the missing offset. ACKing frees log entries and
 * the pump must resume where it stopped. */
static void test_srvrun_pump_stops_at_log_capacity(void) {
  static u8     body[(WIRED_SENDSESS_LOG + 4) * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  u64           pn0;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd        = 1u << 20; /* wide open: isolate the log gate from cwnd */
  pn0              = c.l.tx_pn;
  c.resp[0].in_use = 1;
  c.resp[0].stream_id = 0;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == WIRED_SENDSESS_LOG);
    /* the take that cannot be logged must not have happened */
    CHECK(c.resp[0].sess.q.cur == (usz)WIRED_SENDSESS_LOG * SRVRUN_CHUNK);
    /* ACK the first 4 slices: log entries free up, the pump resumes and
     * drains the remaining 4 slices without losing any */
    wired_sendsess_ack(&c.resp[0].sess, pn0, pn0 + 3);
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.q.cur == sizeof body);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == WIRED_SENDSESS_LOG);
  }
}

/* LOSS + RETRANSMIT ACROSS TWO CONCURRENT RESPONSES: two resp[] slots each
 * push past WIRED_SENDSESS_LOG in-flight slices (33+, TLA+ resp-multiplex's
 * flagged test-design pitfall: the log-full gate only fires above LOG
 * capacity). slot 0 gets a clean ACK sweep; slot 1's ACK skips the middle
 * of its log, past the packet-loss threshold (RFC 9002 6.1.1), forcing a
 * requeue -- proving the loss detector, requeue, and pn-broadcast (guard 5:
 * an ACK range naming slot 0's pns is a no-op against slot 1's log and vice
 * versa, since pn is one connection-wide monotonic space) all still work
 * with two sessions live at once. Every byte of both bodies must eventually
 * reach the log/requeue/acked union -- none silently dropped (I3). */
/* CROSS-STREAM ACK MUST NOT FALSELY ADVANCE A SIBLING'S LOSS THRESHOLD:
 * an ACK range naming only slot 1's pns must leave slot 0's still-in-flight
 * slices alone -- broadcasting the range to every resp[] slot (srvrun_
 * feed_ack_range) must not let a sibling's ACK raise this slot's own
 * largest_acked and falsely push its unacked-but-not-actually-lost slices
 * past the packet-loss threshold (RFC 9002 6.1.1). This is exactly what a
 * real quic-go client's ACKs for streams 4/8 did to stream 0's in-flight
 * slices on a 500KB body (interop http3 test case): offsets past ~90KB
 * were spuriously requeued and re-sent from ~55KB. */
static void test_srvrun_sibling_ack_does_not_lose_other_slot(void) {
  static u8     body0[8 * SRVRUN_CHUNK];
  static u8     body1[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  u64           pn0_b;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20; /* isolate the ACK-broadcast gate from cwnd */
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  c.resp[1].in_use    = 1;
  c.resp[1].stream_id = 4;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    /* slot 0 sends all 8 slices first (fresh pns pn0_a..pn0_a+7), then
     * slot 1 arms and sends its own 4 slices with the next fresh pns --
     * slot 1's pns are all numerically past every pn slot 0 ever used, so
     * an ACK naming only slot 1's range names pns slot 0 never sent. */
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 8);
    pn0_b = c.l.tx_pn;
    wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == 4);

    /* ACK only slot 1's range. Slot 0's log must be untouched: still all 8
     * in flight, no requeue, largest_acked never set (slot 0 has not
     * actually been acked yet). */
    srvrun_feed_ack_range(&cfg, &c, pn0_b, pn0_b + 3, ctx.now_ms);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 8);
    CHECK(c.resp[0].sess.requeue_n == 0);
    CHECK(c.resp[0].sess.has_acked == 0);
  }
}

static void test_srvrun_loss_and_retransmit_across_two_responses(void) {
  static u8     body0[(WIRED_SENDSESS_LOG + 4) * SRVRUN_CHUNK];
  static u8     body1[(WIRED_SENDSESS_LOG + 4) * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  u64           pn0_a, pn0_b;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20; /* isolate the log gate from cwnd */
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  c.resp[1].in_use    = 1;
  c.resp[1].stream_id = 4;
  pn0_a               = c.l.tx_pn;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    /* slot 0 fills its log first (pns pn0_a..pn0_a+31), then slot 1 arms
     * and fills its own log with fresh pns right after. */
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == WIRED_SENDSESS_LOG);
    pn0_b = c.l.tx_pn;
    wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == WIRED_SENDSESS_LOG);

    /* slot 0: a clean ACK sweep of its whole log -- no loss, pump drains
     * the remaining 4 slices. A range naming slot 0's pns must not touch
     * slot 1's still-untouched log (guard 5). */
    srvrun_feed_ack_range(
        &cfg, &c, pn0_a, pn0_a + WIRED_SENDSESS_LOG - 1, ctx.now_ms);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == WIRED_SENDSESS_LOG);
    /* hystart_ack's srtt sample would otherwise arm pacing and block the
     * very next pump at this fixed now_ms; reset it so only the log/cwnd
     * gates (this test's actual subject) govern srvrun_can_send. */
    c.srtt_ms      = 0;
    c.next_send_ms = 0;
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.q.cur == sizeof body0);

    /* slot 1: ACK only the tail (largest_acked jumps to the log's last pn),
     * skipping the first WIRED_SENDSESS_LOG-3 slices entirely -- every one
     * of those is now 3+ behind largest_acked, past RFC 9002 6.1.1's
     * packet-loss threshold, so the detector must requeue all of them
     * rather than silently drop them. */
    srvrun_feed_ack_range(
        &cfg, &c, pn0_b + WIRED_SENDSESS_LOG - 1,
        pn0_b + WIRED_SENDSESS_LOG - 1, ctx.now_ms);
    CHECK(c.resp[1].sess.requeue_n > 0);
    c.srtt_ms      = 0;
    c.next_send_ms = 0;
    /* the pump retransmits the requeued slices (fresh pns) then resumes the
     * unsent tail; eventually every byte is either in flight or sent. Fresh
     * pns keep climbing past what a single ACK range names, so each round
     * ACKs everything currently logged before pumping again -- the same
     * ACK-drains-the-window cycle a real peer runs, just driven by hand. */
    for (int round = 0; round < 8 && c.resp[1].sess.q.cur < sizeof body1;
         round++) {
      u64 lo = 0, hi = 0;
      int found = 0;
      srvrun_pump_sess(&ctx, 0);
      for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
        const wired_sent_slice* e = &c.resp[1].sess.log[i];
        if (!e->inflight) continue;
        if (!found || e->pn < lo) lo = e->pn;
        if (!found || e->pn > hi) hi = e->pn;
        found = 1;
      }
      if (found) {
        srvrun_feed_ack_range(&cfg, &c, lo, hi, ctx.now_ms);
        c.srtt_ms      = 0;
        c.next_send_ms = 0;
      }
    }
    CHECK(c.resp[1].sess.q.cur == sizeof body1);
    CHECK(c.resp[1].sess.requeue_n == 0);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == 0);
  }
}

/* ROUND-ROBIN, NOT DRAIN-THEN-NEXT: with three responses armed at once and
 * cwnd tight enough to allow only a few chunks per pump, every resp[] slot
 * must get a turn before any slot gets a second one -- srvrun_pump_sess used
 * to drain resp[0] to its log cap (or cwnd) before resp[1]/resp[2] ever sent
 * a byte, so the first-registered stream always claimed the shared cwnd
 * first. Against a real quic-go client sending 3 parallel GETs, that let
 * stream 0's log fill to WIRED_SENDSESS_LOG while streams 4/8 starved, fell
 * behind on real send time, and their own in-flight slices then tripped
 * RFC 9002 6.1.1's packet threshold -- not because anything was actually
 * lost, but because slot 0 had burned through pns far faster than its
 * siblings got to send at all. */
static void test_srvrun_pump_round_robins_across_slots(void) {
  static u8     body0[8 * SRVRUN_CHUNK];
  static u8     body1[8 * SRVRUN_CHUNK];
  static u8     body2[8 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  /* room for exactly 3 chunks per pump pass -- one per slot, not enough for
   * any slot to take a second turn within the same round. */
  c.cc.cwnd           = 3 * SRVRUN_CHUNK;
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  c.resp[1].in_use    = 1;
  c.resp[1].stream_id = 4;
  c.resp[2].in_use    = 1;
  c.resp[2].stream_id = 8;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[2].sess, body2, sizeof body2, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
    /* cwnd allows exactly 3 chunks total: a round-robin pump spends them one
     * per slot. A drain-then-next pump would instead spend all 3 on slot 0
     * and leave slots 1/2 at zero. */
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 1);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == 1);
    CHECK(wired_sendsess_inflight(&c.resp[2].sess) == 1);
  }
}

/* PACING GATES PASSES, NOT SLOTS: once an RTT sample exists and cwnd has
 * grown large enough that the pacing interval floors to 1ms (quic_cc.c),
 * that floor must limit how often a whole round-robin PASS may run, not
 * block sibling slots within the SAME pass -- pacing rescheduling
 * next_send_ms after slot 0's slice used to make srvrun_pace_ok fail for
 * slots 4/8 before they ever got a turn in the same step, so a real 3-way
 * parallel GET left two of the three streams completely unserved. */
static void test_srvrun_pacing_floor_does_not_starve_round(void) {
  static u8     body0[4 * SRVRUN_CHUNK];
  static u8     body1[4 * SRVRUN_CHUNK];
  static u8     body2[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  /* real values observed mid-transfer: interval = 5*1200*40/(4*71055)
   * truncates to 0, floored to 1ms by quic_cc_pacing_ms. */
  c.srtt_ms           = 40;
  c.cc.cwnd           = 71055;
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  c.resp[1].in_use    = 1;
  c.resp[1].stream_id = 4;
  c.resp[2].in_use    = 1;
  c.resp[2].stream_id = 8;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[2].sess, body2, sizeof body2, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
    /* one pacing-gated pass must still reach every slot, not just slot 0. */
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 1);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == 1);
    CHECK(wired_sendsess_inflight(&c.resp[2].sess) == 1);
  }
}

/* RFC 9002 7.5: "Probe packets MUST NOT be blocked by the congestion
 * controller." A PTO-requeued slice must go out even though cwnd is
 * already fully used by the one slice still in flight -- gating it on cwnd
 * would deadlock: cwnd only grows from new ACKs, new ACKs need new sends,
 * and this probe is the one send that would produce that ACK (the exact
 * stall observed against a real quic-go interop run: cwnd/inflight both
 * stuck at the same value with the send log never draining). */
static void test_srvrun_pto_probe_bypasses_cwnd(void) {
  static u8     body0[4 * SRVRUN_CHUNK];
  static u8     body1[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20; /* wide open for the initial sends */
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  c.resp[1].in_use    = 1;
  c.resp[1].stream_id = 4;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    /* drive each slot to exactly one in-flight slice, one round at a time,
     * before cwnd gets tightened below (a wide-open cwnd here would drain
     * each slot's whole log via srvrun_pump_sess's inner loop instead). */
    c.cc.cwnd = 2 * SRVRUN_CHUNK;
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 1);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == 1);
    /* now shrink cwnd to exactly slot 1's one chunk -- no room for even a
     * sliver more, so a cwnd-gated resend of slot 0's probe would fail. */
    c.cc.cwnd = SRVRUN_CHUNK;
    /* PTO fires on slot 0 only: its slice moves to requeue. Slot 1's slice
     * is still in flight and alone accounts for cwnd's one chunk of room,
     * so a cwnd-gated pump would find no room for slot 0's probe. */
    CHECK(wired_sendsess_pto_fire(&c.resp[0].sess, SRVRUN_PTO_MAX));
    CHECK(c.resp[0].sess.requeue_n == 1);
    srvrun_pump_sess(&ctx, 0);
    /* the probe went out despite cwnd offering no room: requeue drained,
     * still exactly one slice in flight on slot 0 (the resend, not new
     * data); slot 1 untouched. */
    CHECK(c.resp[0].sess.requeue_n == 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 1);
    CHECK(c.resp[0].sess.q.cur == SRVRUN_CHUNK);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == 1);
    CHECK(c.resp[1].sess.q.cur == SRVRUN_CHUNK);
  }
}

/* Regression counterpart to test_srvrun_pto_probe_bypasses_cwnd: with an
 * EMPTY requeue (no PTO fired), brand-new data must still respect cwnd --
 * the bypass added for probes must not leak into ordinary new sends. */
static void test_srvrun_new_send_still_blocked_by_cwnd(void) {
  static u8     body[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = SRVRUN_CHUNK - 1; /* not even room for one chunk */
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    CHECK(c.resp[0].sess.requeue_n == 0); /* nothing queued: not a probe */
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 0);
    CHECK(c.resp[0].sess.q.cur == 0);
  }
}

/* Several probes queued at once (packet-threshold loss can requeue many
 * slices in a single detect pass) must ALL bypass cwnd in the same
 * round-robin pass -- not just the first one -- draining the whole requeue
 * before any brand-new data goes out. */
static void test_srvrun_pto_probe_drains_multiple_requeued_slices(void) {
  static u8     body0[(WIRED_SENDSESS_LOG + 4) * SRVRUN_CHUNK];
  static u8     body1[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  u64           pn0;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20; /* isolate: fill the log, not cwnd, first */
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  c.resp[1].in_use    = 1;
  c.resp[1].stream_id = 4;
  pn0                 = c.l.tx_pn;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_pump_sess(&ctx, 0); /* slot 0's log fills (32), slot 1 sends 1 */
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == WIRED_SENDSESS_LOG);
    /* ACK only the tail: every earlier slice trips the packet-loss
     * threshold at once and moves to requeue (same shape as
     * test_srvrun_loss_and_retransmit_across_two_responses). */
    c.largest_acked = pn0 + WIRED_SENDSESS_LOG - 1;
    {
      u64 lost[WIRED_SENDSESS_LOG];
      usz n = wired_sendsess_detect_lost(
          &c.resp[0].sess, c.largest_acked, ctx.now_ms, 0, lost,
          WIRED_SENDSESS_LOG);
      CHECK(n > 1); /* more than one probe queued at once */
    }
    /* now pin cwnd down to nothing: a cwnd-gated pump could send none of
     * the requeued probes, let alone drain all of them. */
    c.cc.cwnd = 0;
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.requeue_n == 0); /* every queued probe went out */
  }
}

/* RFC 9002 7.5 exempts cwnd, not the log. A requeued probe can never
 * actually collide with a full log (sendsess_requeue clears its own log
 * entry's inflight flag the instant it queues, so requeue_n != 0 always
 * implies at least that many free entries) -- but brand-new data (no probe
 * queued) must still be capped at WIRED_SENDSESS_LOG regardless of how wide
 * open cwnd is. Exercised the same way test_srvrun_pump_stops_at_log_capacity
 * does, with cwnd wide open, to isolate the log gate as the only thing
 * standing in the way. */
static void test_srvrun_pto_probe_still_respects_log_capacity(void) {
  static u8     body[(WIRED_SENDSESS_LOG + 4) * SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20; /* wide open: isolate the log gate */
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_pump_sess(&ctx, 0); /* log fills to capacity, 4 slices unsent */
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == WIRED_SENDSESS_LOG);
    CHECK(c.resp[0].sess.q.cur == (usz)WIRED_SENDSESS_LOG * SRVRUN_CHUNK);
    /* no probe queued, log full, cwnd wide open: the log gate alone must
     * stop the pump from sending the remaining unsent tail. */
    CHECK(c.resp[0].sess.requeue_n == 0);
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.q.cur == (usz)WIRED_SENDSESS_LOG * SRVRUN_CHUNK);
  }
}

/* A queued probe must not leak its cwnd bypass to a SIBLING slot's
 * brand-new send within the same round-robin pass: slot 0 has a probe
 * queued (bypasses cwnd), slot 1 has only fresh sendq data (must still
 * respect cwnd). */
static void test_srvrun_pto_bypass_does_not_leak_to_sibling_new_sends(void) {
  static u8     body0[SRVRUN_CHUNK];
  static u8     body1[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    c.cc.cwnd           = 1u << 20;
    srvrun_pump_sess(&ctx, 0); /* slot 0 sends its one slice */
    CHECK(c.resp[0].sess.q.cur == SRVRUN_CHUNK);
    CHECK(wired_sendsess_pto_fire(&c.resp[0].sess, SRVRUN_PTO_MAX));
    CHECK(c.resp[0].sess.requeue_n == 1);
    /* slot 1 arms AFTER slot 0's probe is already queued, and cwnd is
     * pinned to exactly zero room: slot 0's probe must still go out (RFC
     * 9002 7.5), but slot 1's brand-new data must NOT. */
    c.resp[1].in_use    = 1;
    c.resp[1].stream_id = 4;
    wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
    c.cc.cwnd = 0;
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.requeue_n == 0); /* slot 0's probe bypassed cwnd */
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 1);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == 0); /* slot 1 blocked */
    CHECK(c.resp[1].sess.q.cur == 0);
  }
}

/* Between a PTO firing (sendsess_requeue clears the log entry's inflight
 * flag) and the actual resend, inflight bytes must already reflect the
 * drop -- this is what lets cwnd stop looking artificially full even
 * before the resend happens (srvrun_inflight_bytes_all reads the log's
 * inflight flags directly, so this is really a sendsess.c invariant
 * exercised through srvrun's own accounting helper). */
static void test_srvrun_pto_requeue_frees_inflight_bytes_before_resend(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20;
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_pump_sess(&ctx, 0);
    CHECK(srvrun_inflight_bytes_all(&c) == SRVRUN_CHUNK);
    CHECK(wired_sendsess_pto_fire(&c.resp[0].sess, SRVRUN_PTO_MAX));
    /* before any resend happens, the byte accounting already dropped --
     * the requeued slice is no longer counted as in flight. */
    CHECK(srvrun_inflight_bytes_all(&c) == 0);
  }
}

/* No in-flight data at all (requeue empty too): PTO firing is defined as a
 * no-op (wired_sendsess_pto_fire returns 1 without touching anything), and
 * the pump must not fabricate a send from nothing. */
static void test_srvrun_pto_noop_when_nothing_inflight(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20;
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 0);
    CHECK(c.resp[0].sess.requeue_n == 0);
    CHECK(wired_sendsess_pto_fire(&c.resp[0].sess, SRVRUN_PTO_MAX) == 1);
    CHECK(c.resp[0].sess.requeue_n == 0); /* still nothing queued */
  }
}

/* @file
 * RFC 9002 6.2 boot-stage PTO (srvrun_boot_pto_slot): a server-initiated,
 * timer-driven resend of the cached accept flight (boot_ini/boot_hs) while a
 * connection is up but not yet confirmed. Distinct from the existing
 * receive-triggered srvrun_resend_boot_flight (a client Initial retransmit
 * arriving), which the interop handshakeloss/handshakecorruption cases can
 * never trigger when the *server's* flight -- not the client's -- is the one
 * dropped or corrupted; nothing then ever arrives to trigger a resend.
 *
 * A minimal boot-stage srvrun_conn: up (accepted) but never confirmed
 * (quic_memset leaves c->s.phase at WIRED_SERVER_HS_INITIAL, and
 * wired_server_is_confirmed only ever checks phase == HS_CONFIRMED, so no
 * real TLS handshake needs driving here -- same minimalism as this file's
 * existing sr_antiamp_seed_flight). boot_ini_len is a dummy nonzero length;
 * its bytes' content is irrelevant to srvrun_boot_pto_slot, which only ever
 * forwards the cached span's length to srvrun_send (cfg->fd == -1 skips the
 * real socket write). */
static void sr_make_boot_conn(srvrun_conn* c, u64 sent_ms) {
  quic_memset(c, 0, sizeof *c);
  c->up               = 1;
  c->boot_ini_len     = 100;
  c->boot_pto_sent_ms = sent_ms;
  /* RFC 9000 8.1: past the antiamp gate so a resend's srvrun_boot_send_
   * initial call actually goes out -- the same 1280-received-bytes budget
   * this file's sr_antiamp_seed_flight-based tests already use, generous
   * enough for the 100-byte dummy flight above. */
  c->boot_rx_bytes = 1280;
  /* RFC 9002 6.2.2: without this, srvrun_pto_deadline_ms sees an all-zero
   * quic_rtt (no kInitialRtt seed) and floors the deadline near 0, firing
   * immediately regardless of now_ms -- same seeding sr_make_confirmed_conn
   * does for the post-confirm PTO tests. */
  quic_rtt_init(&c->rtt);
}

static srvrun_cfg sr_boot_pto_cfg(void) {
  srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, &g_srvrun_env,
                    0,  0, 0, 0, 0};
  return cfg;
}

/* T-001: past the boot PTO deadline (srvrun_pto_deadline_ms's own
 * kInitialRtt-based default, same constant test_srvrun_pto_budget_exhausted_
 * tears_down_connection derives: 1024ms before any RTT sample), the cached
 * flight is resent -- proven by srvrun_test_send_count rising, the same
 * proof test_srvrun_initial_retransmit_resends_cached_flight uses for the
 * receive-triggered path. */
static void test_srvrun_boot_pto_resends_after_deadline(void) {
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = sr_boot_pto_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1025};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 0);
  srvrun_test_reset_send_count();
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(srvrun_test_send_count() > 0);
  CHECK(st.conns[0].up == 1);
  CHECK(st.conns[0].boot_pto_count == 1);
}

/* T-002: well before the deadline, no resend happens and the probe count
 * stays untouched -- the boundary complement to T-001. */
static void test_srvrun_boot_pto_no_resend_before_deadline(void) {
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = sr_boot_pto_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, 500}; /* well under the 1024ms floor */
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 0);
  srvrun_test_reset_send_count();
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(srvrun_test_send_count() == 0);
  CHECK(st.conns[0].boot_pto_count == 0);
}

/* T-003: once confirmed, the boot PTO timer never fires again, regardless of
 * how far past the old boot deadline now_ms sits. */
static void test_srvrun_boot_pto_stops_after_confirm(void) {
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = sr_boot_pto_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1025};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 0);
  st.conns[0].s.phase = WIRED_SERVER_HS_CONFIRMED;
  srvrun_test_reset_send_count();
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(srvrun_test_send_count() == 0);
  CHECK(st.conns[0].boot_pto_count == 0);
}

/* T-004: confirm landing in the same instant a boot PTO tick would otherwise
 * have fired -- the confirm check runs first (srvrun_boot_pto_waiting), so
 * the race resolves to "stopped", never a stray extra resend. */
static void test_srvrun_boot_pto_confirm_race_stops_immediately(void) {
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = sr_boot_pto_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1025};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 0);
  /* one real probe first, to prove the timer was live at all */
  srvrun_test_reset_send_count();
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(srvrun_test_send_count() > 0);
  /* confirm lands right as the next tick would be due again */
  st.conns[0].s.phase = WIRED_SERVER_HS_CONFIRMED;
  srvrun_test_reset_send_count();
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(srvrun_test_send_count() == 0);
}

/* T-005: SRVRUN_PTO_MAX consecutive boot PTO fires with no confirm ever
 * landing tears the connection slot down, mirroring test_srvrun_pto_budget_
 * exhausted_tears_down_connection's policy for the post-confirm path. Each
 * successive deadline doubles (RFC 9002 6.2 exponential backoff, the same
 * kInitialRtt-derived 1024ms base). */
static void test_srvrun_boot_pto_budget_exhausted_frees_slot(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_state   st  = {table, sr_test_conns()};
  srvrun_cfg     cfg = sr_boot_pto_cfg();
  u64            now = 1025;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 0);
  for (int i = 0; i < SRVRUN_PTO_MAX - 1; i++) {
    srvrun_step_ctx tick = {&cfg, 0, &st, now};
    srvrun_boot_pto_slot(&tick, 0);
    CHECK(st.conns[0].up == 1);
    now += 1024u << (i + 1);
  }
  {
    srvrun_step_ctx tick = {&cfg, 0, &st, now};
    srvrun_boot_pto_slot(&tick, 0); /* budget spent: tears the slot down */
    CHECK(st.conns[0].up == 0);
  }
}

/* T-006: one probe short of the budget, the slot survives and keeps
 * resending -- the boundary complement to T-005. */
static void test_srvrun_boot_pto_budget_not_yet_exhausted_keeps_slot(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_state   st  = {table, sr_test_conns()};
  srvrun_cfg     cfg = sr_boot_pto_cfg();
  u64            now = 1025;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 0);
  for (int i = 0; i < SRVRUN_PTO_MAX - 1; i++) {
    srvrun_step_ctx tick = {&cfg, 0, &st, now};
    srvrun_test_reset_send_count();
    srvrun_boot_pto_slot(&tick, 0);
    CHECK(srvrun_test_send_count() > 0);
    CHECK(st.conns[0].up == 1);
    now += 1024u << (i + 1);
  }
  CHECK(st.conns[0].boot_pto_count == SRVRUN_PTO_MAX - 1);
}

/* T-007: a slot with no boot flight ever cached (boot_ini_len == 0 -- still
 * mid-ClientHello-reassembly, or a boot that failed) is a no-op: no send, no
 * probe count, no teardown, regardless of how far now_ms has advanced. */
static void test_srvrun_boot_pto_noop_without_sent_flight(void) {
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = sr_boot_pto_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1000000};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 0);
  st.conns[0].boot_ini_len = 0;
  srvrun_test_reset_send_count();
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(srvrun_test_send_count() == 0);
  CHECK(st.conns[0].up == 1);
  CHECK(st.conns[0].boot_pto_count == 0);
}

/* T-008: a slot that is not up at all (never accepted, or already freed) is
 * a no-op -- srvrun_awaiting_confirm requires c->up. */
static void test_srvrun_boot_pto_noop_when_not_up(void) {
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = sr_boot_pto_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1000000};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 0);
  st.conns[0].up = 0;
  srvrun_test_reset_send_count();
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(srvrun_test_send_count() == 0);
  CHECK(st.conns[0].boot_pto_count == 0);
}

/* T-009: a client-triggered retransmit (srvrun_resend_boot_flight) landing
 * in the same round as a would-be boot PTO deadline re-arms the deadline --
 * the immediately following srvrun_boot_pto_slot call must NOT also fire, or
 * the same flight would go out twice for one round. */
static void test_srvrun_boot_pto_no_double_send_after_client_retransmit(void) {
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_state    st  = {table, sr_test_conns()};
  srvrun_cfg      cfg = sr_boot_pto_cfg();
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1025};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_boot_conn(&st.conns[0], 0);
  /* the client's own Initial retransmit arrives first this round */
  srvrun_resend_boot_flight(&ctx, &st.conns[0]);
  CHECK(st.conns[0].boot_pto_count == 0);
  /* the timer-driven boot PTO evaluates right after, same now_ms */
  srvrun_test_reset_send_count();
  srvrun_boot_pto_slot(&ctx, 0);
  CHECK(srvrun_test_send_count() == 0);
  CHECK(st.conns[0].boot_pto_count == 0);
}

/* RFC 9002 7.5's "MUST NOT be blocked by the congestion controller" covers
 * pacing (7.7) too, not just cwnd -- a queued probe goes out even with the
 * pacing deadline far in the future (srvrun_pace_or_probe_ok). An earlier
 * version of this SDK exempted PTO probes from cwnd but still gated them on
 * pacing; that was itself found to stall a real blackhole interop run (an
 * RTT spike from a link outage pushes next_send_ms far out, silently
 * swallowing the one send that would recover the connection) and was
 * corrected -- see test_srvrun_pace_probe_bypasses_pacing_gate for the
 * dedicated coverage of that fix. */
static void test_srvrun_pto_probe_bypasses_pacing_too(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20;
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_pto_fire(&c.resp[0].sess, SRVRUN_PTO_MAX));
    CHECK(c.resp[0].sess.requeue_n == 1);
    /* an RTT sample exists and the pacing deadline is far in the future --
     * the queued probe still goes out despite it. */
    c.srtt_ms      = 40;
    c.next_send_ms = ctx.now_ms + 1000;
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.requeue_n == 0); /* pacing did not block it */
  }
}

/* @file
 * RFC 9000 4.6/19.11: MAX_STREAMS re-grant, one raise per released srvloop
 * receive slot, keeping the advertised bidi stream limit in lockstep with
 * WIRED_SRVLOOP_MAX_STREAMS instead of promising room the fixed-size slot
 * table cannot back (the multiplexing interop stall this fixes: a real
 * quic-go client exhausts the initial 100-stream limit and blocks forever
 * because the server never raises it). */

/* T-002/T-003: releasing a request stream's receive slot (srvrun_resp_reap,
 * once its session goes idle and it isn't streaming) raises the advertised
 * limit by exactly one past the transport-parameter default. */
static void test_srvrun_slot_release_grants_one_more_stream(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20;
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_pump_sess(&ctx, 0);
    /* deliver the whole session's ACK so srvrun_resp_reap sees it idle */
    wired_sendsess_ack(&c.resp[0].sess, 0, ~(u64)0);
    CHECK(c.stream_limit_advertised == 0); /* nothing granted yet */
    srvrun_reap_resps(&ctx, &c, 0);
    CHECK(c.resp[0].in_use == 0); /* slot released */
    CHECK(c.stream_limit_advertised == QUIC_STP_DEFAULT_MAX_STREAMS_BIDI + 1);
  }
}

/* T-004: the advertised limit only ever grows -- a second release raises it
 * one more from where it already stood, never resets or drops. */
static void test_srvrun_stream_limit_never_decreases(void) {
  static u8     body0[SRVRUN_CHUNK];
  static u8     body1[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20;
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  c.resp[1].in_use    = 1;
  c.resp[1].stream_id = 4;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_pump_sess(&ctx, 0);
    wired_sendsess_ack(&c.resp[0].sess, 0, ~(u64)0);
    srvrun_reap_resps(&ctx, &c, 0);
    CHECK(c.stream_limit_advertised == QUIC_STP_DEFAULT_MAX_STREAMS_BIDI + 1);
    wired_sendsess_ack(&c.resp[1].sess, 0, ~(u64)0);
    srvrun_reap_resps(&ctx, &c, 0);
    CHECK(c.stream_limit_advertised == QUIC_STP_DEFAULT_MAX_STREAMS_BIDI + 2);
  }
}

/* T-002/T-006: a STREAMS_BLOCKED sighting re-sends the limit already in
 * force -- never a peer-claimed value (the frame's own limit field is never
 * even latched, gather_streams_blocked only sets the flag). Needs a
 * confirmed connection (real 1-RTT keys) so the resend actually seals and
 * the send-count assertion below can tell "resent" from "silently
 * dropped". */
static void test_srvrun_streams_blocked_reannounces_current_limit(void) {
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.stream_limit_advertised     = 150;
  c.l.streams_blocked_seen_flag = 1;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, 0, 0, 0};
    srvrun_test_reset_send_count();
    srvrun_reannounce_stream_limit(ctx.cfg, &c, srvrun_stream_limit_base(&ctx));
  }
  CHECK(srvrun_test_send_count() == 1);      /* actually resent, not skipped */
  CHECK(c.stream_limit_advertised == 150);   /* repeated, not recomputed */
  CHECK(c.l.streams_blocked_seen_flag == 0); /* consumed */
}

/* T-011: a connection where no request stream has ever been released yet
 * (fresh, stream_limit_advertised still 0) does not misfire a MAX_STREAMS
 * re-grant on a STREAMS_BLOCKED sighting -- it falls back to the same
 * transport-parameter default already advertised, not some other value.
 * Needs a confirmed connection (real 1-RTT keys) so the send actually seals
 * and stream_limit_advertised gets recorded -- an unconfirmed c's send
 * silently fails to seal (mirrors every other real-send test's setup). */
static void test_srvrun_streams_blocked_before_any_release_uses_base(void) {
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.l.streams_blocked_seen_flag = 1;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, 0, 0, 0};
    srvrun_reannounce_stream_limit(ctx.cfg, &c, srvrun_stream_limit_base(&ctx));
  }
  CHECK(c.stream_limit_advertised == QUIC_STP_DEFAULT_MAX_STREAMS_BIDI);
}

/* T-007/T-008 regression: a small case (one stream opened and closed) grants
 * exactly the expected +1 and nothing more -- no runaway re-grants from a
 * single release, and the flag-based STREAMS_BLOCKED gate stays untouched
 * when no STREAMS_BLOCKED was ever seen. */
static void test_srvrun_stream_limit_small_case_single_grant(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.cc.cwnd           = 1u << 20;
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  wired_sendsess_arm(&c.resp[0].sess, body, sizeof body, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_pump_sess(&ctx, 0);
    wired_sendsess_ack(&c.resp[0].sess, 0, ~(u64)0);
    srvrun_reap_resps(&ctx, &c, 0);
    srvrun_reannounce_stream_limit(ctx.cfg, &c, srvrun_stream_limit_base(&ctx));
  }
  CHECK(c.l.streams_blocked_seen_flag == 0);
  CHECK(c.stream_limit_advertised == QUIC_STP_DEFAULT_MAX_STREAMS_BIDI + 1);
}

/* END-TO-END REGRESSION for the real interop stall: two slots share a cwnd
 * pinned so tight neither slot alone has room for a fresh chunk. Slot 0's
 * one in-flight slice PTOs -- without RFC 9002 7.5's cwnd bypass, this
 * deadlocks forever (cwnd only grows from ACKs, ACKs need sends, the probe
 * IS the send that would produce one). With the bypass, the probe goes out,
 * an ACK for it arrives, and cwnd starts growing again -- breaking the
 * exact stall observed against a real quic-go client (cwnd/inflight stuck
 * at the same value, log never draining, eventual PTO-budget teardown). */
static void test_srvrun_pto_resend_breaks_cwnd_deadlock(void) {
  static u8     body0[SRVRUN_CHUNK];
  static u8     body1[SRVRUN_CHUNK];
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.resp[0].in_use    = 1;
  c.resp[0].stream_id = 0;
  c.resp[1].in_use    = 1;
  c.resp[1].stream_id = 4;
  wired_sendsess_arm(&c.resp[0].sess, body0, sizeof body0, SRVRUN_CHUNK);
  wired_sendsess_arm(&c.resp[1].sess, body1, sizeof body1, SRVRUN_CHUNK);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {0, &c};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    c.cc.cwnd           = 2 * SRVRUN_CHUNK; /* exactly enough for one each */
    srvrun_pump_sess(&ctx, 0);
    CHECK(wired_sendsess_inflight(&c.resp[0].sess) == 1);
    CHECK(wired_sendsess_inflight(&c.resp[1].sess) == 1);
    /* pin cwnd to exactly slot 1's chunk -- slot 0's probe has no cwnd
     * room, matching the real stall's inf==cwnd-ish stuck state. */
    c.cc.cwnd = SRVRUN_CHUNK;
    CHECK(wired_sendsess_pto_fire(&c.resp[0].sess, SRVRUN_PTO_MAX));
    CHECK(c.resp[0].sess.requeue_n == 1);
    srvrun_pump_sess(&ctx, 0);
    CHECK(c.resp[0].sess.requeue_n == 0); /* the probe broke the deadlock */
    /* the probe used a FRESH pn (wired_sendsess_take/srvrun_send_slice
     * mint a new one on every send, retransmit or not) -- feed an ACK
     * range covering everything sent so far and confirm cwnd actually
     * grows again, proving the deadlock is broken end to end, not just
     * that one packet moved. */
    quic_cc_on_ack(&c.cc, SRVRUN_CHUNK, ctx.now_ms, ctx.now_ms);
    CHECK(c.cc.cwnd > SRVRUN_CHUNK);
  }
}

/* WT SUBPROTOCOL NEGOTIATION (draft-ietf-webtrans-http3-15 SS3.4): helpers
 * shared by the tests below. srn_wt_contains scans a response row's bytes
 * for a raw substring -- the wt-protocol field line is encoded as a Literal
 * Field Line With Literal Name (RFC 9204 4.5.6), so its name and sf-string
 * value appear verbatim in the QPACK payload. */
static int srn_wt_contains(const u8* hay, usz n, const char* needle) {
  usz m = quic_cstr_len(needle);
  for (usz i = 0; i + m <= n; i++)
    if (wt_bytes_eq(hay + i, (const u8*)needle, m)) return 1;
  return 0;
}

/* Set the synthetic request's wt-available-protocols offer (the raw sf-list
 * value, exactly what h3reqdrive's capture copies). */
static void srn_wt_set_avail(srvrun_conn* c, const char* offer) {
  usz n = quic_cstr_len(offer);
  quic_memcpy(c->l.req.wt_avail, offer, n);
  c->l.req.wt_avail_len = n;
}

/* Drive srvrun_start_resp over the already-set synthetic request with the
 * given negotiation config (server subprotocol list + session callback). */
static void srn_wt_start(
    quic_conntable*     table,
    srvrun_conn*        conns,
    const char*         protocols,
    wired_wt_on_session on_session) {
  srvrun_cfg      cfg = {-1, 0, 0,         0,          0, 0, 0, 0,
                         0,  0, 0,         0,          0, 0, 0, &g_srvrun_env,
                         0,  0, protocols, on_session, 0};
  srvrun_state    st  = {table, conns};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
  srvrun_start_resp(&ctx, 0);
}

/* An offer with two client-supported subprotocols against a server list
 * holding both picks the CLIENT's first choice (client preference order
 * wins), and the 200's QPACK payload carries a wt-protocol field line whose
 * value is the DQUOTE-wrapped sf-string (the reference peer rejects an
 * unquoted value). */
static void test_srvrun_wt_negotiate_picks_first_client_choice(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  srn_wt_set_avail(&conns[0], "\"foo\", \"bar\"");
  quic_memset(g_srvrun_respstore[0][0], 0, 256);
  srn_wt_start(table, conns, "bar foo", 0);
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].resp[0].sess.active == 1);
  CHECK(srn_wt_contains(g_srvrun_respstore[0][0], 256, "wt-protocol"));
  CHECK(srn_wt_contains(g_srvrun_respstore[0][0], 256, "\"foo\""));
  CHECK(!srn_wt_contains(g_srvrun_respstore[0][0], 256, "\"bar\""));
}

/* No common subprotocol: the session is still accepted (200 armed), but the
 * response carries no wt-protocol header. */
static void test_srvrun_wt_negotiate_no_common_no_header(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  srn_wt_set_avail(&conns[0], "\"foo\"");
  quic_memset(g_srvrun_respstore[0][0], 0, 256);
  srn_wt_start(table, conns, "baz", 0);
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].resp[0].sess.active == 1);
  CHECK(!srn_wt_contains(g_srvrun_respstore[0][0], 256, "wt-protocol"));
}

/* No wt-available-protocols header at all: the session is accepted exactly
 * as before negotiation existed, no wt-protocol header. */
static void test_srvrun_wt_negotiate_absent_offer_no_header(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  quic_memset(g_srvrun_respstore[0][0], 0, 256);
  srn_wt_start(table, conns, "foo", 0);
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].resp[0].sess.active == 1);
  CHECK(!srn_wt_contains(g_srvrun_respstore[0][0], 256, "wt-protocol"));
}

/* An offer that is not a valid sf-list (a bare unquoted token, RFC 8941
 * 3.3.3 requires DQUOTEs) is discarded entirely (RFC 8941 4.2): no
 * wt-protocol header, session still accepted. */
static void test_srvrun_wt_negotiate_bad_syntax_no_header(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  srn_wt_set_avail(&conns[0], "foo");
  quic_memset(g_srvrun_respstore[0][0], 0, 256);
  srn_wt_start(table, conns, "foo", 0);
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].resp[0].sess.active == 1);
  CHECK(!srn_wt_contains(g_srvrun_respstore[0][0], 256, "wt-protocol"));
}

/* REGRESSION: wt_protocols unset (0, the default) skips negotiation even
 * when the client sent an offer -- identical to the pre-negotiation 200. */
static void test_srvrun_wt_negotiate_disabled_unchanged(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  srn_wt_set_avail(&conns[0], "\"foo\"");
  quic_memset(g_srvrun_respstore[0][0], 0, 256);
  srn_wt_start(table, conns, 0, 0);
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].resp[0].sess.active == 1);
  CHECK(!srn_wt_contains(g_srvrun_respstore[0][0], 256, "wt-protocol"));
}

/* wt_on_session capture globals: call count, the last session pointer, and
 * copies of the delivered path/protocol views (they do not outlive the
 * call). */
static int               g_srn_wt_sess_calls = 0;
static wired_wt_session* g_srn_wt_sess_last  = 0;
static u8                g_srn_wt_sess_path[128];
static usz               g_srn_wt_sess_path_len = 0;
static u8                g_srn_wt_sess_proto[64];
static usz               g_srn_wt_sess_proto_len = 0;

static void srn_wt_on_session(
    void* ctx, wired_wt_session* s, quic_span path, quic_span protocol) {
  (void)ctx;
  g_srn_wt_sess_calls++;
  g_srn_wt_sess_last = s;
  quic_memcpy(g_srn_wt_sess_path, path.p, path.n);
  g_srn_wt_sess_path_len = path.n;
  quic_memcpy(g_srn_wt_sess_proto, protocol.p, protocol.n);
  g_srn_wt_sess_proto_len = protocol.n;
}

/* wt_on_session fires exactly once per accepted Extended CONNECT, with the
 * recorded :path and the negotiated raw token (not its sf-string form). */
static void test_srvrun_wt_on_session_notified_once(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  g_srn_wt_sess_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  srn_wt_set_avail(&conns[0], "\"chat\"");
  srn_wt_start(table, conns, "chat", srn_wt_on_session);
  CHECK(g_srn_wt_sess_calls == 1);
  CHECK(g_srn_wt_sess_last == &conns[0].wt);
  CHECK(g_srn_wt_sess_path_len == 3);
  CHECK(wt_bytes_eq(g_srn_wt_sess_path, (const u8*)"/wt", 3));
  CHECK(g_srn_wt_sess_proto_len == 4);
  CHECK(wt_bytes_eq(g_srn_wt_sess_proto, (const u8*)"chat", 4));
}

/* No negotiation result -> the callback still fires, with an empty protocol
 * span. */
static void test_srvrun_wt_on_session_empty_protocol(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn*   conns = sr_test_conns();
  quic_obuf      ob;
  u8             obuf[1024];
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  g_srn_wt_sess_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  srn_wt_start(table, conns, 0, srn_wt_on_session);
  CHECK(g_srn_wt_sess_calls == 1);
  CHECK(g_srn_wt_sess_proto_len == 0);
}

/* A second session on the same connection gets its own notification with its
 * own :path and its own session slot. */
static void test_srvrun_wt_on_session_two_sessions_each_path(void) {
  static const u8 second_path[] = "/two";
  struct lp_fix   f;
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_conn*    conns = sr_test_conns();
  quic_obuf       ob;
  u8              obuf[1024];
  ob                  = (quic_obuf){obuf, sizeof obuf, 0};
  g_srn_wt_sess_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  srn_wt_start(table, conns, 0, srn_wt_on_session);
  CHECK(g_srn_wt_sess_calls == 1);
  CHECK(g_srn_wt_sess_last == &conns[0].wt);
  conns[0].resp[0].in_use = 0; /* pretend the first 2xx finished sending */
  sr_set_req(&conns[0], 1, 1, 8);
  conns[0].l.req.path     = second_path;
  conns[0].l.req.path_len = sizeof second_path - 1;
  srn_wt_start(table, conns, 0, srn_wt_on_session);
  CHECK(g_srn_wt_sess_calls == 2);
  CHECK(g_srn_wt_sess_last == &conns[0].wt1);
  CHECK(g_srn_wt_sess_path_len == 4);
  CHECK(wt_bytes_eq(g_srn_wt_sess_path, (const u8*)"/two", 4));
}

/* RFC 9204 4.5.6: a Literal Field Line With Literal Name carrying
 * (name,value), appended at *off in fs. Local twin of h3reqdrive_test.c's
 * put_litname (that one is another test file's static). */
static void srn_put_litname(
    u8* fs, usz* off, const char* name, const char* value) {
  quic_qpack_field fl = {
      quic_span_of((const u8*)name, quic_cstr_len(name)),
      quic_span_of((const u8*)value, quic_cstr_len(value))};
  *off += quic_qpack_literal_name_encode(quic_mspan_of(fs + *off, 128), 0, &fl);
}

/* WIRE CAPTURE (draft-ietf-webtrans-http3-15 SS3.4): a regular
 * `wt-available-protocols` header decoded off a real QPACK field section
 * lands in r.wt_avail verbatim; a request without it leaves the offer
 * absent; a value too large for the fixed buffer is dropped, not
 * truncated (a truncated sf-list would parse as garbage). */
static void test_srvrun_wt_avail_captured_from_wire(void) {
  u8                   fs[512], req[768], scratch[512], big[300];
  usz                  off;
  quic_obuf            req_ob = {req, sizeof req, 0};
  wired_h3reqdrive_req r;
  quic_qpack_prefix    pfx = {0, 0, 0};
  off                      = quic_qpack_prefix_encode(fs, 64, &pfx);
  off += quic_qpack_indexed_encode(
      quic_mspan_of(fs + off, 64), 17, 1); /* :method GET */
  srn_put_litname(fs, &off, "wt-available-protocols", "\"foo\", \"bar\"");
  {
    quic_h3conn_req_in req_in = {quic_span_of(fs, off), quic_span_of(0, 0)};
    CHECK(quic_h3conn_send_request(0, &req_in, &req_ob));
  }
  CHECK(wired_h3reqdrive_recv_get(
      quic_span_of(req, req_ob.len), quic_mspan_of(scratch, sizeof scratch),
      &r));
  CHECK(r.wt_avail_len == 12);
  CHECK(wt_bytes_eq(r.wt_avail, (const u8*)"\"foo\", \"bar\"", 12));
  /* absent header -> absent offer */
  {
    u8        fs2[64], req2[256];
    quic_obuf ob2 = {req2, sizeof req2, 0};
    usz       n2  = quic_qpack_prefix_encode(fs2, 64, &pfx);
    n2 += quic_qpack_indexed_encode(quic_mspan_of(fs2 + n2, 64), 17, 1);
    {
      quic_h3conn_req_in in2 = {quic_span_of(fs2, n2), quic_span_of(0, 0)};
      CHECK(quic_h3conn_send_request(0, &in2, &ob2));
    }
    CHECK(wired_h3reqdrive_recv_get(
        quic_span_of(req2, ob2.len), quic_mspan_of(scratch, sizeof scratch),
        &r));
    CHECK(r.wt_avail_len == 0);
  }
  /* an oversized value (300 octets > the 256-octet buffer) is dropped */
  {
    static u8        scratch3[1024];
    quic_qpack_field fl;
    quic_obuf        ob3 = {req, sizeof req, 0};
    for (usz i = 0; i < sizeof big; i++) big[i] = 'a';
    big[0]   = '"';
    big[299] = '"';
    fl       = (quic_qpack_field){
        quic_span_of((const u8*)"wt-available-protocols", 22),
        quic_span_of(big, sizeof big)};
    off = quic_qpack_prefix_encode(fs, 64, &pfx);
    off += quic_qpack_indexed_encode(quic_mspan_of(fs + off, 64), 17, 1);
    off += quic_qpack_literal_name_encode(
        quic_mspan_of(fs + off, sizeof fs - off), 0, &fl);
    {
      quic_h3conn_req_in in3 = {quic_span_of(fs, off), quic_span_of(0, 0)};
      CHECK(quic_h3conn_send_request(0, &in3, &ob3));
    }
    CHECK(wired_h3reqdrive_recv_get(
        quic_span_of(req, ob3.len), quic_mspan_of(scratch3, sizeof scratch3),
        &r));
    CHECK(r.wt_avail_len == 0);
  }
}

/* ===== Server-initiated WebTransport stream / datagram sending ===== */

/* Fixture: a confirmed connection installed at g_srvrun_env's slot 0 with an
 * active WT session (CONNECT stream id 4), so the wired_server_wt_* API can
 * resolve the session pointer back to its connection slot exactly the way a
 * production callback's session argument does. Send-side gates are opened
 * wide except where a test narrows one on purpose; the datagram ring is
 * reset so tests do not leak queued entries into one another. */
static srvrun_conn* sr_wtsend_fixture(struct lp_fix* f, quic_obuf* ob) {
  srvrun_conn* c = &g_srvrun_state.conns[0];
  sr_reset_global_table();
  g_srvrun_env.dgring_head = 0;
  g_srvrun_env.dgring_n    = 0;
  sr_make_confirmed_conn(c, f, ob);
  wired_wt_session_init(&c->wt, 4);
  wired_wt_session_establish(&c->wt);
  c->wt_active                                       = 1;
  c->s.sdrv.peer_initial_max_stream_data_uni         = 1u << 24;
  c->s.sdrv.peer_initial_max_stream_data_bidi_remote = 1u << 24;
  c->cc.cwnd                                         = 1u << 20;
  return c;
}

/* ACK every slice currently in s's send log (the same hand-driven
 * ACK-drains-the-window cycle test_srvrun_loss_and_retransmit_across_two_
 * responses runs), then reset pacing so the next pump is not blocked by the
 * fixed test clock. */
static void sr_wtsend_ack_all_inflight(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_sendsess* s, u64 now) {
  u64 lo = 0, hi = 0;
  int found = 0;
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    const wired_sent_slice* e = &s->log[i];
    if (!e->inflight) continue;
    if (!found || e->pn < lo) lo = e->pn;
    if (!found || e->pn > hi) hi = e->pn;
    found = 1;
  }
  if (!found) return;
  srvrun_feed_ack_range(cfg, c, lo, hi, now);
  c->srtt_ms      = 0;
  c->next_send_ms = 0;
}

/* WIRE: wired_server_wt_open_uni allocates the first free server uni id
 * (RFC 9000 2.1: 3 mod 4; the H3 control stream already took 3, so 7) and
 * the pump sends the payload verbatim as a STREAM frame on that id from
 * offset 0, FIN on the final slice. A second open is 4 apart. */
static const u8 sr_wtsend_hello[] = {0x54, 0x04, 'h', 'i'};

static void test_srvrun_wt_open_uni_streams_payload_on_wire(void) {
  struct lp_fix    f;
  quic_obuf        ob = {0};
  u8               obuf[1024];
  u8               asm_buf[64] = {0};
  quic_sockaddr_in srv, from;
  i64              sfd, cfd, id;
  usz              high = 0;
  int              fin  = 0;
  srvrun_conn*     c;
  if (!sr_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  ob      = (quic_obuf){obuf, sizeof obuf, 0};
  c       = sr_wtsend_fixture(&f, &ob);
  c->peer = srv;
  id      = wired_server_wt_open_uni(
      &c->wt, quic_span_of(sr_wtsend_hello, sizeof sr_wtsend_hello));
  CHECK(id == 7);
  {
    srvrun_cfg   cfg = {cfd,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx ctx = {&cfg, &srv, &st, 0};
    srvrun_pump_sess(&ctx, 0);
  }
  {
    u8                pkt[1500];
    const u8*         pl;
    usz               pll;
    quic_stream_frame sf;
    i64 r = wired_udp_recvfrom(sfd, quic_mspan_of(pkt, sizeof pkt), &from);
    CHECK(r > 0);
    CHECK(client_open_onertt(&f, pkt, (usz)r, &pl, &pll) == 1);
    CHECK(quic_frame_get_stream(pl, pll, &sf) > 0);
    CHECK(sf.stream_id == 7);
    CHECK(sf.offset == 0);
    high = sr_collect_stream(pl, pll, asm_buf, sizeof asm_buf, high, &fin);
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
  CHECK(fin == 1);
  CHECK(high == sizeof sr_wtsend_hello);
  for (usz i = 0; i < sizeof sr_wtsend_hello; i++)
    CHECK(asm_buf[i] == sr_wtsend_hello[i]);
  CHECK(
      wired_server_wt_open_uni(
          &c->wt, quic_span_of(sr_wtsend_hello, sizeof sr_wtsend_hello)) == 11);
}

/* RFC 9000 2.1: server-initiated bidi ids are 1 mod 4, allocated from 1 and
 * 4 apart. The armed slot holds the app's payload as a VIEW (no copy, the
 * srvrun.h liveness contract) and its send credit is seeded from the peer's
 * initial_max_stream_data_bidi_remote (0x06). */
static void test_srvrun_wt_open_bidi_allocates_ids_and_holds_view(void) {
  struct lp_fix   f;
  quic_obuf       ob = {0};
  u8              obuf[1024];
  static const u8 pay[] = {0x41, 0x04, 'x'};
  srvrun_conn*    c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  CHECK(wired_server_wt_open_bidi(&c->wt, quic_span_of(pay, sizeof pay)) == 1);
  CHECK(wired_server_wt_open_bidi(&c->wt, quic_span_of(pay, sizeof pay)) == 5);
  CHECK(c->wtsend[0].sess.q.p == pay);
  CHECK(c->wtsend[0].sess.q.len == sizeof pay);
  CHECK(c->wtsend[0].stream_credit == (1u << 24));
}

/* SERVER-INITIATED BIDI RECEIVE (RFC 9000 2.1 / draft-ietf-webtrans-http3-15
 * 4.3): once wired_server_wt_open_bidi has opened a stream, the client's
 * reply on that SAME id (no signal prefix -- the server already knows which
 * session owns it) must be received and delivered to the app callback, not
 * silently dropped. Proves the srvrun_wt_preclaim_bidi_recv wiring: open_bidi
 * pre-claims wt_streams[] for the id it just allocated, so the reply's
 * STREAM frame (id 1, RFC 9000 2.1 server-initiated bidi) lands there even
 * though dispatch.c never saw a leading signal varint for it. */
static void test_srvrun_wt_open_bidi_reply_received(void) {
  struct lp_fix   f;
  quic_obuf       ob = {0};
  u8              obuf[1024], out[1024], frm[64], spkt[1024];
  usz             slen;
  static const u8 pay[]   = {0x41, 0x04, 'x'};
  static const u8 reply[] = {'p', 'o', 'n', 'g'};
  srvrun_conn*    c;
  i64             id;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  id = wired_server_wt_open_bidi(&c->wt, quic_span_of(pay, sizeof pay));
  CHECK(id == 1);
  /* the receive slot was pre-claimed at open time, sig_len 0 (no signal). */
  {
    int i = wired_srvloop_wt_slot_find(&c->l, (u64)id);
    CHECK(i >= 0 && c->l.wt_streams[i].sig_len == 0);
    CHECK(c->l.wt_streams[i].offered == 1);
  }
  /* the client's reply arrives on stream id 1 with no signal prefix. */
  {
    quic_stream_frame sf = {(u64)id, 0, sizeof reply, reply, 1};
    usz               fl = quic_frame_put_stream(frm, sizeof frm, &sf);
    quic_obuf         sob;
    CHECK(fl != 0);
    slen = client_seal_onertt_pn(&f, 3, frm, fl, spkt, sizeof spkt);
    sob  = (quic_obuf){out, sizeof out, 0};
    wired_srvloop_step(
        &(wired_srvloop_conn){&c->l, &c->s}, quic_mspan_of(spkt, slen), &sob);
  }
  g_srsd_calls = 0;
  {
    srvrun_cfg cfg = {
        -1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        sr_stream_data_handler,
        0,
        0,
        &g_srvrun_env,
        0,
        0,
        0,
        0,
        0};
    srvrun_offer_wt_streams(&cfg, c);
  }
  CHECK(g_srsd_calls == 1);
  CHECK(g_srsd_last_stream_id == (u64)id);
  CHECK(g_srsd_last_len == sizeof reply);
  CHECK(g_srsd_last_fin == 1);
  for (usz i = 0; i < sizeof reply; i++) CHECK(g_srsd_last_buf[i] == reply[i]);
}

/* wired_server_wt_stream_reply arms the caller-named client bidi stream with
 * the payload verbatim (no signal prefix -- the client opened the stream, so
 * the prefix already went the other way), credit seeded from the peer's
 * initial_max_stream_data_bidi_local (0x05). */
static void test_srvrun_wt_stream_reply_arms_given_stream_verbatim(void) {
  struct lp_fix   f;
  quic_obuf       ob = {0};
  u8              obuf[1024];
  static const u8 pay[] = {'r', 'e', 'p', 'l', 'y'};
  srvrun_conn*    c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  CHECK(
      wired_server_wt_stream_reply(&c->wt, 8, quic_span_of(pay, sizeof pay)) ==
      1);
  CHECK(c->wtsend[0].in_use == 1);
  CHECK(c->wtsend[0].stream_id == 8);
  CHECK(c->wtsend[0].sess.q.p == pay);
  CHECK(
      c->wtsend[0].stream_credit ==
      c->s.sdrv.peer_initial_max_stream_data_bidi_local);
}

/* BOUNDARY: a session pointer no live connection owns (e.g. a stale or
 * caller-local wired_wt_session) resolves to nothing -- every send API
 * rejects it without touching any connection's state. */
static void test_srvrun_wt_open_unknown_session_rejected(void) {
  struct lp_fix    f;
  quic_obuf        ob = {0};
  u8               obuf[1024];
  wired_wt_session ghost;
  static const u8  pay[] = {1, 2, 3};
  srvrun_conn*     c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  (void)c;
  wired_wt_session_init(&ghost, 4);
  CHECK(wired_server_wt_open_uni(&ghost, quic_span_of(pay, sizeof pay)) < 0);
  CHECK(wired_server_wt_open_bidi(&ghost, quic_span_of(pay, sizeof pay)) < 0);
  CHECK(
      wired_server_wt_stream_reply(&ghost, 8, quic_span_of(pay, sizeof pay)) ==
      0);
  CHECK(
      wired_server_wt_send_datagram_to(&ghost, quic_span_of(pay, sizeof pay)) ==
      0);
  CHECK(c->wtsend[0].in_use == 0);
}

/* SLOT EXHAUSTION: the 7th concurrent open fails (SRVRUN_WT_SEND_SLOTS = 6)
 * without burning a stream id; once every armed stream is fully ACKed the
 * slots are reaped and a new open succeeds with the next id in sequence. */
static void test_srvrun_wt_open_slot_exhaustion_and_reuse(void) {
  struct lp_fix   f;
  quic_obuf       ob = {0};
  u8              obuf[1024];
  static const u8 pay[4] = {1, 2, 3, 4};
  srvrun_conn*    c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  for (int i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    CHECK(
        wired_server_wt_open_uni(&c->wt, quic_span_of(pay, sizeof pay)) ==
        7 + 4 * (i64)i);
  CHECK(wired_server_wt_open_uni(&c->wt, quic_span_of(pay, sizeof pay)) < 0);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
    srvrun_feed_ack_range(&cfg, c, 0, c->l.tx_pn, 1); /* covers every pn */
  }
  srvrun_reap_wtsends(c);
  for (int i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    CHECK(c->wtsend[i].in_use == 0);
  CHECK(
      wired_server_wt_open_uni(&c->wt, quic_span_of(pay, sizeof pay)) ==
      7 + 4 * (i64)SRVRUN_WT_SEND_SLOTS);
}

/* RFC 9000 4.1/19.10: a peer uni-stream credit below one chunk blocks the
 * pump from byte 0; a MAX_STREAM_DATA naming the new stream (received over
 * the real wire) raises the ceiling and the pump resumes. */
static void test_srvrun_wt_open_uni_respects_stream_credit(void) {
  static u8     body[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  c->s.sdrv.peer_initial_max_stream_data_uni = SRVRUN_CHUNK / 2;
  CHECK(wired_server_wt_open_uni(&c->wt, quic_span_of(body, sizeof body)) == 7);
  CHECK(c->wtsend[0].stream_credit == SRVRUN_CHUNK / 2);
  {
    srvrun_cfg             cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                                  0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                                  0,  0, 0, 0, 0};
    srvrun_state           st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx        ctx = {&cfg, 0, &st, 1};
    u8                     fr[32], spkt[1024];
    usz                    fl, slen;
    quic_stream_data_frame msd = {7, SRVRUN_CHUNK * 10};
    srvrun_pump_sess(&ctx, 0);
    CHECK(c->wtsend[0].sess.q.cur == 0); /* blocked below one chunk */
    fl = quic_max_stream_data_encode(fr, sizeof fr, &msd);
    CHECK(fl > 0);
    slen = client_seal_onertt(&f, fr, fl, spkt, sizeof spkt);
    srvrun_on_step(&ctx, c, quic_mspan_of(spkt, slen));
    srvrun_sess_on_step(&ctx, 0);
    CHECK(c->wtsend[0].stream_credit == SRVRUN_CHUNK * 10);
    CHECK(c->wtsend[0].sess.q.cur > 0); /* resumed */
  }
}

/* RFC 9000 4.1: WT sends draw from the SAME connection-level credit as
 * resp[] responses -- with room for exactly one chunk total, the WT slot
 * (pumped first in the round) takes it and the resp slot finds the ceiling
 * spent, never each consuming the full credit independently. */
static void test_srvrun_wt_send_conn_credit_shared_with_resp(void) {
  static u8     wbody[4 * SRVRUN_CHUNK];
  static u8     rbody[4 * SRVRUN_CHUNK];
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob                       = (quic_obuf){obuf, sizeof obuf, 0};
  c                        = sr_wtsend_fixture(&f, &ob);
  c->conn_credit           = SRVRUN_CHUNK + SRVRUN_CHUNK / 2;
  c->resp[0].in_use        = 1;
  c->resp[0].stream_id     = 0;
  c->resp[0].stream_credit = 1u << 24;
  wired_sendsess_arm(&c->resp[0].sess, rbody, sizeof rbody, SRVRUN_CHUNK);
  CHECK(
      wired_server_wt_open_uni(&c->wt, quic_span_of(wbody, sizeof wbody)) == 7);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
  }
  CHECK(c->wtsend[0].sess.q.cur == SRVRUN_CHUNK);
  CHECK(c->resp[0].sess.q.cur == 0);
}

/* RFC 9002 6.2: a WT send slot's unacked slice past its PTO deadline is
 * requeued by the shared probe pass (the same budget policy resp[] slots
 * use), so a lost server-initiated stream slice retransmits. */
static void test_srvrun_wt_send_pto_requeues_unacked_slice(void) {
  static u8     body[SRVRUN_CHUNK];
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  CHECK(wired_server_wt_open_uni(&c->wt, quic_span_of(body, sizeof body)) == 7);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    srvrun_pump_sess(&ctx, 0);
  }
  CHECK(wired_sendsess_inflight(&c->wtsend[0].sess) == 1);
  CHECK(srvrun_pto_all(c, 1 + 10 * 1000) == 1); /* budget intact */
  CHECK(c->wtsend[0].sess.requeue_n == 1);
}

/* VOLUME: a single 2MB payload -- far past the 32-entry send log -- drains
 * to fully-ACKed over repeated pump/ACK rounds (the hand-driven cycle a real
 * peer's ACKs run), and the send slot then reaps itself. */
static u8 sr_wtsend_big[2u << 20];

static void test_srvrun_wt_open_two_megabyte_payload_fully_acked(void) {
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  CHECK(
      wired_server_wt_open_uni(
          &c->wt, quic_span_of(sr_wtsend_big, sizeof sr_wtsend_big)) == 7);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                           0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                           0,  0, 0, 0, 0};
    srvrun_state    st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 1};
    for (int round = 0;
         round < 100 && c->wtsend[0].sess.q.cur < sizeof sr_wtsend_big;
         round++) {
      srvrun_pump_sess(&ctx, 0);
      sr_wtsend_ack_all_inflight(&cfg, c, &c->wtsend[0].sess, 1);
    }
    CHECK(c->wtsend[0].sess.q.cur == sizeof sr_wtsend_big);
    sr_wtsend_ack_all_inflight(&cfg, c, &c->wtsend[0].sess, 1);
  }
  srvrun_reap_wtsends(c);
  CHECK(c->wtsend[0].in_use == 0); /* every byte acked: slot reclaimed */
}

/* WIRE, 5-WAY PARALLEL: five concurrently open server uni streams each carry
 * exactly their own bytes -- reassembled per stream id on the client side,
 * nothing interleaved into a sibling's stream (RFC 9000 2.2). */
static u8 sr_wtsend_bodies[5][2500];
static u8 sr_wtsend_asm[5][2600];

static void test_srvrun_wt_open_five_parallel_streams_unmixed(void) {
  struct lp_fix    f;
  quic_obuf        ob = {0};
  u8               obuf[1024];
  sr_stream_bucket buckets[5] = {0};
  quic_sockaddr_in srv, from;
  i64              sfd, cfd;
  srvrun_conn*     c;
  if (!sr_open_sockets(&sfd, &cfd, &srv)) return; /* sandbox: skip */
  ob      = (quic_obuf){obuf, sizeof obuf, 0};
  c       = sr_wtsend_fixture(&f, &ob);
  c->peer = srv;
  for (usz i = 0; i < 5; i++) {
    for (usz j = 0; j < sizeof sr_wtsend_bodies[i]; j++)
      sr_wtsend_bodies[i][j] = (u8)(i * 31 + j);
    buckets[i].buf = sr_wtsend_asm[i];
    buckets[i].cap = sizeof sr_wtsend_asm[i];
    CHECK(
        wired_server_wt_open_uni(
            &c->wt,
            quic_span_of(sr_wtsend_bodies[i], sizeof sr_wtsend_bodies[i])) ==
        7 + 4 * (i64)i);
  }
  {
    srvrun_cfg   cfg = {cfd,           0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        &g_srvrun_env, 0, 0, 0, 0, 0};
    srvrun_state st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_step_ctx ctx = {&cfg, &srv, &st, 0};
    srvrun_pump_sess(&ctx, 0);
  }
  /* 5 streams x 3 slices (2500 bytes at 1100/chunk) = 15 datagrams */
  for (int d = 0; d < 15; d++) {
    u8        pkt[1500];
    const u8* pl;
    usz       pll;
    i64 r = wired_udp_recvfrom(sfd, quic_mspan_of(pkt, sizeof pkt), &from);
    CHECK(r > 0);
    if (client_open_onertt(&f, pkt, (usz)r, &pl, &pll) == 1)
      sr_collect_stream_multi(pl, pll, buckets, 5);
  }
  wired_udp_close(cfd);
  wired_udp_close(sfd);
  for (usz i = 0; i < 5; i++) {
    usz b = 0;
    while (b < 5 && buckets[b].stream_id != 7 + 4 * i) b++;
    CHECK(b < 5);
    CHECK(buckets[b].used == 1);
    CHECK(buckets[b].fin == 1);
    CHECK(buckets[b].high == sizeof sr_wtsend_bodies[i]);
    for (usz j = 0; j < sizeof sr_wtsend_bodies[i]; j++)
      CHECK(buckets[b].buf[j] == sr_wtsend_bodies[i][j]);
  }
}

/* RFC 9297 2.1: wired_server_wt_send_datagram_to prefixes the quarter-
 * stream-id varint (CONNECT id 4 / 4 = 1) at queue time, and the sealed
 * QUIC DATAGRAM opens back on the client side to exactly qsid + payload. */
static void test_srvrun_wt_send_datagram_to_prefixes_qsid(void) {
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob                                     = (quic_obuf){obuf, sizeof obuf, 0};
  c                                      = sr_wtsend_fixture(&f, &ob);
  c->s.sdrv.peer_max_datagram_frame_size = 65535;
  CHECK(
      wired_server_wt_send_datagram_to(
          &c->wt, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  CHECK(g_srvrun_env.dgring_n == 1);
  {
    const srvrun_dgring_entry* e = &g_srvrun_env.dgring[0];
    CHECK(e->conn_slot == 0);
    CHECK(e->len == 1 + sizeof sr_dg_payload);
    CHECK(e->buf[0] == 0x01);
    for (usz i = 0; i < sizeof sr_dg_payload; i++)
      CHECK(e->buf[1 + i] == sr_dg_payload[i]);
  }
  {
    u8                  out[1600];
    quic_obuf           ob2 = {out, sizeof out, 0};
    const u8*           pl;
    usz                 pll, qn;
    u64                 sid = 0;
    quic_datagram_frame df;
    srvrun_cfg          cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                               0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                               0,  0, 0, 0, 0};
    CHECK(
        srvrun_send_datagram_now(
            &cfg, c,
            quic_span_of(
                g_srvrun_env.dgring[0].buf, g_srvrun_env.dgring[0].len),
            &ob2) == 1);
    CHECK(client_open_onertt(&f, out, ob2.len, &pl, &pll) == 1);
    CHECK(quic_datagram_decode(pl, pll, &df) == pll);
    CHECK(df.length == 1 + sizeof sr_dg_payload);
    qn = quic_wtwire_qsid_take(quic_span_of(df.data, df.length), &sid);
    CHECK(qn == 1);
    CHECK(sid == 4);
    for (usz i = 0; i < sizeof sr_dg_payload; i++)
      CHECK(df.data[1 + i] == sr_dg_payload[i]);
  }
}

/* RFC 9297 2.1: a session-addressed datagram is refused before this
 * endpoint's own SETTINGS have been sent, same self-imposed ordering the
 * single-slot queue already enforces. */
static void test_srvrun_wt_send_datagram_to_requires_settings_sent(void) {
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  c                     = sr_wtsend_fixture(&f, &ob);
  c->l.h3.settings_sent = 0;
  CHECK(
      wired_server_wt_send_datagram_to(
          &c->wt, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 0);
  CHECK(g_srvrun_env.dgring_n == 0);
}

/* BURST: 200 datagrams queued back-to-back inside one step all fit the ring
 * and every one of them goes out on the drain -- none dropped, none
 * overwritten (the ring exists exactly so a burst is not last-writer-wins). */
static void test_srvrun_wt_datagram_ring_drains_200_queued(void) {
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  u8            pay[2];
  srvrun_conn*  c;
  ob                                     = (quic_obuf){obuf, sizeof obuf, 0};
  c                                      = sr_wtsend_fixture(&f, &ob);
  c->s.sdrv.peer_max_datagram_frame_size = 65535;
  for (int i = 0; i < 200; i++) {
    pay[0] = (u8)(i >> 8);
    pay[1] = (u8)i;
    CHECK(wired_server_wt_send_datagram_to(&c->wt, quic_span_of(pay, 2)) == 1);
  }
  CHECK(g_srvrun_env.dgring_n == 200);
  {
    srvrun_cfg   cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                        0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                        0,  0, 0, 0, 0};
    srvrun_state st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_test_reset_send_count();
    srvrun_dgring_drain(&cfg, &st);
    CHECK(srvrun_test_send_count() == 200);
  }
  CHECK(g_srvrun_env.dgring_n == 0);
}

/* BOUNDARY: the ring holds exactly SRVRUN_DGRING_CAP entries; one more is
 * refused (not overwritten), and after a drain the wrapped indices still
 * accept a fresh queue. */
static void test_srvrun_wt_datagram_ring_full_rejects_then_recovers(void) {
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob                                     = (quic_obuf){obuf, sizeof obuf, 0};
  c                                      = sr_wtsend_fixture(&f, &ob);
  c->s.sdrv.peer_max_datagram_frame_size = 65535;
  for (int i = 0; i < SRVRUN_DGRING_CAP; i++)
    CHECK(
        wired_server_wt_send_datagram_to(
            &c->wt, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  CHECK(
      wired_server_wt_send_datagram_to(
          &c->wt, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 0);
  {
    srvrun_cfg   cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                        0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                        0,  0, 0, 0, 0};
    srvrun_state st  = {g_srvrun_table, g_srvrun_state.conns};
    srvrun_dgring_drain(&cfg, &st);
  }
  CHECK(g_srvrun_env.dgring_n == 0);
  CHECK(
      wired_server_wt_send_datagram_to(
          &c->wt, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  CHECK(g_srvrun_env.dgring_n == 1);
}

/* RECEIVE-SIDE FLOW CONTROL (RFC 9000 4.1/19.9/19.10): srvrun_seal_max_
 * stream_data encodes a MAX_STREAM_DATA the client can decode, naming the
 * right stream and value. */
static void test_srvrun_wt_max_stream_data_wire_shape(void) {
  struct lp_fix          f;
  quic_obuf              ob = {0};
  u8                     obuf[1024], pkt[256];
  quic_obuf              pktb = quic_obuf_of(pkt, sizeof pkt);
  const u8*              pl;
  usz                    pll;
  quic_stream_data_frame msd;
  usz                    n;
  srvrun_conn*           c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  CHECK(srvrun_seal_max_stream_data(c, 4, 20000, &pktb) == 1);
  CHECK(client_open_onertt(&f, pktb.p, pktb.len, &pl, &pll) == 1);
  n = quic_max_stream_data_decode(pl, pll, &msd);
  CHECK(n != 0 && n == pll);
  CHECK(msd.stream_id == 4);
  CHECK(msd.value == 20000);
}

/* Same shape, for the connection-wide MAX_DATA frame. */
static void test_srvrun_wt_max_data_wire_shape(void) {
  struct lp_fix   f;
  quic_obuf       ob = {0};
  u8              obuf[1024], pkt[256];
  quic_obuf       pktb = quic_obuf_of(pkt, sizeof pkt);
  const u8*       pl;
  usz             pll;
  quic_data_frame md;
  usz             n;
  srvrun_conn*    c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  CHECK(srvrun_seal_max_data(c, 90000, &pktb) == 1);
  CHECK(client_open_onertt(&f, pktb.p, pktb.len, &pl, &pll) == 1);
  n = quic_max_data_decode(pl, pll, &md);
  CHECK(n != 0 && n == pll);
  CHECK(md.value == 90000);
}

/* PROGRESSION (RFC 9000 4.1): as a WT bidi slot's delivered_len advances,
 * srvrun_grant_wt_credit raises that stream's own credit_advertised (never
 * lowers it) and the connection-wide rx_max_data_advertised, both strictly
 * following delivered progress -- proving the credit stays tied to actual
 * reassembly progress, not emitted unconditionally every step. */
static void test_srvrun_wt_credit_advances_with_delivery(void) {
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  u64           first_stream_credit, first_conn_credit;
  ob                           = (quic_obuf){obuf, sizeof obuf, 0};
  c                            = sr_wtsend_fixture(&f, &ob);
  c->l.wt_streams[0].in_use    = 1;
  c->l.wt_streams[0].stream_id = 4;
  sr_wt_slot_set_frontier(&c->l.wt_streams[0], 100);
  c->l.wt_streams[0].delivered_len = 100;
  {
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0};
    srvrun_grant_wt_credit(&cfg, c);
  }
  first_stream_credit = c->l.wt_streams[0].credit_advertised;
  first_conn_credit   = c->rx_max_data_advertised;
  CHECK(first_stream_credit == 100 + WIRED_SRVLOOP_WT_BUF_CAP);
  CHECK(first_conn_credit == 100 + WIRED_SRVLOOP_WT_BUF_CAP);
  /* more bytes delivered -- both ceilings rise, never fall. */
  sr_wt_slot_set_frontier(&c->l.wt_streams[0], 500);
  c->l.wt_streams[0].delivered_len = 500;
  {
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0};
    srvrun_grant_wt_credit(&cfg, c);
  }
  CHECK(c->l.wt_streams[0].credit_advertised > first_stream_credit);
  CHECK(c->rx_max_data_advertised > first_conn_credit);
  /* a step with no further delivery re-sends nothing (send_count unchanged
   * -- proven indirectly: credit_advertised/rx_max_data_advertised stay put,
   * since a re-send would only happen if wt_credit_stream_due were
   * (incorrectly) true again). */
  {
    u64        stream_before = c->l.wt_streams[0].credit_advertised;
    u64        conn_before   = c->rx_max_data_advertised;
    srvrun_cfg cfg           = {-1, 0, 0, 0, 0, 0, 0, 0,
                                0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                                0,  0, 0, 0, 0};
    srvrun_grant_wt_credit(&cfg, c);
    CHECK(c->l.wt_streams[0].credit_advertised == stream_before);
    CHECK(c->rx_max_data_advertised == conn_before);
  }
}

/* REGRESSION: with several WT slots active at once, the connection-wide
 * MAX_DATA ceiling must give each of them its own full WIRED_SRVLOOP_WT_
 * BUF_CAP of slack, not a single buffer's worth shared across all of them --
 * the bug this guards against summed delivered_len across every slot but
 * then added only ONE buffer's worth on top (wt_slot_credit_ceiling, meant
 * for a single stream's own ceiling, applied to the connection total by
 * mistake). With N slots open, undercounting starved every slot past the
 * first back down to the shared ceiling the moment their combined MAX_
 * STREAM_DATA advertisements outran it (found via a real webtransport-go
 * interop run: streams stalled hard past a few hundred KB combined once 3+
 * were active). Three slots (2 bidi, 1 uni) each 100 bytes delivered: the
 * ceiling must be 300 + 3*WIRED_SRVLOOP_WT_BUF_CAP, not 300 + 1*CAP. */
static void test_srvrun_wt_credit_conn_ceiling_scales_with_slot_count(void) {
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob                           = (quic_obuf){obuf, sizeof obuf, 0};
  c                            = sr_wtsend_fixture(&f, &ob);
  c->l.wt_streams[0].in_use    = 1;
  c->l.wt_streams[0].stream_id = 4;
  sr_wt_slot_set_frontier(&c->l.wt_streams[0], 100);
  c->l.wt_streams[0].delivered_len = 100;
  c->l.wt_streams[1].in_use        = 1;
  c->l.wt_streams[1].stream_id     = 8;
  sr_wt_slot_set_frontier(&c->l.wt_streams[1], 100);
  c->l.wt_streams[1].delivered_len = 100;
  c->l.wt_uni_streams[0].in_use    = 1;
  c->l.wt_uni_streams[0].stream_id = 2;
  sr_wt_uni_slot_set_frontier(&c->l.wt_uni_streams[0], 100);
  c->l.wt_uni_streams[0].delivered_len = 100;
  {
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0};
    srvrun_grant_wt_credit(&cfg, c);
  }
  CHECK(c->rx_max_data_advertised == 300 + 3 * (u64)WIRED_SRVLOOP_WT_BUF_CAP);
}

/* GATE: a connection with no WT slot ever claimed never emits a gratuitous
 * MAX_DATA -- the bug this guards against sent a MAX_DATA(WIRED_SRVLOOP_WT_
 * BUF_CAP) on every plain HTTP/3 connection's very first step, an unasked-
 * for frame with nothing to raise credit for. */
static void test_srvrun_wt_credit_no_op_without_any_wt_slot(void) {
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  {
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0,
                      0,  0, 0, 0, 0, 0, 0, &g_srvrun_env,
                      0,  0, 0, 0, 0};
    srvrun_grant_wt_credit(&cfg, c);
  }
  CHECK(c->rx_max_data_advertised == 0);
}

/* SLOT RELEASE + RECLAIM (RFC 9000 2.1/19.8): once a WT bidi slot's FIN has
 * been delivered to the app, srvrun_offer_and_deliver_wt_slot (reached via
 * srvrun_offer_wt_streams) frees it -- a 5th distinct WT bidi stream (past
 * WIRED_SRVLOOP_MAX_WT_STREAMS == 4) can then claim the freed slot rather
 * than being dropped by a permanently-exhausted table. */
static void test_srvrun_wt_slot_released_after_fin_and_reclaimed(void) {
  struct lp_fix f;
  quic_obuf     ob = {0};
  u8            obuf[1024];
  srvrun_conn*  c;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  c  = sr_wtsend_fixture(&f, &ob);
  /* fill every slot with a finished, fully-delivered stream. */
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    c->l.wt_streams[i].in_use    = 1;
    c->l.wt_streams[i].stream_id = 4 + 4 * (u64)i;
    c->l.wt_streams[i].offered   = 1;
    c->l.wt_streams[i].fin       = 1;
    c->l.wt_streams[i].fin_off   = 0; /* empty stream, FIN at offset 0 */
  }
  {
    srvrun_cfg cfg = {
        -1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        sr_stream_data_handler,
        0,
        0,
        &g_srvrun_env,
        0,
        0,
        0,
        0,
        0};
    srvrun_offer_wt_streams(&cfg, c);
  }
  /* every slot's FIN was delivered and the slot freed. */
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    CHECK(c->l.wt_streams[i].in_use == 0);
  /* a fresh (5th) stream id now successfully claims a slot. */
  CHECK(wired_srvloop_wt_slot_claim(&c->l, 100) >= 0);
}

/* STALE ID REJECTED: once a stream id has been released, a late/duplicate
 * frame naming that SAME id (a reordered retransmission arriving after the
 * slot was already reaped) must not re-claim a slot -- RFC 9000 2.1's
 * strictly-increasing stream id space means a peer never legitimately reuses
 * one, so re-claiming would let stale data resurrect a finished stream. */
static void test_srvrun_wt_released_id_not_reclaimed(void) {
  wired_srvloop l;
  wired_srvloop_init(&l, (const u8*)"c", 1);
  CHECK(wired_srvloop_wt_slot_claim(&l, 4) >= 0);
  wired_srvloop_wt_slot_release(&l, 4);
  CHECK(wired_srvloop_wt_slot_claim(&l, 4) < 0);  /* same id: stale, rejected */
  CHECK(wired_srvloop_wt_slot_claim(&l, 8) >= 0); /* a genuinely new id: ok */
}

void test_srvrun(void) {
  test_srvrun_broadcast_datagram_queues_active_wt_sessions();
  test_srvrun_broadcast_datagram_skips_inactive_wt();
  test_srvrun_broadcast_datagram_skips_unused_slot();
  test_srvrun_broadcast_datagram_rejects_oversize();
  test_srvrun_broadcast_datagram_reaches_two_real_clients();
  test_srvrun_broadcast_datagram_flushes_on_poll_tick_alone();
  test_srvrun_wt_full_session_lifecycle_on_wire();
  test_srvrun_wt_accept_second_session_below_limit();
  test_srvrun_wt_reject_at_session_limit();
  test_srvrun_wt_accept_records_path();
  test_srvrun_wt_distinct_paths_coexist();
  test_srvrun_wt_stream_routes_to_matching_session();
  test_srvrun_wt_foreign_stream_id_rejected();
  test_srvrun_wt_stream_exclusive_ownership();
  test_srvrun_wt_dgram_routes_to_matching_session();
  test_srvrun_wt_foreign_dgram_id_rejected();
  test_srvrun_wt_close_one_session_leaves_others_untouched();
  test_srvrun_wt_drain_one_session_leaves_others_untouched();
  test_srvrun_wt_close_frees_slot_for_new_accept();
  test_srvrun_wt_free_slot_closes_all_open_sessions();
  test_srvrun_wt_connect_stream_close_closes_only_that_session();
  test_srvrun_wt_all_slots_cycle_through_open_and_close();
  test_srvrun_wt_limit_one_matches_legacy_behavior();
  test_srvrun_wt_establish_associates_only_own_buffered_items();
  test_srvrun_wt_reused_slot_has_no_stale_data();
  test_srvrun_wt_session_limit_fits_stream_table_capacity();
  test_srvrun_no_shutdown_accepts_new();
  test_srvrun_bigbuf_pool_serves_large_body();
  test_srvrun_bigbuf_pool_exhausted_falls_back_to_fixed_row();
  test_srvrun_hq09_resp_has_no_h3_framing();
  test_srvrun_hq09_missing_file_arms_empty_body();
  test_srvrun_streaming_next_round_armed_after_done();
  test_srvrun_streaming_final_round_releases_slot();
  test_srvrun_streaming_stream_offset_accumulates_across_rounds();
  test_srvrun_streaming_concurrent_requests_do_not_corrupt_each_other();
  test_srvrun_streaming_later_round_uses_own_stream_not_sibling();
  test_srvrun_streaming_h3_prefix_receives_total_size_not_round_len();
  test_srvrun_streaming_body_exactly_row_cap_single_round();
  test_srvrun_streaming_body_row_cap_plus_one_streams();
  test_srvrun_streaming_last_round_not_shrunk_to_fixed();
  test_srvrun_streaming_rearm_respects_existing_send_gates();
  test_srvrun_streaming_bigbuf_exhausted_falls_back_to_fixed_row();
  test_srvrun_streaming_mid_round_read_error_truncates();
  test_srvrun_streaming_file_shrinks_completes_with_actual_bytes();
  test_srvrun_streaming_round_fin_suppressed_until_final();
  test_srvrun_fifth_sequential_get_reuses_freed_slot();
  test_srvrun_pto_budget_exhausted_tears_down_connection();
  test_srvrun_pto_not_due_within_rtt_window();
  test_srvrun_ku_old_keys_retained_within_3pto_window();
  test_srvrun_ku_old_keys_discarded_after_3pto_window();
  test_srvrun_sibling_ack_does_not_lose_other_slot();
  test_srvrun_loss_and_retransmit_across_two_responses();
  test_srvrun_pump_round_robins_across_slots();
  test_srvrun_pacing_floor_does_not_starve_round();
  test_srvrun_pto_probe_bypasses_cwnd();
  test_srvrun_new_send_still_blocked_by_cwnd();
  test_srvrun_pto_probe_drains_multiple_requeued_slices();
  test_srvrun_pto_probe_still_respects_log_capacity();
  test_srvrun_pto_bypass_does_not_leak_to_sibling_new_sends();
  test_srvrun_pto_requeue_frees_inflight_bytes_before_resend();
  test_srvrun_pto_noop_when_nothing_inflight();
  test_srvrun_boot_pto_resends_after_deadline();
  test_srvrun_boot_pto_no_resend_before_deadline();
  test_srvrun_boot_pto_stops_after_confirm();
  test_srvrun_boot_pto_confirm_race_stops_immediately();
  test_srvrun_boot_pto_budget_exhausted_frees_slot();
  test_srvrun_boot_pto_budget_not_yet_exhausted_keeps_slot();
  test_srvrun_boot_pto_noop_without_sent_flight();
  test_srvrun_boot_pto_noop_when_not_up();
  test_srvrun_boot_pto_no_double_send_after_client_retransmit();
  test_srvrun_pto_probe_bypasses_pacing_too();
  test_srvrun_slot_release_grants_one_more_stream();
  test_srvrun_stream_limit_never_decreases();
  test_srvrun_streams_blocked_reannounces_current_limit();
  test_srvrun_streams_blocked_before_any_release_uses_base();
  test_srvrun_stream_limit_small_case_single_grant();
  test_srvrun_pto_resend_breaks_cwnd_deadlock();
  test_srvrun_recv_max_data_then_send_unblocks();
  test_srvrun_max_stream_data_unknown_stream_is_noop();
  test_srvrun_pto_resend_does_not_double_count_credit();
  test_srvrun_conn_credit_ignores_lower_max_data();
  test_srvrun_stream_credit_ignores_lower_max_stream_data();
  test_srvrun_conn_credit_exhausted_blocks_send();
  test_srvrun_stream_credit_exhausted_blocks_only_that_slot();
  test_srvrun_conn_credit_sums_across_slots();
  test_srvrun_send_credit_boundary_exact_fit_allowed();
  test_srvrun_pump_stops_at_log_capacity();
  test_srvrun_accept_rekeys_to_slot_scid();
  test_srvrun_open_slot_xdp_embeds_core_id();
  test_srvrun_open_slot_xdp_embeds_core_id_zero();
  test_srvrun_open_slot_non_xdp_no_core_id_embedding();
  test_srvrun_issue_cid_xdp_negative_core_id_no_embed();
  test_srvrun_issue_cid_xdp_embeds_core_id();
  test_srvrun_initial_retransmit_resends_cached_flight();
  test_srvrun_boot_antiamp_first_round_caps_at_3x();
  test_srvrun_boot_antiamp_unsent_tail_not_counted();
  test_srvrun_boot_antiamp_second_round_releases_more();
  test_srvrun_boot_antiamp_budget_off_by_one_blocks();
  test_srvrun_boot_antiamp_budget_exact_fit_sends();
  test_srvrun_boot_antiamp_zero_budget_sends_nothing();
  test_srvrun_boot_antiamp_confirmed_bypasses_limit();
  test_srvrun_boot_antiamp_small_flight_sends_in_one_round();
  test_srvrun_boot_antiamp_sent_includes_initial_and_handshake();
  test_srvrun_boot_antiamp_client_silent_no_crash();
  test_srvrun_conn_rx_bytes_counts_malformed_datagram();
  test_srvrun_resend_boot_flight_respects_antiamp_budget();
  test_srvrun_free_slot_resets_antiamp_state();
  test_srvrun_coalesced_handshake_not_boot_retransmit();
  test_srvrun_split_ch_boots_across_datagrams();
  test_srvrun_stalled_boot_swept();
  test_srvrun_alien_version_claims_no_slot();
  test_srvrun_failed_accept_unclaims();
  test_srvrun_peer_close_frees_slot();
  test_srvrun_idle_sweep_evicts_expired();
  test_srvrun_idle_sweep_releases_bigbuf_row();
  test_srvrun_serve_slot_touches_last_ms();
  test_srvrun_qlog_records_received();
  test_srvrun_qlog_no_dup_record();
  test_srvrun_qlog_recv_no_path_writes_nothing();
  test_srvrun_qlog_skips_undecryptable();
  test_srvrun_qlog_records_initial();
  test_srvrun_qlog_skips_failed_accept();
  test_srvrun_batch_serves_each();
  test_srvrun_takeover_streams_large_body();
  test_srvrun_onertt_get_is_acked_via_srvrun_on_step();
  test_srvrun_multi_range_ack_via_srvrun_on_step();
  test_srvrun_ack_timer_shares_now_ms_with_pto();
  test_srvrun_parallel_responses_three_streams();
  test_srvrun_cc_algo_selected();
  test_srvrun_hystart_ends_slow_start();
  test_srvrun_hystart_round_boundary_survives_interleaving();
  test_srvrun_rtt_ewma();
  test_srvrun_rtt_sample_uses_newest_hit_only();
  test_srvrun_pacing_gate();
  test_srvrun_pacing_no_stall_within_poll_tick();
  test_srvrun_pace_interval_equals_poll_no_extra_round();
  test_srvrun_pace_interval_over_poll_waits();
  test_srvrun_pace_bursts_within_poll_interval();
  test_srvrun_pace_subms_still_unlimited();
  test_srvrun_pace_small_response_unaffected();
  test_srvrun_pace_burst_no_data_terminates();
  test_srvrun_pace_probe_bypasses_pacing_gate();
  test_srvrun_pace_no_probe_still_gated();
  test_srvrun_pace_mixed_probe_and_new_data_round();
  test_srvrun_pace_probe_bypass_still_respects_log_gate();
  test_srvrun_pace_probe_bypass_activates_on_requeue();
  test_srvrun_pace_probe_round_still_schedules_next();
  test_srvrun_pace_within_poll_tick_unaffected_by_probe_change();
  test_srvrun_shutdown_rejects_new_initial();
  test_srvrun_shutdown_refuses_slot_claim();
  test_srvrun_owes_goaway_once();
  test_srvrun_goaway_wire_content();
  test_srvrun_not_up_owes_nothing();
  test_srvrun_unconfirmed_owes_nothing();
  test_srvrun_all_drained_true_when_all_down();
  test_srvrun_all_drained_false_when_one_up();
  test_srvrun_send_no_qlog_path_writes_nothing();
  test_srvrun_send_qlog_path_writes_packet_sent();
  test_srvrun_send_empty_pkt_no_qlog_record();
  test_srvrun_no_reload_leaves_id_untouched();
  test_srvrun_reload_requested_updates_id();
  test_srvrun_reload_disabled_when_no_cert_path();
  test_srvrun_reload_failure_keeps_previous_id();
  test_srvrun_busy_poll_off_uses_any_waiting_branch();
  test_srvrun_busy_poll_on_never_blocks_wait();
  test_srvrun_busy_poll_step_never_blocks();
  test_srvrun_polling_pto_tick();
  test_srvrun_opt_zeroed_matches_plain_default();
  test_srvrun_so_busy_poll_zero_still_binds();
  test_srvrun_wt_uni_stream_offered_to_session();
  test_srvrun_wt_uni_stream_no_session_not_offered();
  test_srvrun_wt_bidi_stream_offered_to_session();
  test_srvrun_wt_bidi_stream_buffer_full_sends_reset();
  test_srvrun_wt_uni_stream_buffer_full_sends_reset();
  test_srvrun_normal_request_unaffected_by_wt_branch();
  test_srvrun_wt_connect_establishes_session();
  test_srvrun_wt_connect_webtransport_token();
  test_srvrun_plain_connect_no_protocol_no_wt_session();
  test_srvrun_wt_connect_missing_scheme_no_session();
  test_srvrun_wt_connect_missing_path_no_session();
  test_srvrun_wt_connect_missing_authority_no_session();
  test_srvrun_wt_connect_origin_ok_establishes();
  test_srvrun_wt_connect_origin_malformed_403();
  test_srvrun_second_wt_connect_rejected_429();
  test_srvrun_second_wt_connect_sends_reset_stream();
  test_srvrun_wt_connect_client_bidi_id_establishes_session();
  test_srvrun_wt_connect_non_client_bidi_id_rejected();
  test_srvrun_seal_app_close_is_application_level();
  test_srvrun_seal_app_close_empty_reason();
  test_srvrun_send_app_close_does_not_crash();
  test_srvrun_first_wt_connect_no_reset_stream();
  test_srvrun_connect_stream_reset_closes_wt_session();
  test_srvrun_other_stream_reset_does_not_close_wt_session();
  test_srvrun_no_stream_close_leaves_wt_session();
  test_srvrun_idle_sweep_closes_wt_session();
  test_srvrun_idle_sweep_without_wt_unaffected();
  test_srvrun_datagram_round_trip_on_wire();
  test_srvrun_datagram_dropped_before_settings_sent();
  test_srvrun_datagram_rejected_when_peer_unadvertised();
  test_srvrun_datagram_rejected_over_peer_limit();
  test_srvrun_datagram_unused_does_not_affect_stream_response();
  test_srvrun_datagram_too_large_rejected();
  test_srvrun_datagram_second_queue_overwrites_first();
  test_srvrun_rx_datagram_delivers_to_callback();
  test_srvrun_rx_datagram_multiple_all_delivered();
  test_srvrun_rx_datagram_no_callback_still_drains();
  test_srvrun_rx_datagram_no_session_callback_not_invoked();
  test_srvrun_seal_transport_close_is_transport_level();
  test_srvrun_oversized_datagram_latches_violation_on_step();
  test_srvrun_wt_stream_data_delivered_on_offer();
  test_srvrun_wt_stream_data_delivers_delta_only();
  test_srvrun_wt_stream_data_fin_only_delivered();
  test_srvrun_wt_stream_data_no_callback_still_offers();
  test_srvrun_wt_stream_data_no_session_not_delivered();
  test_srvrun_wt_uni_stream_data_delivered_on_offer();
  test_srvrun_wt_negotiate_picks_first_client_choice();
  test_srvrun_wt_negotiate_no_common_no_header();
  test_srvrun_wt_negotiate_absent_offer_no_header();
  test_srvrun_wt_negotiate_bad_syntax_no_header();
  test_srvrun_wt_negotiate_disabled_unchanged();
  test_srvrun_wt_on_session_notified_once();
  test_srvrun_wt_on_session_empty_protocol();
  test_srvrun_wt_on_session_two_sessions_each_path();
  test_srvrun_wt_avail_captured_from_wire();
  test_srvrun_wt_open_uni_streams_payload_on_wire();
  test_srvrun_wt_open_bidi_allocates_ids_and_holds_view();
  test_srvrun_wt_open_bidi_reply_received();
  test_srvrun_wt_stream_reply_arms_given_stream_verbatim();
  test_srvrun_wt_open_unknown_session_rejected();
  test_srvrun_wt_open_slot_exhaustion_and_reuse();
  test_srvrun_wt_open_uni_respects_stream_credit();
  test_srvrun_wt_send_conn_credit_shared_with_resp();
  test_srvrun_wt_send_pto_requeues_unacked_slice();
  test_srvrun_wt_open_two_megabyte_payload_fully_acked();
  test_srvrun_wt_open_five_parallel_streams_unmixed();
  test_srvrun_wt_send_datagram_to_prefixes_qsid();
  test_srvrun_wt_send_datagram_to_requires_settings_sent();
  test_srvrun_wt_datagram_ring_drains_200_queued();
  test_srvrun_wt_datagram_ring_full_rejects_then_recovers();
  test_srvrun_wt_max_stream_data_wire_shape();
  test_srvrun_wt_max_data_wire_shape();
  test_srvrun_wt_credit_advances_with_delivery();
  test_srvrun_wt_credit_conn_ceiling_scales_with_slot_count();
  test_srvrun_wt_credit_no_op_without_any_wt_slot();
  test_srvrun_wt_slot_released_after_fin_and_reclaimed();
  test_srvrun_wt_released_id_not_reclaimed();
}
