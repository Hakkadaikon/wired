#include "app/http3/server/srvrun/srvrun.h"

#include "app/http3/core/h3/frame.h"
#include "test.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"

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
    srvrun_cfg cfg = {-1, 0, 0, 0, 0,
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
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
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
  srvrun_cfg  cfg    = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
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
  srvrun_cfg  cfg    = {-1, 0, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0};
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
  srvrun_cfg  cfg = {-1, 0, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0};
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
  srvrun_cfg cfg = {-1, &id, 0, 0, 0, 0, srvrunt_cert_path, srvrunt_key_path,
                    0, 0};
  srvrun_test_set_reload(0);
  srvrun_reload_if_requested(&cfg);
  CHECK(id.pub == pub);
  CHECK(id.chain_count == 0);
}

/* RELOAD APPLIED: a pending reload decodes the PEM pair into id and clears
 * the flag (srvrun_reload_requested reads 0 afterward). */
static void test_srvrun_reload_requested_updates_id(void) {
  wired_srvboot_id id = {0};
  srvrun_cfg cfg = {-1, &id, 0, 0, 0, 0, srvrunt_cert_path, srvrunt_key_path,
                    0, 0};
  srvrunt_write(
      srvrunt_cert_path, srvrunt_cert_pem, sizeof(srvrunt_cert_pem) - 1);
  srvrunt_write(srvrunt_key_path, srvrunt_key_pem, sizeof(srvrunt_key_pem) - 1);
  srvrun_test_set_reload(1);
  srvrun_reload_if_requested(&cfg);
  CHECK(srvrun_reload_requested() == 0);
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
  srvrun_cfg cfg       = {-1, &id, 0, 0, 0, 0, 0, 0, 0, 0};
  srvrun_test_set_reload(1);
  srvrun_reload_if_requested(&cfg);
  CHECK(srvrun_reload_requested() == 0);
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
    srvrun_cfg cfg = {-1, &id, 0, 0, 0, 0, srvrunt_cert_path, srvrunt_key_path,
                      0, 0};
    srvrun_test_set_reload(1);
    srvrun_reload_if_requested(&cfg);
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
  id->priv             = priv;
  id->pub              = pub;
  id->cert_seed        = seed;
  id->scid             = g_sr_srv_scid;
  id->scid_len         = 6;
  id->random           = rnd;
  id->chain            = 0;
  id->chain_count      = 0;
  id->max_data                = 0;
  id->max_streams_bidi        = 0;
  id->max_datagram_frame_size = 0;
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, 0, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    srvrun_serve(&ctx, quic_mspan_of(dg, total));
  }
  CHECK(st.conns[0].up == 1);
  /* the Initial's DCID no longer routes anywhere... */
  CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, g_sr_odcid, 8) == -1);
  /* ...the slot's generated SCID does */
  CHECK(
      quic_conntable_find(
          table, QUIC_CONNTABLE_CAP, st.conns[0].scid, id.scid_len) == 0);
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, 0, 0, 0, 0, 0, 0};
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, 0, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 1000};
    quic_conntable_init(table, QUIC_CONNTABLE_CAP);
    st.conns[0].up       = 0;
    st.conns[0].boot.any = 0;
    srvrun_serve(&ctx, quic_mspan_of(dg1, n1));
    CHECK(st.conns[0].boot.any == 1);
    srvrun_sweep_idle(&st, 1000 + WIRED_SRVRUN_IDLE_MS);
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, 0, 0, 0, 0, 0, 0};
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, 0, 0, 0, 0, 0, 0};
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0};
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
  srvrun_sweep_idle(&st, 1000 + WIRED_SRVRUN_IDLE_MS);
  /* the expired slot is gone, the active one survives */
  CHECK(st.conns[0].up == 0);
  CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, k1, 4) == -1);
  CHECK(st.conns[1].up == 1);
  CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, k2, 4) == 1);
  /* the freed slot is claimable again */
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, k1, 4) == 0);
}

/* ACTIVITY REFRESH (RFC 9000 10.1): every datagram routed to a slot stamps
 * its last-activity time, so a served connection never counts as idle. */
static void test_srvrun_serve_slot_touches_last_ms(void) {
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  srvrun_state     st    = {table, g_srvrun_state.conns};
  quic_sockaddr_in peer  = {0};
  u8               sh[8] = {0x40, 1, 2, 3, 4, 5, 6, 7}; /* short header */
  srvrun_cfg       cfg   = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  srvrun_step_ctx  ctx   = {&cfg, &peer, &st, 12345};
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, qlog_path, 0, 0, 0, 0, 0};
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0};
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0};
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, srvrunt_qlog_path, 0, 0, 0, 0, 0};
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
    srvrun_cfg cfg = {-1, &id, 0, 0, 0, 0, 0, 0, 0, 0};
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
    quic_obuf*                  body_out,
    const char**                ct) {
  (void)hctx;
  (void)req;
  (void)ct;
  for (usz i = 0; i < 2500 && i < body_out->cap; i++)
    body_out->p[i] = (u8)(i & 0xff);
  body_out->len = 2500;
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
    srvrun_cfg      cfg = {cfd, &id, sr_body_handler, 0, 0, 0, 0, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &srv, &st, 0};
    srvrun_serve(&ctx, quic_mspan_of(spkt, slen));
  }
  /* 4 datagrams queued: the loop's ACK reply, then 3 response slices. */
  for (int d = 0; d < 4; d++) {
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, 0, 0, 0, 0, QUIC_CC_ALGO_CUBIC, 0};
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
  wired_sendsess_arm(&c->sess, g_srvrun_respstore[3], 16000, 100);
  {
    wired_sendq_slice sl;
    /* round 1: 8 packets sent at t=0, acked at t=40 (RTT 40) */
    for (u64 pn = 0; pn < 8; pn++) {
      CHECK(wired_sendsess_take(&c->sess, &sl) == 1);
      CHECK(wired_sendsess_sent(&c->sess, &sl, pn, 0) == 1);
    }
    c->l.tx_pn = 8; /* production: sending advanced the next pn */
    for (u64 pn = 0; pn < 8; pn++) srvrun_hystart_ack(c, pn, pn, 40);
    CHECK(c->cc.ssthresh == ~(u64)0); /* still slow start */
    /* round 2: RTT jumped to 60 >= 40 + eta(5): exit on the 8th sample */
    for (u64 pn = 8; pn < 16; pn++) {
      CHECK(wired_sendsess_take(&c->sess, &sl) == 1);
      CHECK(wired_sendsess_sent(&c->sess, &sl, pn, 100) == 1);
    }
    c->l.tx_pn = 16;
    for (u64 pn = 8; pn < 16; pn++) srvrun_hystart_ack(c, pn, pn, 160);
  }
  CHECK(c->cc.ssthresh == c->cc.cwnd); /* slow start ended */
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

/* PACING GATE: before the first RTT sample sends are unpaced; with an srtt,
 * a send scheduled in the future blocks the pump and the next-send time
 * advances by the pacing interval (1.25 * pkt * srtt / cwnd). */
static void test_srvrun_pacing_gate(void) {
  srvrun_conn     c   = {0};
  srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  srvrun_state    st  = {0, 0};
  srvrun_step_ctx ctx = {&cfg, 0, &st, 1000};
  quic_cc_init(&c.cc);                  /* cwnd 12000 */
  CHECK(srvrun_pace_ok(&ctx, &c) == 1); /* srtt 0: unpaced */
  c.srtt_ms      = 100;
  c.next_send_ms = 1010; /* future */
  CHECK(srvrun_pace_ok(&ctx, &c) == 0);
  c.next_send_ms = 1000; /* due now */
  CHECK(srvrun_pace_ok(&ctx, &c) == 1);
  srvrun_pace_next(&ctx, &c);
  /* 5 * 1200 * 100 / (4 * 12000) = 12ms */
  CHECK(c.next_send_ms == 1012);
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
  srvrun_state    st  = {0, 0};
  srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_conn     conns[QUIC_CONNTABLE_CAP] = {0};
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
  srvrun_state    st                        = {0, 0};
  srvrun_cfg      cfg                       = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  quic_conntable  table[QUIC_CONNTABLE_CAP];
  srvrun_conn     conns[QUIC_CONNTABLE_CAP] = {0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st              = (srvrun_state){table, conns};
  conns[0].up     = 1;
  conns[0].sess.active = 1; /* srvrun_any_waiting now says yes */
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
  srvrun_state     st                        = {0, 0};
  quic_conntable   table[QUIC_CONNTABLE_CAP];
  srvrun_conn      conns[QUIC_CONNTABLE_CAP] = {0};
  srvrun_cfg       cfg;
  CHECK(fd >= 0);
  wired_udp_addr(&sa, 4491, (const u8[4]){127, 0, 0, 1});
  CHECK(wired_udp_bind(fd, &sa) >= 0);
  cfg = (srvrun_cfg){fd, 0, 0, 0, 0, 0, 0, 0, 0, 1};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st          = (srvrun_state){table, conns};
  bufs[0].buf = quic_mspan_of(storage[0], sizeof storage[0]);
  bufs[1].buf = quic_mspan_of(storage[1], sizeof storage[1]);
  for (int i = 0; i < 50; i++) srvrun_step(&cfg, &st, bufs, 2);
  wired_udp_close(fd);
  /* reaching here (instead of hanging in the harness) is the assertion */
  CHECK(1);
}

/* WRAPPER EQUIVALENCE: wired_server_run_opt with a zeroed wired_srvrun_opt
 * behaves the same as wired_server_run at the point they actually differ --
 * the srvrun_cfg they build. Both must produce busy_poll=0, proving
 * wired_server_run's internal default_opt wrapper is wired correctly. */
static void test_srvrun_opt_zeroed_matches_plain_default(void) {
  wired_srvrun_opt opt = {0, 0};
  CHECK(opt.busy_poll == 0);
  CHECK(opt.so_busy_poll_us == 0);
}

/* BOUNDARY: so_busy_poll_us=0 -- srvrun_maybe_busy_poll's `> 0` guard skips
 * wired_udp_busy_poll_enable's setsockopt call entirely (opt-in, not
 * opt-out). No getsockopt wrapper exists in this libc-free SDK to observe
 * SO_BUSY_POLL's kernel-side value directly (out of scope, YAGNI;
 * wired_udp_busy_poll_enable's own success/failure is already covered at
 * the udp_gso_test.c layer) so this is proven at the call-boundary instead:
 * srvrun_listen(port, 0) still succeeds exactly as before this task (the
 * regression bar), i.e. the guard being skipped never blocks the bind. */
static void test_srvrun_so_busy_poll_zero_still_binds(void) {
  i64 fd = srvrun_listen(4492, 0);
  CHECK(fd >= 0);
  wired_udp_close(fd);
}

/* WEBTRANSPORT EXTENDED CONNECT (tasks/webtransport-plan.md Phase 7a):
 * srvrun_start_resp establishes a wired_wt_session for a well-formed
 * Extended CONNECT (:protocol=webtransport-h3) instead of calling the app
 * handler. Counts invocations to prove the handler path was skipped. */
static int  g_sr_wt_handler_calls = 0;
static int sr_wt_handler(
    void*                       hctx,
    const wired_h3reqdrive_req* req,
    quic_obuf*                  body_out,
    const char**                ct) {
  (void)hctx;
  (void)req;
  (void)ct;
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
  c->l.req.origin     = 0;
  c->l.req.origin_len = 0;
  c->l.req.body       = 0;
  c->l.req.body_len   = 0;
  c->l.req_stream_id  = stream_id;
  c->l.got_request    = 1;
}

/* REGRESSION: a normal GET (no :protocol) still goes through
 * srvrun_call_handler unchanged -- the app handler is invoked exactly once
 * and no WT session is created. */
static void test_srvrun_normal_request_unaffected_by_wt_branch(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 0, 0, 0);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(g_sr_wt_handler_calls == 1);
  CHECK(conns[0].wt_active == 0);
  CHECK(conns[0].sess.active == 1); /* the normal 200 was still armed */
}

/* An Extended CONNECT with :protocol=webtransport-h3 establishes a WT
 * session keyed by the CONNECT stream's own id and never calls the app
 * handler. */
static void test_srvrun_wt_connect_establishes_session(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(g_sr_wt_handler_calls == 0);
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].wt.connect_stream_id == 4);
  CHECK(conns[0].sess.active == 1); /* the bare 2xx was armed */
}

/* A plain CONNECT (no :protocol at all) is not Extended CONNECT: no WT
 * session is created, and it falls through to the existing app-handler path
 * (today's only defined behavior for a bare CONNECT -- there is no
 * CONNECT-specific handling yet). */
static void test_srvrun_plain_connect_no_protocol_no_wt_session(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 0, 4);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
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
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
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
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
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
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
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
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
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
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
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
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
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
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.origin     = sr_wt_origin_ok;
  conns[0].l.req.origin_len = sizeof sr_wt_origin_ok - 1;
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  CHECK(conns[0].sess.active == 1);
}

/* WT-B-005/007/008: a present but malformed (empty-value) Origin gets a
 * 403-equivalent response instead of establishing a session -- no
 * wired_wt_session is created, but a response is still armed (the 403). */
static void test_srvrun_wt_connect_origin_malformed_403(void) {
  struct lp_fix  f;
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  quic_obuf      ob;
  u8             obuf[1024];
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  conns[0].l.req.origin     = sr_wt_origin_ok; /* present, but... */
  conns[0].l.req.origin_len = 0;               /* ...empty: malformed */
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 0);
  CHECK(conns[0].wt.state != WIRED_WT_ESTABLISHED);
  CHECK(conns[0].sess.active == 1); /* the 403 was still armed */
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
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  quic_obuf      ob;
  u8             obuf[1024];
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  conns[0].sess.active = 0; /* pretend the first 2xx finished sending */
  sr_set_req(&conns[0], 1, 1, 8); /* second Extended CONNECT, different stream */
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(g_sr_wt_handler_calls == 0);
  CHECK(conns[0].sess.active == 1); /* the 429 was armed */
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED); /* original session intact */
  CHECK(conns[0].wt.connect_stream_id == 4);         /* still the first id */
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
  struct lp_fix           f;
  quic_conntable          table[QUIC_CONNTABLE_CAP];
  srvrun_conn             conns[QUIC_CONNTABLE_CAP] = {0};
  quic_obuf               ob;
  u8                      obuf[1024];
  u8                      pkt[256];
  quic_obuf               pktb = quic_obuf_of(pkt, sizeof pkt);
  const u8*               pl;
  usz                     pll;
  quic_reset_stream_frame rs;
  quic_stop_sending_frame ss;
  usz                     rn, sn;
  ob                    = (quic_obuf){obuf, sizeof obuf, 0};
  g_sr_wt_handler_calls = 0;
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  conns[0].sess.active = 0; /* pretend the first 2xx finished sending */
  sr_set_req(
      &conns[0], 1, 1, 8); /* second Extended CONNECT, different stream */
  {
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].sess.active == 1); /* the 429 was armed, same as before */
  CHECK(srvrun_seal_wt_busy_reset(&conns[0], 8, &pktb) == 1);
  CHECK(client_open_onertt(&f, pktb.p, pktb.len, &pl, &pll) == 1);
  rn = quic_reset_stream_decode(pl, pll, &rs);
  CHECK(rn != 0);
  CHECK(rs.stream_id == 8);
  CHECK(rs.error_code == QUIC_H3_REQUEST_REJECTED);
  sn = quic_stop_sending_decode(pl + rn, pll - rn, &ss);
  CHECK(sn != 0);
  CHECK(ss.stream_id == 8);
  CHECK(ss.error_code == QUIC_H3_REQUEST_REJECTED);
  CHECK(rn + sn == pll); /* nothing else in the packet */
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
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
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
    srvrun_cfg      cfg = {-1, 0, sr_wt_handler, 0, 0, 0, 0, 0, 0, 0};
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
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  quic_obuf      ob;
  u8             obuf[1024];
  struct lp_fix  f;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  sr_make_confirmed_conn(&conns[0], &f, &ob);
  sr_set_req(&conns[0], 1, 1, 4);
  {
    srvrun_cfg      cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    srvrun_state    st  = {table, conns};
    srvrun_step_ctx ctx = {&cfg, 0, &st, 0};
    srvrun_start_resp(&ctx, 0);
  }
  CHECK(conns[0].wt_active == 1);
  CHECK(conns[0].wt.state == WIRED_WT_ESTABLISHED);
  conns[0].last_ms = 1000;
  {
    srvrun_state st = {table, conns};
    srvrun_sweep_idle(&st, 1000 + WIRED_SRVRUN_IDLE_MS);
  }
  CHECK(conns[0].wt_active == 0);
  CHECK(conns[0].wt.state == WIRED_WT_CLOSED);
  CHECK(conns[0].up == 0);
}

/* REGRESSION: a connection with no active WT session (wt_active == 0) tears
 * down exactly as before -- srvrun_free_slot is the most commonly hit
 * teardown path, so a crash or behavior change here would be severe. */
static void test_srvrun_idle_sweep_without_wt_unaffected(void) {
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn    conns[QUIC_CONNTABLE_CAP] = {0};
  srvrun_state   st                        = {table, conns};
  u8             k[4]                      = {9, 9, 9, 9};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  conns[0].up        = 1;
  conns[0].last_ms   = 1000;
  conns[0].wt_active = 0;
  CHECK(quic_conntable_insert(table, QUIC_CONNTABLE_CAP, k, 4) == 0);
  srvrun_sweep_idle(&st, 1000 + WIRED_SRVRUN_IDLE_MS);
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
  struct lp_fix f;
  srvrun_conn   c;
  quic_obuf     ob;
  u8            obuf[1600];
  const u8*     pl;
  usz           pll;
  quic_datagram_frame df;
  ob = (quic_obuf){obuf, sizeof obuf, 0};
  sr_make_confirmed_conn(&c, &f, &ob);
  c.s.sdrv.peer_max_datagram_frame_size = 65535;
  CHECK(srvrun_queue_datagram(&c, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  CHECK(c.dg_pending == 1);
  {
    quic_obuf  out = {obuf, sizeof obuf, 0};
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CHECK(srvrun_send_pending_datagram(&cfg, &c, &out) == 1);
    CHECK(client_open_onertt(&f, out.p, out.len, &pl, &pll) == 1);
  }
  CHECK(c.dg_pending == 0); /* drained */
  CHECK(quic_datagram_decode(pl, pll, &df) == pll);
  CHECK(df.length == sizeof sr_dg_payload);
  for (usz i = 0; i < sizeof sr_dg_payload; i++)
    CHECK(df.data[i] == sr_dg_payload[i]);
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
  CHECK(srvrun_queue_datagram(&c, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  {
    quic_obuf  out = {obuf, sizeof obuf, 0};
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
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
  c.s.sdrv.peer_max_datagram_frame_size = 3; /* smaller than the encoded frame */
  CHECK(srvrun_queue_datagram(&c, quic_span_of(sr_dg_payload, sizeof sr_dg_payload)) == 1);
  {
    quic_obuf  out = {obuf, sizeof obuf, 0};
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
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
  srvrun_conn c = {0};
  CHECK(srvrun_queue_datagram(&c, quic_span_of(sr_dg_first, sizeof sr_dg_first)) == 1);
  CHECK(srvrun_queue_datagram(&c, quic_span_of(sr_dg_second, sizeof sr_dg_second)) == 1);
  CHECK(c.dg_pending == 1);
  CHECK(c.dg_pending_len == sizeof sr_dg_second);
  for (usz i = 0; i < sizeof sr_dg_second; i++)
    CHECK(c.dg_pending_buf[i] == sr_dg_second[i]);
}

void test_srvrun(void) {
  test_srvrun_no_shutdown_accepts_new();
  test_srvrun_accept_rekeys_to_slot_scid();
  test_srvrun_split_ch_boots_across_datagrams();
  test_srvrun_stalled_boot_swept();
  test_srvrun_alien_version_claims_no_slot();
  test_srvrun_failed_accept_unclaims();
  test_srvrun_peer_close_frees_slot();
  test_srvrun_idle_sweep_evicts_expired();
  test_srvrun_serve_slot_touches_last_ms();
  test_srvrun_qlog_records_received();
  test_srvrun_qlog_no_dup_record();
  test_srvrun_qlog_recv_no_path_writes_nothing();
  test_srvrun_qlog_skips_undecryptable();
  test_srvrun_qlog_records_initial();
  test_srvrun_qlog_skips_failed_accept();
  test_srvrun_batch_serves_each();
  test_srvrun_takeover_streams_large_body();
  test_srvrun_cc_algo_selected();
  test_srvrun_hystart_ends_slow_start();
  test_srvrun_rtt_ewma();
  test_srvrun_pacing_gate();
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
  test_srvrun_opt_zeroed_matches_plain_default();
  test_srvrun_so_busy_poll_zero_still_binds();
  test_srvrun_normal_request_unaffected_by_wt_branch();
  test_srvrun_wt_connect_establishes_session();
  test_srvrun_plain_connect_no_protocol_no_wt_session();
  test_srvrun_wt_connect_missing_scheme_no_session();
  test_srvrun_wt_connect_missing_path_no_session();
  test_srvrun_wt_connect_missing_authority_no_session();
  test_srvrun_wt_connect_origin_ok_establishes();
  test_srvrun_wt_connect_origin_malformed_403();
  test_srvrun_second_wt_connect_rejected_429();
  test_srvrun_second_wt_connect_sends_reset_stream();
  test_srvrun_first_wt_connect_no_reset_stream();
  test_srvrun_idle_sweep_closes_wt_session();
  test_srvrun_idle_sweep_without_wt_unaffected();
  test_srvrun_datagram_round_trip_on_wire();
  test_srvrun_datagram_rejected_when_peer_unadvertised();
  test_srvrun_datagram_rejected_over_peer_limit();
  test_srvrun_datagram_unused_does_not_affect_stream_response();
  test_srvrun_datagram_too_large_rejected();
  test_srvrun_datagram_second_queue_overwrites_first();
}
