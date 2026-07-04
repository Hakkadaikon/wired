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
    srvrun_conn* c, struct lp_fix* f, quic_obuf* ob) {
  lp_confirm(f, ob);
  *c = (srvrun_conn){f->s, f->l, 1, {0}, {0}, 0, 0};
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
                      0,  0, 0}; /* fd unused: srvrun_send
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
    srvrun_cfg cfg = {-1, 0, 0, 0, 0, 0, 0, 0};
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

/* No qlog path set (the default): srvrun_send writes nothing to any qlog
 * file. */
static void test_srvrun_send_no_qlog_path_writes_nothing(void) {
  u8          buf[8] = {1, 2, 3, 4};
  srvrun_conn c      = {0};
  srvrun_cfg  cfg    = {-1, 0, 0, 0, 0, 0, 0, 0};
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
  srvrun_cfg  cfg    = {-1, 0, 0, 0, srvrunt_qlog_path, 0, 0, 0};
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
  srvrun_cfg  cfg = {-1, 0, 0, 0, srvrunt_qlog_path, 0, 0, 0};
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
  srvrun_cfg cfg = {-1, &id, 0, 0, 0, 0, srvrunt_cert_path, srvrunt_key_path};
  srvrun_test_set_reload(0);
  srvrun_reload_if_requested(&cfg);
  CHECK(id.pub == pub);
  CHECK(id.chain_count == 0);
}

/* RELOAD APPLIED: a pending reload decodes the PEM pair into id and clears
 * the flag (srvrun_reload_requested reads 0 afterward). */
static void test_srvrun_reload_requested_updates_id(void) {
  wired_srvboot_id id = {0};
  srvrun_cfg cfg = {-1, &id, 0, 0, 0, 0, srvrunt_cert_path, srvrunt_key_path};
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
  srvrun_cfg cfg       = {-1, &id, 0, 0, 0, 0, 0, 0};
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
    srvrun_cfg cfg = {-1, &id, 0, 0, 0, 0, srvrunt_cert_path, srvrunt_key_path};
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
  id->priv        = priv;
  id->pub         = pub;
  id->cert_seed   = seed;
  id->scid        = g_sr_srv_scid;
  id->scid_len    = 6;
  id->random      = rnd;
  id->chain       = 0;
  id->chain_count = 0;
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, 0, 0, 0, 0};
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, 0, 0, 0, 0};
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
    srvrun_cfg      cfg = {-1, &id, 0, 0, srvrunt_qlog_path, 0, 0, 0};
    srvrun_step_ctx ctx = {&cfg, &peer, &st, 0};
    srvrun_serve(&ctx, quic_mspan_of(spkt, slen));
    /* slot freed: up cleared, DCID no longer routes */
    CHECK(st.conns[0].up == 0);
    CHECK(quic_conntable_find(table, QUIC_CONNTABLE_CAP, g_cli_scid, 6) == -1);
    /* no reply was sent for the close (draining sends nothing) */
    {
      u8  out[64] = {0};
      ssz n = wired_fio_read(srvrunt_qlog_path, quic_mspan_of(out, sizeof out));
      CHECK(n < 0);
    }
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
  srvrun_cfg       cfg   = {-1, 0, 0, 0, 0, 0, 0, 0};
  srvrun_step_ctx  ctx   = {&cfg, &peer, &st, 12345};
  quic_conntable_init(table, QUIC_CONNTABLE_CAP);
  st.conns[2].up      = 0;
  st.conns[2].last_ms = 0;
  srvrun_serve_slot(&ctx, 2, quic_mspan_of(sh, sizeof sh));
  CHECK(st.conns[2].last_ms == 12345);
}

void test_srvrun(void) {
  test_srvrun_no_shutdown_accepts_new();
  test_srvrun_accept_rekeys_to_slot_scid();
  test_srvrun_failed_accept_unclaims();
  test_srvrun_peer_close_frees_slot();
  test_srvrun_idle_sweep_evicts_expired();
  test_srvrun_serve_slot_touches_last_ms();
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
}
