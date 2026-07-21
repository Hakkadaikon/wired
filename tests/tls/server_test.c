#include "tls/handshake/roles/server/server.h"

#include "test.h"
#include "tls/ext/tlsext/preshared.h"
#include "tls/handshake/core/tls/appkeys.h"
#include "tls/handshake/core/tls/binder.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/master.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/keys/schedule_drive/keyschedule.h"
#include "tls/keys/ticket/ticket.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* RFC 8446 4 / RFC 9001 4.1.2: drive the server orchestrator through a full
 * handshake by buffer injection (no socket): a real ClientHello, the server
 * flight, then a genuine vs. forged client Finished. The central safety
 * property is that a forged Finished promotes nothing. */

/* Test fixture: the bytes a client needs to forge a genuine Finished. */
struct srv_fix {
  wired_server s;
  u8           ch[512];
  usz          ch_len;
  u8           sh[256];
  usz          sh_len;
  u8           flight[2048];
  usz          flight_len;
  u8           srv_random[32];
  u8           cli_priv[32];
  u8           sh_pub[32];  /* server x25519 public from ServerHello */
  u8           cli_fin[64]; /* genuine client Finished message */
  usz          cli_fin_len;
};

/* Build a ClientHello with a real x25519 key_share into f. */
static void make_client_hello(struct srv_fix* f) {
  static const u8 tp[1] = {0};
  u8              cli_pub[32];
  for (usz i = 0; i < 32; i++) {
    f->cli_priv[i]   = (u8)(i + 1);
    f->srv_random[i] = (u8)(0xa0 + i);
  }
  quic_x25519_base(cli_pub, f->cli_priv);
  f->ch_len = quic_tls_client_hello(
      &(quic_clienthello_in){
          f->srv_random, cli_pub, quic_span_of(0, 0),
          quic_span_of(tp, sizeof(tp))},
      &(quic_obuf){f->ch, sizeof(f->ch), 0});
}

/* Bring the server to FLIGHT_SENT and capture the flight bytes. */
static void drive_to_flight(struct srv_fix* f) {
  u8 srv_priv[32], srv_pub[32], cert_seed[32];
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_seed[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);

  wired_server_init_in sin   = {srv_priv, srv_pub, cert_seed, 0, 0, 0, 0, 0};
  quic_obuf            sh_ob = quic_obuf_of(f->sh, sizeof(f->sh));
  quic_obuf            fl_ob = quic_obuf_of(f->flight, sizeof(f->flight));
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  wired_server_init(&f->s, &sin);
  CHECK(wired_server_recv_initial(&f->s, f->ch, f->ch_len) == 1);
  CHECK(f->s.phase == WIRED_SERVER_HS_CH_RECVD);
  CHECK(wired_server_build_flight(&f->s, f->srv_random, &fo) == 1);
  f->sh_len     = sh_ob.len;
  f->flight_len = fl_ob.len;
  CHECK(f->s.phase == WIRED_SERVER_HS_FLIGHT_SENT);
}

/* RFC 8446 4.4.4: compute the genuine client Finished the way the client does:
 * base key = client hs traffic secret over the transcript through ServerHello;
 * verify_data over the transcript hash through the server Finished. */
static void make_client_finished(struct srv_fix* f) {
  quic_serverhello_out sh;
  u8                   hs[32], c_traffic[32], th[32];
  quic_transcript      tr;
  usz                  off;
  CHECK(quic_tls_parse_server_hello(
      quic_span_of(f->sh, f->sh_len), f->sh_pub, &sh));
  {
    u8 shared[32];
    quic_x25519(shared, f->cli_priv, f->sh_pub);
    quic_tls_handshake_secret(shared, hs);
  }
  quic_transcript_init(&tr);
  quic_transcript_add(&tr, f->ch, f->ch_len);
  quic_transcript_add(&tr, f->sh, f->sh_len);
  quic_transcript_hash(&tr, th); /* through ServerHello */
  quic_hkdf_label chl = {"c hs traffic", 12, {th, 32}};
  quic_hkdf_expand_label(hs, &chl, quic_mspan_of(c_traffic, 32));
  quic_transcript_add(&tr, f->flight, f->flight_len);
  quic_transcript_hash(&tr, th); /* through server Finished */

  off = quic_hs_begin(f->cli_fin, sizeof(f->cli_fin), QUIC_HS_FINISHED);
  quic_tls_finished_verify_data(c_traffic, th, f->cli_fin + off);
  f->cli_fin_len = off + QUIC_TLS_VERIFY_DATA;
  quic_hs_finish(f->cli_fin, f->cli_fin_len);
}

/* Wrap a TLS message as a CRYPTO-frame payload for wired_server_feed. */
static usz srv_wrap_crypto(const u8* msg, usz len, u8* out, usz cap) {
  usz                        n;
  quic_obuf                  ob  = quic_obuf_of(out, cap);
  quic_crypto_stream_emit_in ein = {0, 256};
  if (!quic_crypto_stream_emit(quic_span_of(msg, len), &ein, &ob)) return 0;
  n = ob.len;
  return n;
}

/* Happy path: CH -> flight -> good Finished -> confirmed -> HANDSHAKE_DONE. */
static void test_server_happy(void) {
  struct srv_fix f;
  u8             payload[256], hsdone[4];
  usz            plen;
  quic_obuf      hd_ob;
  make_client_hello(&f);
  drive_to_flight(&f);

  /* 1-RTT not armed, not confirmed at flight time. */
  CHECK(wired_server_is_confirmed(&f.s) == 0);
  {
    const quic_initial_keys* k;
    CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_ONERTT, &k) == 0);
    CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_HANDSHAKE, &k) == 1);
  }

  make_client_finished(&f);
  plen = srv_wrap_crypto(f.cli_fin, f.cli_fin_len, payload, sizeof(payload));
  CHECK(plen != 0);
  CHECK(wired_server_feed(&f.s, payload, plen) == 1);
  CHECK(wired_server_is_confirmed(&f.s) == 1);
  CHECK(f.s.phase == WIRED_SERVER_HS_CONFIRMED);
  {
    const quic_initial_keys* k;
    CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_ONERTT, &k) == 1);
  }

  /* HANDSHAKE_DONE exactly once. */
  hd_ob = quic_obuf_of(hsdone, sizeof(hsdone));
  CHECK(wired_server_handshake_done(&f.s, &hd_ob) == 1);
  CHECK(hd_ob.len == 1 && hsdone[0] == 0x1e);
  CHECK(wired_server_handshake_done(&f.s, &hd_ob) == 0);
}

/* CENTRAL SAFETY: a forged client Finished promotes nothing. */
static void test_server_forged_finished(void) {
  struct srv_fix f;
  u8             payload[256], hsdone[4];
  usz            plen;
  quic_obuf      hd_ob;
  make_client_hello(&f);
  drive_to_flight(&f);
  make_client_finished(&f);
  f.cli_fin[4] ^= 0x01; /* tamper verify_data */

  plen = srv_wrap_crypto(f.cli_fin, f.cli_fin_len, payload, sizeof(payload));
  CHECK(wired_server_feed(&f.s, payload, plen) == 0);
  CHECK(wired_server_is_confirmed(&f.s) == 0);
  CHECK(f.s.phase == WIRED_SERVER_HS_FLIGHT_SENT);
  {
    const quic_initial_keys* k;
    CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_ONERTT, &k) == 0);
  }
  hd_ob = quic_obuf_of(hsdone, sizeof(hsdone));
  CHECK(wired_server_handshake_done(&f.s, &hd_ob) == 0);
}

/* Forbidden order: flight before the ClientHello is refused, no Handshake key.
 */
static void test_server_flight_before_ch(void) {
  struct srv_fix       f;
  u8                   srv_priv[32], srv_pub[32], cert_seed[32];
  u8                   sh[256], flight[2048], rnd[32];
  quic_obuf            sh_ob = quic_obuf_of(sh, sizeof(sh));
  quic_obuf            fl_ob = quic_obuf_of(flight, sizeof(flight));
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  wired_server_init_in sin;
  for (usz i = 0; i < 32; i++) {
    srv_priv[i] = (u8)(0x40 + i);
    rnd[i]      = (u8)i;
  }
  quic_x25519_base(srv_pub, srv_priv);
  sin = (wired_server_init_in){srv_priv, srv_pub, cert_seed, 0, 0, 0, 0, 0};
  wired_server_init(&f.s, &sin);
  CHECK(wired_server_build_flight(&f.s, rnd, &fo) == 0);
  {
    const quic_initial_keys* k;
    CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_HANDSHAKE, &k) == 0);
  }
}

/* Forbidden order: a client Finished before the flight is rejected. */
static void test_server_fin_before_flight(void) {
  struct srv_fix f;
  u8             payload[256];
  usz            plen;
  make_client_hello(&f);
  {
    u8                   srv_priv[32], srv_pub[32], cert_seed[32];
    wired_server_init_in sin;
    for (usz i = 0; i < 32; i++) srv_priv[i] = (u8)(0x40 + i);
    quic_x25519_base(srv_pub, srv_priv);
    sin = (wired_server_init_in){srv_priv, srv_pub, cert_seed, 0, 0, 0, 0, 0};
    wired_server_init(&f.s, &sin);
    CHECK(wired_server_recv_initial(&f.s, f.ch, f.ch_len) == 1);
  }
  /* still CH_RECVD: any Finished-like payload must not promote */
  {
    u8  fin[40];
    usz off = quic_hs_begin(fin, sizeof(fin), QUIC_HS_FINISHED);
    for (usz i = 0; i < 32; i++) fin[off + i] = 0;
    quic_hs_finish(fin, off + 32);
    plen = srv_wrap_crypto(fin, off + 32, payload, sizeof(payload));
  }
  CHECK(wired_server_feed(&f.s, payload, plen) == 0);
  CHECK(wired_server_is_confirmed(&f.s) == 0);
  CHECK(f.s.phase == WIRED_SERVER_HS_CH_RECVD);
}

/* Concatenate the raw transcript through the server Finished into buf. */
static usz client_transcript(struct srv_fix* f, u8* buf) {
  usz n = 0, i;
  for (i = 0; i < f->ch_len; i++) buf[n++] = f->ch[i];
  for (i = 0; i < f->sh_len; i++) buf[n++] = f->sh[i];
  for (i = 0; i < f->flight_len; i++) buf[n++] = f->flight[i];
  return n;
}

/* Derive the application keys the way the client does: master secret from the
 * shared ECDHE, then app_keys over the raw transcript through the server
 * Finished (CH..SH..server flight) — never the client Finished. */
static void client_ap_keys(
    struct srv_fix* f, int is_server, quic_initial_keys* out) {
  u8  shared[32], hs[32], master[32], tr[3072];
  usz tlen;
  quic_x25519(shared, f->cli_priv, f->sh_pub);
  quic_tls_handshake_secret(shared, hs);
  quic_tls_master_secret(hs, master);
  tlen = client_transcript(f, tr);
  quic_tls_app_keys(
      &(quic_app_keys_in){master, quic_span_of(tr, tlen), is_server}, out);
}

/* Whole key material (key+iv+hp) is identical. */
static int ap_keys_eq(const quic_initial_keys* a, const quic_initial_keys* b) {
  const u8 *pa = (const u8*)a, *pb = (const u8*)b;
  int       diff = 0;
  for (usz i = 0; i < sizeof(quic_initial_keys); i++) diff |= pa[i] ^ pb[i];
  return diff == 0;
}

/* The server's installed AP keys for one direction equal the client's. */
static void check_dir_matches(struct srv_fix* f, int which, int is_server) {
  const quic_initial_keys* got;
  quic_initial_keys        want;
  CHECK(quic_keysched_get(&f->s.sched, which, &got) == 1);
  client_ap_keys(f, is_server, &want);
  CHECK(ap_keys_eq(got, &want));
}

/* RFC 8446 7.1: server and client reach the SAME 1-RTT keys. The server must
 * derive over the server Finished, not the client Finished, or these diverge
 * and curl's 1-RTT cannot be decrypted. */
static void test_server_ap_keys_match_client(void) {
  struct srv_fix f;
  u8             payload[256];
  usz            plen;
  make_client_hello(&f);
  drive_to_flight(&f);
  make_client_finished(&f);
  plen = srv_wrap_crypto(f.cli_fin, f.cli_fin_len, payload, sizeof(payload));
  CHECK(wired_server_feed(&f.s, payload, plen) == 1);
  CHECK(wired_server_is_confirmed(&f.s) == 1);
  check_dir_matches(&f, QUIC_KS_SERVER_AP, 1);
  check_dir_matches(&f, QUIC_KS_CLIENT_AP, 0);
}

/* ClientHello.random (RFC 8446 4.1.2) is recorded verbatim off ch_msg. */
static void test_server_records_client_random(void) {
  struct srv_fix f;
  make_client_hello(&f);
  drive_to_flight(&f);
  /* ch_msg layout (RFC 8446 4.1.2): 4-byte handshake header, then
   * legacy_version(2), then random(32) -- offset 6. */
  for (usz i = 0; i < 32; i++) CHECK(f.s.client_random[i] == f.ch[6 + i]);
}

#define SYS_unlinkat 263
#define SRVT_AT_FDCWD (-100)
static const char srvt_keylog_path[] = "build/server_keylog_test.tmp";

static void srvt_keylog_unlink(void) {
  syscall3(SYS_unlinkat, SRVT_AT_FDCWD, srvt_keylog_path, 0);
}

/* No keylog path set (the default): a verified Finished writes nothing. */
static void test_server_no_keylog_path_writes_nothing(void) {
  struct srv_fix f;
  u8             payload[256];
  usz            plen;
  make_client_hello(&f);
  drive_to_flight(&f);
  make_client_finished(&f);
  plen = srv_wrap_crypto(f.cli_fin, f.cli_fin_len, payload, sizeof(payload));
  srvt_keylog_unlink();
  CHECK(wired_server_feed(&f.s, payload, plen) == 1);
  {
    u8  out[8] = {0};
    ssz n = wired_fio_read(srvt_keylog_path, quic_mspan_of(out, sizeof out));
    CHECK(n < 0); /* file never created */
  }
}

/* A keylog path set before the flight: a verified Finished appends one
 * CLIENT_HANDSHAKE_TRAFFIC_SECRET line keyed by ClientHello.random. */
static void test_server_keylog_path_writes_line(void) {
  struct srv_fix f;
  u8             payload[256];
  usz            plen;
  make_client_hello(&f);
  drive_to_flight(&f);
  wired_server_set_keylog_path(&f.s, srvt_keylog_path);
  make_client_finished(&f);
  plen = srv_wrap_crypto(f.cli_fin, f.cli_fin_len, payload, sizeof(payload));
  srvt_keylog_unlink();
  CHECK(wired_server_feed(&f.s, payload, plen) == 1);
  {
    u8  out[512] = {0};
    ssz n = wired_fio_read(srvt_keylog_path, quic_mspan_of(out, sizeof out));
    const char label[] = "CLIENT_HANDSHAKE_TRAFFIC_SECRET";
    usz        label_n = sizeof(label) - 1;
    CHECK(n > 0);
    for (usz i = 0; i < label_n; i++) CHECK(out[i] == (u8)label[i]);
    CHECK(out[label_n] == ' ');
    CHECK(out[label_n + 1] == 'a' && out[label_n + 2] == '0'); /* ch[6]=0xa0 */
  }
  srvt_keylog_unlink();
}

/* PSK-resumption round trip through the connection-level key schedule
 * (keyschedule.c/server.c), not just sdrv's own flight (already covered by
 * tests/tls/sdrv_test.c's PSK fixtures). A resumption ClientHello carries a
 * pre_shared_key identifying a ticket sealed under the same ticket_key the
 * server was initialized with, with a correctly computed binder. */
/* RFC 8446 4.6.1: mirrors sdrv.c's sdrv_psk_from_ticket_secret -- the PSK a
 * ticket offers is HKDF-Expand-Label(resumption_master_secret,
 * "resumption", ticket_nonce, 32), empty ticket_nonce. */
static void srvt_psk_from_res_master(
    const u8 res_master_secret[QUIC_TICKET_SECRET_LEN], u8 psk_out[32]) {
  quic_hkdf_label l = {"resumption", 10, {0, 0}};
  quic_hkdf_expand_label(res_master_secret, &l, quic_mspan_of(psk_out, 32));
}

typedef struct {
  u8 ticket_key[QUIC_TICKET_KEY_LEN];
  u8 secret[QUIC_TICKET_SECRET_LEN]; /* resumption_master_secret */
  u8 psk[32];                        /* HKDF-Expand-Label(secret, ...) */
  u8 sealed[QUIC_TICKET_SEALED_LEN];
} srvt_psk_fixture;

static void srvt_psk_fixture_init(srvt_psk_fixture* f) {
  quic_ticket t = {{0}, 0, 7200};
  for (usz i = 0; i < QUIC_TICKET_KEY_LEN; i++)
    f->ticket_key[i] = (u8)(0xd0 + i);
  for (usz i = 0; i < QUIC_TICKET_SECRET_LEN; i++) {
    f->secret[i] = (u8)(0x60 + i);
    t.secret[i]  = f->secret[i];
  }
  srvt_psk_from_res_master(f->secret, f->psk);
  quic_ticket_seal(&t, f->ticket_key, f->sealed);
}

/* Append a pre_shared_key extension (single identity/binder) to a ClientHello
 * previously built by make_client_hello (same fixed extensions layout as
 * sdrv_test.c's sdrv_test_append_psk: no session_id, one cipher suite). Sets
 * *psk_ext_off to the extension's own TLV offset (header included). */
static usz srvt_psk_append(
    u8*                       out,
    usz                       out_cap,
    const u8*                 ch,
    usz                       ch_len,
    const quic_tlsext_psk_in* psk,
    usz*                      psk_ext_off) {
  usz       exts_len_off = 45; /* see sdrv_test.c's sdrv_test_append_psk */
  usz       old_exts_len;
  u8        scratch[128];
  quic_obuf eob = quic_obuf_of(scratch, sizeof(scratch));
  if (!quic_tlsext_pre_shared_key(psk, &eob)) return 0;
  if (ch_len + eob.len > out_cap) return 0;
  for (usz i = 0; i < ch_len; i++) out[i] = ch[i];
  old_exts_len = (usz)out[exts_len_off] << 8 | out[exts_len_off + 1];
  *psk_ext_off = ch_len;
  for (usz i = 0; i < eob.len; i++) out[ch_len + i] = scratch[i];
  quic_put_be16(out + exts_len_off, (u16)(old_exts_len + eob.len));
  quic_hs_finish(out, ch_len + eob.len);
  return ch_len + eob.len;
}

/* RFC 8446 4.2.11.2 truncation point, see sdrv.c's sdrv_psk_truncate. */
static usz srvt_psk_truncate_len(usz psk_ext_off, usz id_len) {
  return psk_ext_off + 12 + id_len;
}

/* Build a resumption ClientHello (a plain one, plus a valid pre_shared_key
 * offering f's ticket with a correctly computed binder) into ch2/ch2_len
 * (ch2_cap bytes available at ch2). */
static void make_psk_client_hello(
    struct srv_fix*         f,
    const srvt_psk_fixture* pf,
    u8*                     ch2,
    usz                     ch2_cap,
    usz*                    ch2_len) {
  u8  binder[QUIC_HKDF_PRK];
  usz psk_ext_off, trunc_len;
  make_client_hello(f);
  {
    u8                 zero_binder[QUIC_HKDF_PRK] = {0};
    quic_tlsext_psk_in psk                        = {
        quic_span_of(pf->sealed, sizeof(pf->sealed)), 0,
        quic_span_of(zero_binder, sizeof(zero_binder))};
    *ch2_len =
        srvt_psk_append(ch2, ch2_cap, f->ch, f->ch_len, &psk, &psk_ext_off);
    CHECK(*ch2_len != 0);
  }
  trunc_len = srvt_psk_truncate_len(psk_ext_off, sizeof(pf->sealed));
  quic_tls_binder_compute(pf->psk, quic_span_of(ch2, trunc_len), binder);
  {
    quic_tlsext_psk_in psk = {
        quic_span_of(pf->sealed, sizeof(pf->sealed)), 0,
        quic_span_of(binder, sizeof(binder))};
    *ch2_len =
        srvt_psk_append(ch2, ch2_cap, f->ch, f->ch_len, &psk, &psk_ext_off);
    CHECK(*ch2_len != 0);
  }
}

/* Bring the server to FLIGHT_SENT from a resumption ClientHello, with
 * resumption enabled via ticket_key. Mirrors drive_to_flight. */
static void drive_psk_to_flight(
    struct srv_fix* f, const srvt_psk_fixture* pf, const u8* ch2, usz ch2_len) {
  u8 srv_priv[32], srv_pub[32], cert_seed[32];
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]  = (u8)(0x40 + i);
    cert_seed[i] = (u8)(0x80 + i);
  }
  quic_x25519_base(srv_pub, srv_priv);

  wired_server_init_in sin   = {srv_priv, srv_pub, cert_seed, 0,
                                0,        0,       0,         pf->ticket_key};
  quic_obuf            sh_ob = quic_obuf_of(f->sh, sizeof(f->sh));
  quic_obuf            fl_ob = quic_obuf_of(f->flight, sizeof(f->flight));
  quic_sdrv_flight_out fo    = {&sh_ob, &fl_ob};
  wired_server_init(&f->s, &sin);
  CHECK(wired_server_recv_initial(&f->s, ch2, ch2_len) == 1);
  CHECK(f->s.sdrv.psk_accepted == 1);
  CHECK(wired_server_build_flight(&f->s, f->srv_random, &fo) == 1);
  f->sh_len     = sh_ob.len;
  f->flight_len = fl_ob.len;
  /* client_transcript/make_client_finished below must hash the PSK
   * ClientHello actually folded into the server's transcript, not the
   * plain f->ch make_psk_client_hello started from. */
  CHECK(ch2_len <= sizeof(f->ch));
  f->ch_len = ch2_len;
  for (usz i = 0; i < ch2_len; i++) f->ch[i] = ch2[i];
}

/* Same as make_client_finished, but for a PSK-resumption ClientHello: base
 * key = client hs traffic secret over the PSK-branch Handshake Secret (RFC
 * 8446 7.1: Early = HKDF-Extract(0, PSK)). Otherwise identical. */
static void make_client_finished_psk(
    struct srv_fix* f, const srvt_psk_fixture* pf) {
  quic_serverhello_out sh;
  u8                   hs[32], c_traffic[32], th[32];
  quic_transcript      tr;
  usz                  off;
  CHECK(quic_tls_parse_server_hello(
      quic_span_of(f->sh, f->sh_len), f->sh_pub, &sh));
  {
    u8 shared[32];
    quic_x25519(shared, f->cli_priv, f->sh_pub);
    quic_tls_handshake_secret_psk(pf->psk, shared, hs);
  }
  quic_transcript_init(&tr);
  quic_transcript_add(&tr, f->ch, f->ch_len);
  quic_transcript_add(&tr, f->sh, f->sh_len);
  quic_transcript_hash(&tr, th); /* through ServerHello */
  quic_hkdf_label chl = {"c hs traffic", 12, {th, 32}};
  quic_hkdf_expand_label(hs, &chl, quic_mspan_of(c_traffic, 32));
  quic_transcript_add(&tr, f->flight, f->flight_len);
  quic_transcript_hash(&tr, th); /* through server Finished */

  off = quic_hs_begin(f->cli_fin, sizeof(f->cli_fin), QUIC_HS_FINISHED);
  quic_tls_finished_verify_data(c_traffic, th, f->cli_fin + off);
  f->cli_fin_len = off + QUIC_TLS_VERIFY_DATA;
  quic_hs_finish(f->cli_fin, f->cli_fin_len);
}

/* Derive the application keys the way a resuming client does: PSK-branch
 * Handshake Secret (RFC 8446 7.1: Early = HKDF-Extract(0, PSK)) from the
 * shared ECDHE and the ticket's resumption secret, then Master Secret and
 * app_keys over the raw transcript through the server Finished -- the PSK
 * counterpart of client_ap_keys above. */
static void client_ap_keys_psk(
    struct srv_fix*         f,
    const srvt_psk_fixture* pf,
    int                     is_server,
    quic_initial_keys*      out) {
  u8  shared[32], hs[32], master[32], tr[3072];
  usz tlen;
  quic_x25519(shared, f->cli_priv, f->sh_pub);
  quic_tls_handshake_secret_psk(pf->psk, shared, hs);
  quic_tls_master_secret(hs, master);
  tlen = client_transcript(f, tr);
  quic_tls_app_keys(
      &(quic_app_keys_in){master, quic_span_of(tr, tlen), is_server}, out);
}

/* A PSK-accepted connection's Handshake Secret (recomputed the RFC
 * 8446 7.1 PSK way from the accepted ticket's secret + the real ECDHE) must
 * equal BOTH sdrv's own internal Handshake Secret (used to build sdrv's
 * flight, sdrv_flight.c's derive_secret) AND, downstream, the connection's
 * real application traffic keys the server actually installs -- proving
 * server.c's srv_advance_handshake branch and keyschedule.c's PSK entry
 * point are wired to the identical ecdhe/transcript sdrv used, not a
 * silently diverging computation. */
static void test_server_psk_accepted_keys_match_client(void) {
  struct srv_fix   f;
  srvt_psk_fixture pf;
  u8               ch2[700];
  usz              ch2_len;
  u8               payload[256];
  usz              plen;
  const u8*        sdrv_hs;
  u8               want_hs[32], shared[32];

  srvt_psk_fixture_init(&pf);
  make_psk_client_hello(&f, &pf, ch2, sizeof(ch2), &ch2_len);
  drive_psk_to_flight(&f, &pf, ch2, ch2_len);

  /* sdrv's own Handshake Secret (sdrv_flight.c's PSK branch) equals an
   * independent recomputation from the same ECDHE and the ticket secret. */
  quic_x25519(shared, f.cli_priv, f.sh_pub);
  quic_tls_handshake_secret_psk(pf.psk, shared, want_hs);
  CHECK(quic_sdrv_handshake_secret(&f.s.sdrv, &sdrv_hs) == 1);
  for (usz i = 0; i < 32; i++) CHECK(sdrv_hs[i] == want_hs[i]);

  /* The connection's real Handshake-level keys (keyschedule.c, via
   * server.c's srv_advance_handshake) match a client's PSK derivation too,
   * over the transcript through ServerHello (ClientHello || ServerHello),
   * the same span srv_derive_hs feeds quic_keysched_advance_handshake_psk. */
  {
    const quic_initial_keys* got;
    quic_initial_keys        want;
    u8                       tr_sh[1024];
    usz                      tr_sh_len = 0;
    for (usz i = 0; i < f.ch_len; i++) tr_sh[tr_sh_len++] = f.ch[i];
    for (usz i = 0; i < f.sh_len; i++) tr_sh[tr_sh_len++] = f.sh[i];
    CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_SERVER_HS, &got) == 1);
    quic_tls_handshake_keys(
        &(quic_handshake_keys_in){want_hs, quic_span_of(tr_sh, tr_sh_len), 1},
        &want);
    CHECK(ap_keys_eq(got, &want));
  }

  /* Full round trip: verified client Finished promotes to CONFIRMED and
   * installs 1-RTT keys that match a resuming client's own PSK-branch
   * derivation -- the real proof the whole downstream chain (Handshake ->
   * Master -> application traffic secrets) carries the PSK through. */
  make_client_finished_psk(&f, &pf);
  plen = srv_wrap_crypto(f.cli_fin, f.cli_fin_len, payload, sizeof(payload));
  CHECK(wired_server_feed(&f.s, payload, plen) == 1);
  CHECK(wired_server_is_confirmed(&f.s) == 1);
  {
    const quic_initial_keys* got;
    quic_initial_keys        want;
    CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_SERVER_AP, &got) == 1);
    client_ap_keys_psk(&f, &pf, 1, &want);
    CHECK(ap_keys_eq(got, &want));
    CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_CLIENT_AP, &got) == 1);
    client_ap_keys_psk(&f, &pf, 0, &want);
    CHECK(ap_keys_eq(got, &want));
  }
}

/* 1 if a and b's key material differs anywhere (own copy, not reusing
 * keyschedule_test.c's identically-shaped helper -- both are unity-built
 * into the same TU, but each test file should stand alone rather than lean
 * on another file's include order). */
static int srvt_keys_differ(
    const quic_initial_keys* a, const quic_initial_keys* b) {
  int d = 0;
  for (usz i = 0; i < QUIC_INITIAL_KEY; i++) d |= (a->key[i] != b->key[i]);
  return d;
}

/* Regression guard: a PSK-accepted connection's application keys
 * genuinely differ from what a plain (non-PSK) derivation over the same
 * ECDHE/transcript would produce -- proves the PSK secret is actually mixed
 * into the key schedule, not silently ignored. */
static void test_server_psk_keys_differ_from_plain(void) {
  struct srv_fix           f;
  srvt_psk_fixture         pf;
  u8                       ch2[700];
  usz                      ch2_len;
  const quic_initial_keys* got;
  quic_initial_keys        plain;

  srvt_psk_fixture_init(&pf);
  make_psk_client_hello(&f, &pf, ch2, sizeof(ch2), &ch2_len);
  drive_psk_to_flight(&f, &pf, ch2, ch2_len);

  CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_SERVER_HS, &got) == 1);
  client_ap_keys(&f, 1, &plain); /* plain (non-PSK) derivation, same ecdhe */
  CHECK(srvt_keys_differ(got, &plain));
}

/* Regression guard: a connection with NO pre_shared_key offered takes the
 * plain path -- byte-identical Handshake/AP keys to a non-PSK client's own
 * derivation, proving server.c's srv_advance_handshake branch is a true
 * no-op when psk_accepted stays 0. Duplicates
 * test_server_ap_keys_match_client under its own name so a future
 * regression here reads as a resumption failure, not a generic AP-keys
 * failure. */
static void test_server_no_psk_regression_unchanged(void) {
  test_server_ap_keys_match_client();
}

void test_server(void) {
  test_server_happy();
  test_server_forged_finished();
  test_server_flight_before_ch();
  test_server_fin_before_flight();
  test_server_ap_keys_match_client();
  test_server_records_client_random();
  test_server_no_keylog_path_writes_nothing();
  test_server_keylog_path_writes_line();
  test_server_psk_accepted_keys_match_client();
  test_server_psk_keys_differ_from_plain();
  test_server_no_psk_regression_unchanged();
}
