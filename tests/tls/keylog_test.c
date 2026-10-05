#include "test.h"
#include "tls/handshake/core/tls/clienthello.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/serverhello.h"
#include "tls/handshake/core/tls/transcript.h"
#include "tls/handshake/core/tls/x25519.h"
#include "tls/handshake/roles/server/server.h"
#include "tls/keys/schedule_drive/keyschedule.h"
#include "transport/conn/pnspace/crypto_stream/crypto_tx.h"

/* NSS Key Log Format (draft-ietf-tls-keylogfile 3/4; RFC 8446 7.1 names the
 * secrets): a server whose client Finished verified appends one line per
 * TLS 1.3 secret -- "<LABEL> <client_random hex> <secret hex>\n" -- with
 * CLIENT_EARLY_TRAFFIC_SECRET first only when 0-RTT was accepted. The
 * handshake secrets are re-derived client-side here (independent of the
 * server); the 1-RTT/exporter ones are pinned to the server's keysched. */

#define SYS_unlinkat 263
#define TKL_AT_FDCWD (-100)
#define TKL_FILE_MAX 2048 /* 6 lines x ~160 bytes, with room */

static const char tkl_path[] = "build/tls_keylog_test.tmp";

static void tkl_unlink(void) {
  syscall3(SYS_unlinkat, TKL_AT_FDCWD, tkl_path, 0);
}

typedef struct {
  wired_server s;
  u8           ch[512];
  usz          ch_len;
  u8           sh[256];
  usz          sh_len;
  u8           flight[2048];
  usz          flight_len;
  u8           cr[32];
  u8           cli_priv[32];
  u8           c_hs[32]; /* client-side c hs traffic */
  u8           s_hs[32]; /* client-side s hs traffic */
  u8           fin[64];
  usz          fin_len;
} tkl_fix;

static void tkl_client_hello(tkl_fix* f) {
  u8 cli_pub[32];
  for (usz i = 0; i < 32; i++) {
    f->cli_priv[i] = (u8)(i + 1);
    f->cr[i]       = (u8)(0xc0 + i);
  }
  wired_x25519_base(cli_pub, f->cli_priv);
  f->ch_len = tls_client_hello(
      &(clienthello_in){
          f->cr, cli_pub, wired_span_of(0, 0), wired_span_of(0, 0)},
      &(wired_obuf){f->ch, sizeof(f->ch), 0});
}

static void tkl_server_flight(tkl_fix* f) {
  u8 srv_priv[32], srv_pub[32], seed[32], srv_random[32];
  for (usz i = 0; i < 32; i++) {
    srv_priv[i]   = (u8)(0x40 + i);
    seed[i]       = (u8)(0x80 + i);
    srv_random[i] = (u8)(0x20 + i);
  }
  wired_x25519_base(srv_pub, srv_priv);
  wired_server_init_in sin   = {srv_priv, srv_pub, seed, 0, 0, 0, 0, 0};
  wired_obuf           sh_ob = obuf_of(f->sh, sizeof(f->sh));
  wired_obuf           fl_ob = obuf_of(f->flight, sizeof(f->flight));
  sdrv_flight_out      fo    = {&sh_ob, &fl_ob};
  wired_server_init(&f->s, &sin);
  CHECK(wired_server_recv_initial(&f->s, f->ch, f->ch_len) == 1);
  CHECK(wired_server_build_flight(&f->s, srv_random, &fo) == 1);
  f->sh_len     = sh_ob.len;
  f->flight_len = fl_ob.len;
}

/* RFC 8446 7.1: client-side Handshake Secret and both hs traffic secrets
 * over Hash(ClientHello..ServerHello). */
static void tkl_client_hs_secrets(tkl_fix* f, transcript* tr) {
  serverhello_out sh;
  u8              sh_pub[32], shared[32], hs[32], th[32];
  CHECK(tls_parse_server_hello(wired_span_of(f->sh, f->sh_len), sh_pub, &sh));
  wired_x25519(shared, f->cli_priv, sh_pub);
  tls_handshake_secret(shared, hs);
  transcript_init(tr);
  transcript_add(tr, f->ch, f->ch_len);
  transcript_add(tr, f->sh, f->sh_len);
  transcript_hash(tr, th);
  hkdf_label cl = {"c hs traffic", 12, {th, 32}};
  hkdf_label sl = {"s hs traffic", 12, {th, 32}};
  hkdf_expand_label(hs, &cl, wired_mspan_of(f->c_hs, 32));
  hkdf_expand_label(hs, &sl, wired_mspan_of(f->s_hs, 32));
}

/* RFC 8446 4.4.4: the genuine client Finished, wrapped as a CRYPTO payload. */
static void tkl_client_finished(tkl_fix* f) {
  transcript tr;
  u8         th[32];
  usz        off;
  tkl_client_hs_secrets(f, &tr);
  transcript_add(&tr, f->flight, f->flight_len);
  transcript_hash(&tr, th);
  off = hs_begin(f->fin, sizeof(f->fin), HS_FINISHED);
  tls_finished_verify_data(f->c_hs, th, f->fin + off);
  f->fin_len = off + TLS_VERIFY_DATA;
  hs_finish(f->fin, f->fin_len);
}

static void tkl_feed_finished(tkl_fix* f) {
  u8                    payload[256];
  wired_obuf            ob  = obuf_of(payload, sizeof payload);
  crypto_stream_emit_in ein = {0, 256};
  tkl_client_finished(f);
  CHECK(crypto_stream_emit(wired_span_of(f->fin, f->fin_len), &ein, &ob));
  CHECK(wired_server_feed(&f->s, payload, ob.len) == 1);
}

static usz tkl_put_hex(u8* out, const u8* p, usz n) {
  static const char d[] = "0123456789abcdef";
  for (usz i = 0; i < n; i++) {
    out[2 * i]     = (u8)d[p[i] >> 4];
    out[2 * i + 1] = (u8)d[p[i] & 0xF];
  }
  return 2 * n;
}

/* Expect exactly "<label> <hex cr> <hex secret>\n" at file[*off]. */
static void tkl_expect_line(
    const u8*   file,
    usz*        off,
    const char* label,
    const u8    cr[32],
    const u8    secret[32]) {
  u8  want[256];
  usz n = 0;
  while (label[n]) {
    want[n] = (u8)label[n];
    n++;
  }
  want[n++] = ' ';
  n += tkl_put_hex(want + n, cr, 32);
  want[n++] = ' ';
  n += tkl_put_hex(want + n, secret, 32);
  want[n++] = '\n';
  for (usz i = 0; i < n; i++) CHECK(file[*off + i] == want[i]);
  *off += n;
}

static void tkl_expect_tail(const u8* file, usz off, const tkl_fix* f) {
  const u8 *cap, *sap, *exp;
  CHECK(keysched_client_ap_secret(&f->s.sched, &cap) == 1);
  CHECK(keysched_server_ap_secret(&f->s.sched, &sap) == 1);
  CHECK(keysched_exporter_secret(&f->s.sched, &exp) == 1);
  tkl_expect_line(
      file, &off, "CLIENT_HANDSHAKE_TRAFFIC_SECRET", f->cr, f->c_hs);
  tkl_expect_line(
      file, &off, "SERVER_HANDSHAKE_TRAFFIC_SECRET", f->cr, f->s_hs);
  tkl_expect_line(file, &off, "CLIENT_TRAFFIC_SECRET_0", f->cr, cap);
  tkl_expect_line(file, &off, "SERVER_TRAFFIC_SECRET_0", f->cr, sap);
  tkl_expect_line(file, &off, "EXPORTER_SECRET", f->cr, exp);
  CHECK(file[off] == 0); /* exactly these lines, nothing after */
}

static ssz tkl_read(u8* file) {
  return wired_fio_read(tkl_path, wired_mspan_of(file, TKL_FILE_MAX));
}

/* 1-RTT handshake (no 0-RTT): exactly the five TLS 1.3 labels, in order. */
static void test_tls_keylog_full_handshake(void) {
  static tkl_fix f;
  u8             file[TKL_FILE_MAX + 1] = {0};
  tkl_client_hello(&f);
  tkl_server_flight(&f);
  wired_server_set_keylog_path(&f.s, tkl_path);
  tkl_unlink();
  tkl_feed_finished(&f);
  CHECK(tkl_read(file) > 0);
  tkl_expect_tail(file, 0, &f);
  tkl_unlink();
}

/* RFC 8446 7.1: client_early_traffic_secret = Derive-Secret(HKDF-Extract(0,
 * PSK), "c e traffic", ClientHello), derived independently here. */
static void tkl_early_secret(const u8 psk[32], const tkl_fix* f, u8 out[32]) {
  u8 zero[32] = {0}, early[32], th[32];
  hkdf_extract(wired_span_of(zero, 32), wired_span_of(psk, 32), early);
  wired_sha256(f->ch, f->ch_len, th);
  hkdf_label l = {"c e traffic", 11, {th, 32}};
  hkdf_expand_label(early, &l, wired_mspan_of(out, 32));
}

/* Accepted 0-RTT (state poked as server_test.c's early-data test does):
 * CLIENT_EARLY_TRAFFIC_SECRET leads, then the same five lines. */
static void test_tls_keylog_early_data(void) {
  static tkl_fix f;
  u8             file[TKL_FILE_MAX + 1] = {0}, early[32];
  usz            off                    = 0;
  tkl_client_hello(&f);
  tkl_server_flight(&f);
  wired_server_set_keylog_path(&f.s, tkl_path);
  for (usz i = 0; i < 32; i++) f.s.sdrv.psk_secret[i] = (u8)(0x70 + i);
  f.s.sdrv.early_data_accepted = 1;
  tkl_early_secret(f.s.sdrv.psk_secret, &f, early);
  tkl_unlink();
  tkl_feed_finished(&f);
  CHECK(tkl_read(file) > 0);
  tkl_expect_line(file, &off, "CLIENT_EARLY_TRAFFIC_SECRET", f.cr, early);
  tkl_expect_tail(file, off, &f);
  tkl_unlink();
}

/* Opt-in: no path set, a full handshake creates no file. */
static void test_tls_keylog_off_by_default(void) {
  static tkl_fix f;
  u8             file[TKL_FILE_MAX + 1];
  tkl_client_hello(&f);
  tkl_server_flight(&f);
  tkl_unlink();
  tkl_feed_finished(&f);
  CHECK(tkl_read(file) < 0);
}

void test_tls_keylog(void) {
  test_tls_keylog_full_handshake();
  test_tls_keylog_early_data();
  test_tls_keylog_off_by_default();
}
