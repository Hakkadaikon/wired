#include "tls/handshake/core/fullhs/fullhs_impl.h"

static void hs_traffic(
    const u8 hs[HKDF_PRK], wired_span sh, int is_server, u8 out[HKDF_PRK]);
static void seed_secrets(fullhs* h, const u8* sh, usz sh_len);
static void prime_order(fullhs* h);
static int  fullhs_time_ok(const fullhs* h, const x509* x);
static int  fullhs_host_ok(const fullhs* h, const x509* x);
static int  fullhs_policy_checks(const fullhs* h, const u8* cert, usz n);

/* RFC 8446 4.4 / RFC 9001 4.1: full handshake orchestration. */

/* Append a handshake message to the raw transcript, clamping at the cap so a
 * malformed flight can never overrun. Returns 1 if it fit. */
int fullhs_tr_add(fullhs* h, const u8* msg, usz len) {
  if (len > FULLHS_TRANSCRIPT_MAX - h->tr_len) {
    return 0;
  }
  for (usz i = 0; i < len; i++) {
    h->tr[h->tr_len + i] = msg[i];
  }
  h->tr_len += len;
  return 1;
}

/* RFC 8446 4.4.1: Transcript-Hash over every message buffered so far. */
void fullhs_tr_hash(const fullhs* h, u8 out[SHA256_DIGEST]) {
  wired_sha256(h->tr, h->tr_len, out);
}

/* RFC 8446 7.1: one direction's handshake traffic secret over the transcript
 * through ServerHello. is_server selects "s hs traffic"/"c hs traffic". */
static void hs_traffic(
    const u8 hs[HKDF_PRK], wired_span sh, int is_server, u8 out[HKDF_PRK]) {
  const char*      label = is_server ? "s hs traffic" : "c hs traffic";
  derive_secret_in in    = {hs, wired_span_of((const u8*)label, 12), sh, 0};
  tls_derive_secret(&in, out);
}

/* Derive both directions' handshake traffic secrets over the transcript
 * through ServerHello and seed the cumulative transcript with it.
 * RFC 8446 4.4.1/7.1: that transcript is ClientHello||ServerHello, not
 * ServerHello alone -- h->tls->transcript_ch (saved by tlsdriver_
 * client_hello, empty on the server side, see tlsdriver.h's doc comment)
 * is prepended first, exactly like tlsdriver.c's own build_transcript does
 * for the handshake-secret derivation. */
static void seed_secrets(fullhs* h, const u8* sh, usz sh_len) {
  u8         hs[HKDF_PRK];
  const u8*  ecdhe;
  wired_span tr_span;
  tlsdriver_shared_secret(h->tls, &ecdhe);
  tls_handshake_secret(ecdhe, hs);
  h->tr_len = 0;
  fullhs_tr_add(h, h->tls->transcript_ch, h->tls->transcript_ch_len);
  fullhs_tr_add(h, sh, sh_len);
  tr_span = wired_span_of(h->tr, h->tr_len);
  /* peer direction is the opposite of our own role. */
  hs_traffic(hs, tr_span, !h->is_server, h->hs_traffic_peer);
  hs_traffic(hs, tr_span, h->is_server, h->hs_traffic_self);
}

/* Walk the order machine through the flight already exchanged before this
 * layer takes over: ClientHello, ServerHello (Initial), EncryptedExtensions
 * (Handshake). The tlsdriver derived keys for these but left the order machine
 * at the start, so replay them here. */
static void prime_order(fullhs* h) {
  hsdriver_recv(&h->tls->hs, HSD_CLIENT_HELLO, HSD_PROT_INITIAL);
  hsdriver_recv(&h->tls->hs, HSD_SERVER_HELLO, HSD_PROT_INITIAL);
  hsdriver_recv(&h->tls->hs, HSD_ENCRYPTED_EXT, HSD_PROT_HANDSHAKE);
}

int fullhs_init(fullhs* h, tlsdriver* tls, wired_span sh) {
  if (!tlsdriver_handshake_secret_ready(tls)) {
    return 0;
  }
  h->tls             = tls;
  h->is_server       = tls->is_server;
  h->peer_cert       = 0;
  h->peer_cert_len   = 0;
  h->master_tr_len   = 0;
  h->policy_now      = 0;
  h->policy_host     = 0;
  h->policy_host_len = 0;
  h->cert_count      = 0;
  h->castore         = 0;
  seed_secrets(h, sh.p, sh.n);
  prime_order(h);
  return 1;
}

void fullhs_set_policy(fullhs* h, u64 now, wired_span host) {
  h->policy_now      = now;
  h->policy_host     = host.p;
  h->policy_host_len = host.n;
}

void fullhs_set_castore(fullhs* h, const castore* store) { h->castore = store; }

/* RFC 8446 7.1: fold a Finished into the transcript and, if it is the first
 * one seen (the server's), record the length at which the application traffic
 * secrets are derived. */
int fullhs_fold_finished(fullhs* h, const u8* fin, usz len) {
  if (!fullhs_tr_add(h, fin, len)) {
    return 0;
  }
  if (h->master_tr_len == 0) {
    h->master_tr_len = h->tr_len;
  }
  return 1;
}

/* The peer's protection level for handshake-flight messages is Handshake. */
int fullhs_order_ok(fullhs* h, u8 msg_type) {
  return hsdriver_recv(&h->tls->hs, msg_type, HSD_PROT_HANDSHAKE);
}

/* RFC 5280 6.1: the certificate window covers policy_now (0 skips). */
static int fullhs_time_ok(const fullhs* h, const x509* x) {
  return h->policy_now == 0 || x509_validity_ok(x->tbs, h->policy_now);
}

/* RFC 6125: a SAN dNSName matches policy_host (length 0 skips). */
static int fullhs_host_ok(const fullhs* h, const x509* x) {
  return h->policy_host_len == 0 ||
         x509_san_matches(
             x->tbs, wired_span_of(h->policy_host, h->policy_host_len));
}

static int fullhs_policy_checks(const fullhs* h, const u8* cert, usz n) {
  x509 x;
  if (!x509_parse(wired_span_of(cert, n), &x)) {
    return 0;
  }
  return fullhs_time_ok(h, &x) && fullhs_host_ok(h, &x);
}

/* No policy set = legacy signature-only behavior; else parse and enforce. */
int fullhs_policy_ok(const fullhs* h, const u8* cert, usz n) {
  if (h->policy_now == 0 && h->policy_host_len == 0) {
    return 1;
  }
  return fullhs_policy_checks(h, cert, n);
}
