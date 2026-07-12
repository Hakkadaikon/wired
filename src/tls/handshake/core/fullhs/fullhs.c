#include "tls/handshake/core/fullhs/fullhs.h"

#include "crypto/kdf/keys/discard_driver.h"
#include "crypto/kdf/keys/keyset.h"
#include "crypto/pki/encoding/x509/san.h"
#include "crypto/pki/encoding/x509/validity.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/certverify.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/hs_message.h"
#include "tls/handshake/core/tls/hsdriver.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/keys/schedule_drive/keyschedule.h"

/* RFC 8446 4.4 / RFC 9001 4.1: full handshake orchestration. */

/* Append a handshake message to the raw transcript, clamping at the cap so a
 * malformed flight can never overrun. Returns 1 if it fit. */
static int tr_add(quic_fullhs* h, const u8* msg, usz len) {
  if (len > QUIC_FULLHS_TRANSCRIPT_MAX - h->tr_len) return 0;
  for (usz i = 0; i < len; i++) h->tr[h->tr_len + i] = msg[i];
  h->tr_len += len;
  return 1;
}

/* RFC 8446 4.4.1: Transcript-Hash over every message buffered so far. */
static void tr_hash(const quic_fullhs* h, u8 out[QUIC_SHA256_DIGEST]) {
  quic_sha256(h->tr, h->tr_len, out);
}

/* RFC 8446 7.1: one direction's handshake traffic secret over the transcript
 * through ServerHello. is_server selects "s hs traffic"/"c hs traffic". */
static void hs_traffic(
    const u8  hs[QUIC_HKDF_PRK],
    quic_span sh,
    int       is_server,
    u8        out[QUIC_HKDF_PRK]) {
  const char*           label = is_server ? "s hs traffic" : "c hs traffic";
  quic_derive_secret_in in    = {hs, quic_span_of((const u8*)label, 12), sh};
  quic_tls_derive_secret(&in, out);
}

/* Derive both directions' handshake traffic secrets over the transcript
 * through ServerHello and seed the cumulative transcript with it.
 * RFC 8446 4.4.1/7.1: that transcript is ClientHello||ServerHello, not
 * ServerHello alone -- h->tls->transcript_ch (saved by quic_tlsdriver_
 * client_hello, empty on the server side, see tlsdriver.h's doc comment)
 * is prepended first, exactly like tlsdriver.c's own build_transcript does
 * for the handshake-secret derivation. */
static void seed_secrets(quic_fullhs* h, const u8* sh, usz sh_len) {
  u8        hs[QUIC_HKDF_PRK];
  const u8* ecdhe;
  quic_span tr_span;
  quic_tlsdriver_shared_secret(h->tls, &ecdhe);
  quic_tls_handshake_secret(ecdhe, hs);
  h->tr_len = 0;
  tr_add(h, h->tls->transcript_ch, h->tls->transcript_ch_len);
  tr_add(h, sh, sh_len);
  tr_span = quic_span_of(h->tr, h->tr_len);
  /* peer direction is the opposite of our own role. */
  hs_traffic(hs, tr_span, !h->is_server, h->hs_traffic_peer);
  hs_traffic(hs, tr_span, h->is_server, h->hs_traffic_self);
}

/* Walk the order machine through the flight already exchanged before this
 * layer takes over: ClientHello, ServerHello (Initial), EncryptedExtensions
 * (Handshake). The tlsdriver derived keys for these but left the order machine
 * at the start, so replay them here. */
static void prime_order(quic_fullhs* h) {
  quic_hsdriver_recv(&h->tls->hs, QUIC_HSD_CLIENT_HELLO, QUIC_HSD_PROT_INITIAL);
  quic_hsdriver_recv(&h->tls->hs, QUIC_HSD_SERVER_HELLO, QUIC_HSD_PROT_INITIAL);
  quic_hsdriver_recv(
      &h->tls->hs, QUIC_HSD_ENCRYPTED_EXT, QUIC_HSD_PROT_HANDSHAKE);
}

int quic_fullhs_init(quic_fullhs* h, quic_tlsdriver* tls, quic_span sh) {
  if (!quic_tlsdriver_handshake_secret_ready(tls)) return 0;
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

void quic_fullhs_set_policy(quic_fullhs* h, u64 now, quic_span host) {
  h->policy_now      = now;
  h->policy_host     = host.p;
  h->policy_host_len = host.n;
}

void quic_fullhs_set_castore(quic_fullhs* h, const quic_castore* store) {
  h->castore = store;
}

/* RFC 8446 7.1: fold a Finished into the transcript and, if it is the first
 * one seen (the server's), record the length at which the application traffic
 * secrets are derived. */
static int fold_finished(quic_fullhs* h, const u8* fin, usz len) {
  if (!tr_add(h, fin, len)) return 0;
  if (h->master_tr_len == 0) h->master_tr_len = h->tr_len;
  return 1;
}

/* The peer's protection level for handshake-flight messages is Handshake. */
static int order_ok(quic_fullhs* h, u8 msg_type) {
  return quic_hsdriver_recv(&h->tls->hs, msg_type, QUIC_HSD_PROT_HANDSHAKE);
}

/* RFC 5280 6.1: the certificate window covers policy_now (0 skips). */
static int fullhs_time_ok(const quic_fullhs* h, const quic_x509* x) {
  return h->policy_now == 0 || quic_x509_validity_ok(x->tbs, h->policy_now);
}

/* RFC 6125: a SAN dNSName matches policy_host (length 0 skips). */
static int fullhs_host_ok(const quic_fullhs* h, const quic_x509* x) {
  return h->policy_host_len == 0 ||
         quic_x509_san_matches(
             x->tbs, quic_span_of(h->policy_host, h->policy_host_len));
}

static int fullhs_policy_checks(const quic_fullhs* h, const u8* cert, usz n) {
  quic_x509 x;
  if (!quic_x509_parse(quic_span_of(cert, n), &x)) return 0;
  return fullhs_time_ok(h, &x) && fullhs_host_ok(h, &x);
}

/* No policy set = legacy signature-only behavior; else parse and enforce. */
static int fullhs_policy_ok(const quic_fullhs* h, const u8* cert, usz n) {
  if (h->policy_now == 0 && h->policy_host_len == 0) return 1;
  return fullhs_policy_checks(h, cert, n);
}

/* Every CertificateEntry of the wire chain, leaf first. */
static int fullhs_chain_parse(
    quic_span cert_msg, const quic_tls_cert_chain_out* out) {
  quic_span ctx;
  quic_span body =
      quic_span_of(cert_msg.p + QUIC_HS_HEADER, cert_msg.n - QUIC_HS_HEADER);
  return quic_tls_cert_chain(body, &ctx, out);
}

/* RFC 5280 6.1: when a trust store is set, the whole wire chain must chain
 * link-by-link to one of its anchors. NULL store skips. */
static int fullhs_chain_ok(
    const quic_fullhs* h, const quic_tls_cert_entry* e, usz n) {
  quic_span certs[QUIC_TLS_CERT_CHAIN_MAX];
  if (h->castore == 0) return 1;
  for (usz i = 0; i < n; i++)
    certs[i] = quic_span_of(e[i].cert_data, e[i].cert_len);
  return quic_castore_validate_chain(h->castore, certs, n);
}

/* The leaf passes the acceptance policy and the chain anchors to the store. */
static int fullhs_cert_checks(
    const quic_fullhs* h, const quic_tls_cert_entry* e, usz n) {
  if (n < 1) return 0;
  if (!fullhs_policy_ok(h, e[0].cert_data, e[0].cert_len)) return 0;
  return fullhs_chain_ok(h, e, n);
}

/* Parse and accept (or reject) the wire chain. */
static int fullhs_chain_accept(
    const quic_fullhs*             h,
    quic_span                      cert_msg,
    const quic_tls_cert_chain_out* out) {
  if (!fullhs_chain_parse(cert_msg, out)) return 0;
  return fullhs_cert_checks(h, out->entries, *out->count);
}

/* Record every cert as an offset into the transcript copy of cert_msg (the
 * bytes tr_add appended at `base`), so the views outlive the caller's
 * datagram buffer for the rest of the handshake. */
typedef struct {
  usz                        base;
  quic_span                  cert_msg;
  const quic_tls_cert_entry* e;
  usz                        n;
} fullhs_chain_rec_in;

static void fullhs_cert_record(quic_fullhs* h, const fullhs_chain_rec_in* in) {
  for (usz i = 0; i < in->n; i++) {
    h->cert_off[i]  = in->base + (usz)(in->e[i].cert_data - in->cert_msg.p);
    h->cert_lens[i] = in->e[i].cert_len;
  }
  h->cert_count    = in->n;
  h->peer_cert     = h->tr + h->cert_off[0];
  h->peer_cert_len = h->cert_lens[0];
}

/* On any reject nothing is recorded, so the CertificateVerify signature can
 * never verify and cert_verified stays shut. */
static int fullhs_cert_take(quic_fullhs* h, quic_span cert_msg) {
  quic_tls_cert_entry     e[QUIC_TLS_CERT_CHAIN_MAX];
  usz                     n;
  fullhs_chain_rec_in     rec;
  quic_tls_cert_chain_out out = {e, QUIC_TLS_CERT_CHAIN_MAX, &n};
  if (!fullhs_chain_accept(h, cert_msg, &out)) return 0;
  rec.base = h->tr_len;
  if (!tr_add(h, cert_msg.p, cert_msg.n)) return 0;
  rec.cert_msg = cert_msg;
  rec.e        = e;
  rec.n        = n;
  fullhs_cert_record(h, &rec);
  return 1;
}

int quic_fullhs_recv_cert(quic_fullhs* h, const u8* cert_msg, usz len) {
  if (!order_ok(h, QUIC_HSD_CERTIFICATE)) return 0;
  return fullhs_cert_take(h, quic_span_of(cert_msg, len));
}

/* Verify the CertificateVerify signature over the transcript hash through the
 * Certificate message (the message body precedes the running hash). */
static int cv_verify(quic_fullhs* h, quic_span cv_msg, u16 scheme) {
  u16       sig_scheme;
  quic_span sig,
      body = quic_span_of(cv_msg.p + QUIC_HS_HEADER, cv_msg.n - QUIC_HS_HEADER);
  u8                 th[QUIC_SHA256_DIGEST];
  quic_certverify_in in;
  if (!quic_tls_certverify_parse(body, &sig_scheme, &sig)) return 0;
  tr_hash(h, th);
  in.scheme          = scheme;
  in.cert            = quic_span_of(h->peer_cert, h->peer_cert_len);
  in.sig             = sig;
  in.transcript_hash = th;
  return quic_tls_verify_cert_signature(&in);
}

int quic_fullhs_recv_certverify(quic_fullhs* h, quic_span cv_msg, u16 scheme) {
  if (!cv_verify(h, cv_msg, scheme)) return 0;
  if (!order_ok(h, QUIC_HSD_CERT_VERIFY)) return 0;
  quic_hsdriver_cert_verified(&h->tls->hs);
  return tr_add(h, cv_msg.p, cv_msg.n);
}

/* A well-sized Finished whose verify_data matches the peer's handshake traffic
 * secret over the current transcript. Checked before the order machine is
 * advanced so a bad Finished never marks the handshake complete. */
static int fin_verifies(quic_fullhs* h, const u8* fin_msg, usz len) {
  u8 th[QUIC_SHA256_DIGEST];
  if (len != QUIC_HS_HEADER + QUIC_TLS_VERIFY_DATA) return 0;
  tr_hash(h, th);
  return quic_tls_finished_check(
      h->hs_traffic_peer, th, fin_msg + QUIC_HS_HEADER);
}

int quic_fullhs_recv_finished(quic_fullhs* h, const u8* fin_msg, usz len) {
  if (!fin_verifies(h, fin_msg, len)) return 0;
  if (!order_ok(h, QUIC_HSD_FINISHED)) return 0;
  return fold_finished(h, fin_msg, len);
}

int quic_fullhs_send_finished(quic_fullhs* h, quic_obuf* out) {
  u8 th[QUIC_SHA256_DIGEST];
  if (out->cap < QUIC_HS_HEADER + QUIC_TLS_VERIFY_DATA) return 0;
  out->p[0] = QUIC_HSD_FINISHED;
  out->p[1] = 0;
  out->p[2] = 0;
  out->p[3] = QUIC_TLS_VERIFY_DATA;
  tr_hash(h, th);
  quic_tls_finished_verify_data(
      h->hs_traffic_self, th, out->p + QUIC_HS_HEADER);
  out->len = QUIC_HS_HEADER + QUIC_TLS_VERIFY_DATA;
  return fold_finished(h, out->p, out->len);
}

/* Install the 1-RTT keys for our send direction, unlocking 1-RTT sending. */
static void install_app(quic_fullhs* h) {
  const quic_initial_keys* k;
  int which = h->is_server ? QUIC_KS_SERVER_AP : QUIC_KS_CLIENT_AP;
  if (quic_keysched_get(&h->tls->ks, which, &k))
    quic_keyset_install(&h->tls->keys, QUIC_LEVEL_ONERTT, k);
}

/* RFC 8446 7.1: application_traffic_secret_0 is derived over the transcript
 * through the server's Finished, which is the last message buffered once the
 * peer's Finished was accepted. */
int quic_fullhs_advance_application(quic_fullhs* h) {
  if (!quic_hsdriver_complete(&h->tls->hs)) return 0;
  quic_keysched_advance_master(&h->tls->ks, h->tr, h->master_tr_len);
  install_app(h);
  return 1;
}

int quic_fullhs_confirmed(quic_fullhs* h) {
  if (!quic_hsdriver_recv(
          &h->tls->hs, QUIC_HSD_HANDSHAKE_DONE, QUIC_HSD_PROT_1RTT))
    return 0;
  if (quic_key_should_discard_handshake(quic_hsdriver_confirmed(&h->tls->hs)))
    quic_keyset_discard(&h->tls->keys, QUIC_LEVEL_HANDSHAKE);
  return 1;
}

int quic_fullhs_is_complete(const quic_fullhs* h) {
  return quic_hsdriver_complete(&h->tls->hs);
}

int quic_fullhs_is_confirmed(const quic_fullhs* h) {
  return quic_hsdriver_confirmed(&h->tls->hs);
}
