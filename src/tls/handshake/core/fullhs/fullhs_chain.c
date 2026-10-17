#include "tls/handshake/core/fullhs/fullhs_impl.h"

static int fullhs_chain_parse(
    wired_span cert_msg, const tls_cert_chain_out* out);
static int fullhs_chain_ok(const fullhs* h, const tls_cert_entry* e, usz n);
static int fullhs_cert_checks(const fullhs* h, const tls_cert_entry* e, usz n);
static int fullhs_chain_accept(
    const fullhs* h, wired_span cert_msg, const tls_cert_chain_out* out);
static void fullhs_cert_record(fullhs* h, const fullhs_chain_rec_in* in);
static int  fullhs_cert_take(fullhs* h, wired_span cert_msg);
static int  cv_verify(fullhs* h, wired_span cv_msg, u16 scheme);
static int  fin_verifies(fullhs* h, const u8* fin_msg, usz len);

/* Every CertificateEntry of the wire chain, leaf first. */
static int fullhs_chain_parse(
    wired_span cert_msg, const tls_cert_chain_out* out) {
  wired_span ctx;
  wired_span body =
      wired_span_of(cert_msg.p + HS_HEADER, cert_msg.n - HS_HEADER);
  return tls_cert_chain(body, &ctx, out);
}

/* RFC 5280 6.1: when a trust store is set, the whole wire chain must chain
 * link-by-link to one of its anchors. NULL store skips. */
static int fullhs_chain_ok(const fullhs* h, const tls_cert_entry* e, usz n) {
  wired_span certs[TLS_CERT_CHAIN_MAX];
  if (h->castore == 0) {
    return 1;
  }
  for (usz i = 0; i < n; i++) {
    certs[i] = wired_span_of(e[i].cert_data, e[i].cert_len);
  }
  return castore_validate_chain(h->castore, certs, n);
}

/* The leaf passes the acceptance policy and the chain anchors to the store. */
static int fullhs_cert_checks(const fullhs* h, const tls_cert_entry* e, usz n) {
  if (n < 1) {
    return 0;
  }
  if (!fullhs_policy_ok(h, e[0].cert_data, e[0].cert_len)) {
    return 0;
  }
  return fullhs_chain_ok(h, e, n);
}

/* Parse and accept (or reject) the wire chain. */
static int fullhs_chain_accept(
    const fullhs* h, wired_span cert_msg, const tls_cert_chain_out* out) {
  if (!fullhs_chain_parse(cert_msg, out)) {
    return 0;
  }
  return fullhs_cert_checks(h, out->entries, *out->count);
}

static void fullhs_cert_record(fullhs* h, const fullhs_chain_rec_in* in) {
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
static int fullhs_cert_take(fullhs* h, wired_span cert_msg) {
  tls_cert_entry      e[TLS_CERT_CHAIN_MAX];
  usz                 n;
  fullhs_chain_rec_in rec;
  tls_cert_chain_out  out = {e, TLS_CERT_CHAIN_MAX, &n};
  if (!fullhs_chain_accept(h, cert_msg, &out)) {
    return 0;
  }
  rec.base = h->tr_len;
  if (!fullhs_tr_add(h, cert_msg.p, cert_msg.n)) {
    return 0;
  }
  rec.cert_msg = cert_msg;
  rec.e        = e;
  rec.n        = n;
  fullhs_cert_record(h, &rec);
  return 1;
}

int fullhs_recv_cert(fullhs* h, const u8* cert_msg, usz len) {
  if (!fullhs_order_ok(h, HSD_CERTIFICATE)) {
    return 0;
  }
  return fullhs_cert_take(h, wired_span_of(cert_msg, len));
}

/* Verify the CertificateVerify signature over the transcript hash through the
 * Certificate message (the message body precedes the running hash). */
static int cv_verify(fullhs* h, wired_span cv_msg, u16 scheme) {
  u16        sig_scheme;
  wired_span sig,
      body = wired_span_of(cv_msg.p + HS_HEADER, cv_msg.n - HS_HEADER);
  u8            th[SHA256_DIGEST];
  certverify_in in;
  if (!tls_certverify_parse(body, &sig_scheme, &sig)) {
    return 0;
  }
  fullhs_tr_hash(h, th);
  in.scheme          = scheme;
  in.cert            = wired_span_of(h->peer_cert, h->peer_cert_len);
  in.sig             = sig;
  in.transcript_hash = th;
  return tls_verify_cert_signature(&in);
}

int fullhs_recv_certverify(fullhs* h, wired_span cv_msg, u16 scheme) {
  if (!cv_verify(h, cv_msg, scheme)) {
    return 0;
  }
  if (!fullhs_order_ok(h, HSD_CERT_VERIFY)) {
    return 0;
  }
  hsdriver_cert_verified(&h->tls->hs);
  return fullhs_tr_add(h, cv_msg.p, cv_msg.n);
}

/* A well-sized Finished whose verify_data matches the peer's handshake traffic
 * secret over the current transcript. Checked before the order machine is
 * advanced so a bad Finished never marks the handshake complete. */
static int fin_verifies(fullhs* h, const u8* fin_msg, usz len) {
  u8 th[SHA256_DIGEST];
  if (len != HS_HEADER + TLS_VERIFY_DATA) {
    return 0;
  }
  fullhs_tr_hash(h, th);
  return tls_finished_check(h->hs_traffic_peer, th, fin_msg + HS_HEADER);
}

int fullhs_recv_finished(fullhs* h, const u8* fin_msg, usz len) {
  if (!fin_verifies(h, fin_msg, len)) {
    return 0;
  }
  if (!fullhs_order_ok(h, HSD_FINISHED)) {
    return 0;
  }
  return fullhs_fold_finished(h, fin_msg, len);
}
