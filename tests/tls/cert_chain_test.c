#include "test.h"
#include "tls/handshake/core/tls/cert.h"

/* One CertificateEntry: cert_data (3-byte length) + empty extensions. */
static usz cc_entry(u8 *out, const u8 *cert, usz n) {
  out[0] = (u8)(n >> 16);
  out[1] = (u8)(n >> 8);
  out[2] = (u8)n;
  for (usz i = 0; i < n; i++) out[3 + i] = cert[i];
  out[3 + n] = 0;
  out[4 + n] = 0;
  return n + 5;
}

/* A Certificate message body (RFC 8446 4.4.2, after the handshake header):
 * ctx(1)=0 | list_len(3) | entries. */
static usz cc_body(u8 *out, const u8 *const *certs, const usz *lens, usz k) {
  usz off = 4, list;
  out[0]  = 0;
  for (usz i = 0; i < k; i++) off += cc_entry(out + off, certs[i], lens[i]);
  list   = off - 4;
  out[1] = (u8)(list >> 16);
  out[2] = (u8)(list >> 8);
  out[3] = (u8)list;
  return off;
}

static const u8 cc_a[3] = {0xa1, 0xa2, 0xa3};
static const u8 cc_b[5] = {0xb1, 0xb2, 0xb3, 0xb4, 0xb5};
static const u8 cc_c[2] = {0xc1, 0xc2};

/* [leaf, issuer]: both entries viewed, leaf first, lengths exact. */
static void test_cert_chain_two(void) {
  u8                  body[64];
  const u8           *certs[2] = {cc_a, cc_b};
  usz                 lens[2]  = {sizeof(cc_a), sizeof(cc_b)};
  quic_tls_cert_entry e[QUIC_TLS_CERT_CHAIN_MAX];
  quic_span ctx;
  usz                 n = cc_body(body, certs, lens, 2), count;
  CHECK(quic_tls_cert_chain(quic_span_of(body, n), &ctx, &(quic_tls_cert_chain_out){e, 4, &count}) == 1);
  CHECK(count == 2);
  CHECK(e[0].cert_len == 3 && e[0].cert_data[0] == 0xa1);
  CHECK(e[1].cert_len == 5 && e[1].cert_data[4] == 0xb5);
}

/* 1 entry and 3 entries both enumerate fully. */
static void test_cert_chain_counts(void) {
  u8                  body[64];
  const u8           *certs[3] = {cc_a, cc_b, cc_c};
  usz                 lens[3]  = {sizeof(cc_a), sizeof(cc_b), sizeof(cc_c)};
  quic_tls_cert_entry e[QUIC_TLS_CERT_CHAIN_MAX];
  quic_span ctx;
  usz                 n, count;
  n = cc_body(body, certs, lens, 1);
  CHECK(quic_tls_cert_chain(quic_span_of(body, n), &ctx, &(quic_tls_cert_chain_out){e, 4, &count}) == 1);
  CHECK(count == 1);
  n = cc_body(body, certs, lens, 3);
  CHECK(quic_tls_cert_chain(quic_span_of(body, n), &ctx, &(quic_tls_cert_chain_out){e, 4, &count}) == 1);
  CHECK(count == 3 && e[2].cert_len == 2);
}

/* More entries than cap is rejected (fail closed), not truncated. */
static void test_cert_chain_overflow(void) {
  u8        body[96];
  const u8 *certs[5] = {cc_a, cc_a, cc_a, cc_a, cc_a};
  usz       lens[5]  = {
      sizeof(cc_a), sizeof(cc_a), sizeof(cc_a), sizeof(cc_a), sizeof(cc_a)};
  quic_tls_cert_entry e[QUIC_TLS_CERT_CHAIN_MAX];
  quic_span ctx;
  usz                 n = cc_body(body, certs, lens, 5), count;
  CHECK(quic_tls_cert_chain(quic_span_of(body, n), &ctx, &(quic_tls_cert_chain_out){e, 4, &count}) == 0);
}

/* A truncated entry (cert bytes or extensions cut off) is rejected. */
static void test_cert_chain_truncated(void) {
  u8                  body[64];
  const u8           *certs[2] = {cc_a, cc_b};
  usz                 lens[2]  = {sizeof(cc_a), sizeof(cc_b)};
  quic_tls_cert_entry e[QUIC_TLS_CERT_CHAIN_MAX];
  quic_span ctx;
  usz                 n = cc_body(body, certs, lens, 2), count;
  /* entry 2's cert_len claims more bytes than the list holds
   * (entry 1 spans body[4..11], entry 2's 3-byte length is at body[12]) */
  body[14] = 0x09;
  CHECK(quic_tls_cert_chain(quic_span_of(body, n), &ctx, &(quic_tls_cert_chain_out){e, 4, &count}) == 0);
  body[14] = 0x05;
  /* whole buffer cut short: the certificate_list vector itself is truncated */
  CHECK(quic_tls_cert_chain(quic_span_of(body, n - 1), &ctx, &(quic_tls_cert_chain_out){e, 4, &count}) == 0);
}

void test_cert_chain(void) {
  test_cert_chain_two();
  test_cert_chain_counts();
  test_cert_chain_overflow();
  test_cert_chain_truncated();
}
