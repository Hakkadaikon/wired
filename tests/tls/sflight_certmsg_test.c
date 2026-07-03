#include "test.h"
#include "realchain_golden.h"
#include "tls/handshake/core/tls/cert.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/roles/sflight/certmsg.h"

/* RFC 8446 4.4.2: a 2-entry chain [leaf, int] round-trips through
 * quic_tls_cert_chain byte-for-byte against the golden DERs. */
static void test_certchain_two_roundtrip(void) {
  const quic_span certs[2] = {
      quic_span_of(
          quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)),
      quic_span_of(quic_realchain_int_der, sizeof(quic_realchain_int_der))};
  quic_sflight_certchain_in in = {certs, 2};
  u8                        out[2048];
  quic_obuf                 ob = quic_obuf_of(out, sizeof(out));
  usz                       body_len;
  u8                        type;
  quic_span                 ctx;
  quic_tls_cert_entry       entries[QUIC_TLS_CERT_CHAIN_MAX];
  usz                       count;
  quic_tls_cert_chain_out   co = {entries, QUIC_TLS_CERT_CHAIN_MAX, &count};

  CHECK(quic_sflight_certificate_chain(&in, &ob));
  CHECK(quic_hs_parse(quic_span_of(out, ob.len), &type, &body_len) == 4);
  CHECK(quic_tls_cert_chain(quic_span_of(out + 4, body_len), &ctx, &co));
  CHECK(count == 2);
  CHECK(entries[0].cert_len == sizeof(quic_realchain_leaf_der));
  CHECK(entries[1].cert_len == sizeof(quic_realchain_int_der));
  for (usz i = 0; i < entries[0].cert_len; i++)
    CHECK(entries[0].cert_data[i] == quic_realchain_leaf_der[i]);
  for (usz i = 0; i < entries[1].cert_len; i++)
    CHECK(entries[1].cert_data[i] == quic_realchain_int_der[i]);
}

/* A 1-entry chain output is byte-identical to the legacy single-cert path. */
static void test_certchain_single_equals_legacy(void) {
  const u8   der[7] = {0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
  quic_span  cert   = quic_span_of(der, sizeof(der));
  u8         out_chain[64], out_legacy[64];
  quic_obuf  ob_chain  = quic_obuf_of(out_chain, sizeof(out_chain));
  quic_obuf  ob_legacy = quic_obuf_of(out_legacy, sizeof(out_legacy));
  quic_sflight_certchain_in in = {&cert, 1};

  CHECK(quic_sflight_certificate_chain(&in, &ob_chain));
  CHECK(quic_sflight_certificate(cert, &ob_legacy));
  CHECK(ob_chain.len == ob_legacy.len);
  for (usz i = 0; i < ob_chain.len; i++) CHECK(out_chain[i] == out_legacy[i]);
}

/* count 0 and count > QUIC_TLS_CERT_CHAIN_MAX are rejected; count 2 is fine. */
static void test_certchain_bounds(void) {
  const quic_span certs[QUIC_TLS_CERT_CHAIN_MAX + 1] = {
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)),
      quic_span_of(quic_realchain_int_der, sizeof(quic_realchain_int_der)),
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)),
      quic_span_of(quic_realchain_int_der, sizeof(quic_realchain_int_der)),
      quic_span_of(quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der))};
  u8         out[4096];
  quic_obuf  ob0 = quic_obuf_of(out, sizeof(out));
  quic_obuf  ob1 = quic_obuf_of(out, sizeof(out));
  quic_obuf  ob2 = quic_obuf_of(out, sizeof(out));
  quic_sflight_certchain_in in0 = {certs, 0};
  quic_sflight_certchain_in in1 = {certs, QUIC_TLS_CERT_CHAIN_MAX + 1};
  quic_sflight_certchain_in in2 = {certs, 2};

  CHECK(!quic_sflight_certificate_chain(&in0, &ob0));
  CHECK(!quic_sflight_certificate_chain(&in1, &ob1));
  CHECK(quic_sflight_certificate_chain(&in2, &ob2));
}

/* A cap too small for the chain is rejected (0), not truncated. */
static void test_certchain_no_room(void) {
  const quic_span certs[2] = {
      quic_span_of(
          quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)),
      quic_span_of(quic_realchain_int_der, sizeof(quic_realchain_int_der))};
  u8         out[16];
  quic_obuf  ob = quic_obuf_of(out, sizeof(out));
  quic_sflight_certchain_in in = {certs, 2};

  CHECK(!quic_sflight_certificate_chain(&in, &ob));
}

/* RFC 8446 4.4.2: the built Certificate message must parse back with an empty
 * request context and the same end-entity cert_data. */
void test_sflight_certmsg(void) {
  const u8            der[7] = {0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
  u8                  out[64];
  usz                 body_len;
  u8                  type;
  quic_span           ctx;
  quic_tls_cert_entry first;
  quic_obuf           ob = quic_obuf_of(out, sizeof(out));

  CHECK(quic_sflight_certificate(quic_span_of(der, sizeof(der)), &ob));
  CHECK(quic_hs_parse(quic_span_of(out, ob.len), &type, &body_len) == 4);
  CHECK(type == 11);
  CHECK(4 + body_len == ob.len);

  CHECK(quic_tls_cert_parse(quic_span_of(out + 4, body_len), &ctx, &first));
  CHECK(ctx.n == 0); /* empty request context */
  CHECK(first.cert_len == sizeof(der));
  CHECK(first.cert_data[0] == 0x30 && first.cert_data[6] == 0x05);

  ob = quic_obuf_of(out, 4);
  CHECK(!quic_sflight_certificate(quic_span_of(der, sizeof(der)), &ob));

  test_certchain_two_roundtrip();
  test_certchain_single_equals_legacy();
  test_certchain_bounds();
  test_certchain_no_room();
}
