#include "test.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/roles/srvfin/verify.h"

/* Build a client Finished message the way the client would: verify_data =
 * HMAC(HKDF-Expand-Label(client_hs_secret, "finished"), transcript_hash),
 * wrapped in a handshake header (type 20). The server must accept it and
 * reject any tampered byte, wrong type, or wrong length. */
void test_srvfin_verify(void) {
  u8 secret[QUIC_HKDF_PRK];
  u8 th[QUIC_SHA256_DIGEST];
  for (usz i = 0; i < QUIC_HKDF_PRK; i++) secret[i] = (u8)(i + 7);
  for (usz i = 0; i < QUIC_SHA256_DIGEST; i++) th[i] = (u8)(0x30 + i);

  /* client side: hand-build the Finished message */
  u8  msg[64];
  usz off = quic_hs_begin(msg, sizeof msg, QUIC_HS_FINISHED);
  quic_tls_finished_verify_data(secret, th, msg + off);
  usz total = off + QUIC_TLS_VERIFY_DATA;
  quic_hs_finish(msg, total);

  /* round-trip: server accepts the genuine Finished */
  CHECK(
      quic_srvfin_verify_client_finished(
          quic_span_of(msg, total), secret, th) == 1);

  /* tampered verify_data is rejected */
  u8 bad[64];
  for (usz i = 0; i < total; i++) bad[i] = msg[i];
  bad[off] ^= 0x01;
  CHECK(
      quic_srvfin_verify_client_finished(
          quic_span_of(bad, total), secret, th) == 0);

  /* a different transcript hash does not verify */
  u8 th2[QUIC_SHA256_DIGEST];
  for (usz i = 0; i < QUIC_SHA256_DIGEST; i++) th2[i] = th[i];
  th2[0] ^= 0xFF;
  CHECK(
      quic_srvfin_verify_client_finished(
          quic_span_of(msg, total), secret, th2) == 0);

  /* wrong handshake type (not Finished) is rejected */
  u8 wt[64];
  for (usz i = 0; i < total; i++) wt[i] = msg[i];
  wt[0] = QUIC_HS_CLIENT_HELLO;
  CHECK(
      quic_srvfin_verify_client_finished(quic_span_of(wt, total), secret, th) ==
      0);

  /* truncated message (body shorter than verify_data) is rejected */
  CHECK(
      quic_srvfin_verify_client_finished(
          quic_span_of(msg, total - 1), secret, th) == 0);

  /* wrong body length: a Finished header claiming 16-byte body */
  u8  shortmsg[32];
  usz so = quic_hs_begin(shortmsg, sizeof shortmsg, QUIC_HS_FINISHED);
  for (usz i = 0; i < 16; i++) shortmsg[so + i] = 0;
  quic_hs_finish(shortmsg, so + 16);
  CHECK(
      quic_srvfin_verify_client_finished(
          quic_span_of(shortmsg, so + 16), secret, th) == 0);
}
