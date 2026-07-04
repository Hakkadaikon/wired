#include "transport/packet/frame/pipeline/rxpacket.h"

#include "test.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/txpacket.h"

/* Open one Initial packet; returns 1 and the frames view on success. */
static int r_rx(
    const quic_initial_keys* ik,
    const quic_aes128*       hp,
    u8*                      pkt,
    usz                      n,
    quic_span*               frames) {
  quic_protect_keys k = {ik, hp};
  quic_rx_desc      d = {quic_mspan_of(pkt, n), 1};
  return quic_rx_packet(&k, &d, frames);
}

/* RFC 9001 5: rx recovers the exact multi-frame payload that tx sealed. */
static void test_rxpacket_payload_view(void) {
  const u8          dcid[8] = {9, 8, 7, 6, 5, 4, 3, 2};
  quic_initial_keys ik;
  quic_aes128       hp;
  quic_initial_derive(quic_span_of(dcid, 8), 1, &ik);
  quic_aes128_init(&hp, ik.hp);

  u8  frames[8];
  usz fl = 0;
  fl +=
      quic_frame_put_simple(frames + fl, sizeof(frames) - fl, QUIC_FRAME_PING);
  fl += quic_frame_put_simple(
      frames + fl, sizeof(frames) - fl, QUIC_FRAME_PADDING);
  fl +=
      quic_frame_put_simple(frames + fl, sizeof(frames) - fl, QUIC_FRAME_PING);
  CHECK(fl == 3);

  u8                pkt[256];
  quic_protect_keys k    = {&ik, &hp};
  quic_span         none = quic_span_of((const u8*)0, 0);
  quic_tx_desc      td   = {0xc3, quic_span_of(dcid, 8),   none, 1, none,
                            5,    quic_span_of(frames, fl)};
  usz n = quic_tx_packet(&k, &td, quic_mspan_of(pkt, sizeof(pkt)));
  CHECK(n != 0);

  quic_span got;
  CHECK(r_rx(&ik, &hp, pkt, n, &got) == 1);
  CHECK(got.n == 3);
  CHECK(got.p[0] == QUIC_FRAME_PING && got.p[1] == QUIC_FRAME_PADDING);
  CHECK(got.p[2] == QUIC_FRAME_PING);
}

/* A packet shorter than its header is rejected. Keys are zeroed, not derived:
 * the length check must reject the packet before they are ever read. */
static void test_rxpacket_too_short(void) {
  quic_initial_keys ik     = {0};
  quic_aes128       hp     = {0};
  u8                buf[4] = {0};
  quic_span         got;
  CHECK(r_rx(&ik, &hp, buf, sizeof(buf), &got) == 0);
}

/* Build one valid Initial packet for the rejection tests. dcid is fixed. */
static usz build_pkt(quic_initial_keys* ik, quic_aes128* hp, u8* pkt, usz cap) {
  static const u8 dcid[8] = {9, 8, 7, 6, 5, 4, 3, 2};
  u8              frames[3];
  usz             fl = 0;
  quic_initial_derive(quic_span_of(dcid, 8), 1, ik);
  quic_aes128_init(hp, ik->hp);
  fl += quic_frame_put_simple(frames + fl, sizeof(frames), QUIC_FRAME_PING);
  quic_protect_keys k    = {ik, hp};
  quic_span         none = quic_span_of((const u8*)0, 0);
  quic_tx_desc      td   = {0xc3, quic_span_of(dcid, 8),   none, 1, none,
                            5,    quic_span_of(frames, fl)};
  return quic_tx_packet(&k, &td, quic_mspan_of(pkt, cap));
}

/* RFC 9001 5.2: a packet whose AEAD tag is flipped must be dropped, not crash.
 */
static void test_rxpacket_tampered_tag(void) {
  quic_initial_keys ik;
  quic_aes128       hp;
  u8                pkt[256];
  quic_span         got;
  usz               n = build_pkt(&ik, &hp, pkt, sizeof(pkt));
  CHECK(n != 0);
  pkt[n - 1] ^= 0x01; /* flip one tag byte */
  CHECK(r_rx(&ik, &hp, pkt, n, &got) == 0);
}

/* RFC 9001 5.2: a packet truncated below its tag must be dropped, not crash. */
static void test_rxpacket_truncated_payload(void) {
  quic_initial_keys ik;
  quic_aes128       hp;
  u8                pkt[256];
  quic_span         got;
  usz               n = build_pkt(&ik, &hp, pkt, sizeof(pkt));
  CHECK(n != 0);
  CHECK(r_rx(&ik, &hp, pkt, n - 1, &got) == 0);
}

/* RFC 9001 5.2: an attacker Length that exceeds the remaining buffer must be
 * rejected by the bounds check, not used to read past the buffer. The Initial
 * built here is byte0|ver(4)|dcl|dcid(8)|scl|token_len(=0) then a one-byte
 * Length varint at offset 16; widen it so length > bytes that remain. */
static void test_rxpacket_oversized_length(void) {
  quic_initial_keys ik;
  quic_aes128       hp;
  u8                pkt[256];
  quic_span         got;
  usz               n = build_pkt(&ik, &hp, pkt, sizeof(pkt));
  CHECK(n != 0);
  CHECK(pkt[15] == 0x00);     /* empty token length */
  CHECK((pkt[16] >> 6) == 0); /* one-byte Length varint */
  pkt[16] = 0x3f;             /* claim 63 bytes of payload; far more than n */
  CHECK(r_rx(&ik, &hp, pkt, n, &got) == 0);
}

/* RFC 9001 5.2: a packet opened with the wrong key fails authentication. */
static void test_rxpacket_wrong_key(void) {
  static const u8   other[8] = {1, 1, 1, 1, 1, 1, 1, 1};
  quic_initial_keys ik, wrong;
  quic_aes128       hp;
  u8                pkt[256];
  quic_span         got;
  usz               n = build_pkt(&ik, &hp, pkt, sizeof(pkt));
  CHECK(n != 0);
  quic_initial_derive(quic_span_of(other, 8), 1, &wrong);
  CHECK(r_rx(&wrong, &hp, pkt, n, &got) == 0);
}

void test_rxpacket(void) {
  test_rxpacket_payload_view();
  test_rxpacket_too_short();
  test_rxpacket_tampered_tag();
  test_rxpacket_truncated_payload();
  test_rxpacket_oversized_length();
  test_rxpacket_wrong_key();
}
