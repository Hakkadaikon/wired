#include "transport/packet/frame/pipeline/rxpacket.h"

#include "test.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/txpacket.h"

/* RFC 9001 5: rx recovers the exact multi-frame payload that tx sealed. */
static void test_rxpacket_payload_view(void) {
  const u8          dcid[8] = {9, 8, 7, 6, 5, 4, 3, 2};
  quic_initial_keys ik;
  quic_aes128       hp;
  quic_initial_derive(dcid, 8, 1, &ik);
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

  u8  pkt[256];
  usz n = quic_tx_packet(
      &ik, &hp, 0xc3, dcid, 8, (const u8 *)0, 0, 1, (const u8 *)0, 0, 5, frames,
      fl, pkt, sizeof(pkt));
  CHECK(n != 0);

  const u8 *got;
  usz       got_len;
  CHECK(quic_rx_packet(&ik, &hp, pkt, n, 1, &got, &got_len) == 1);
  CHECK(got_len == 3);
  CHECK(got[0] == QUIC_FRAME_PING && got[1] == QUIC_FRAME_PADDING);
  CHECK(got[2] == QUIC_FRAME_PING);
}

/* A packet shorter than its header is rejected. */
static void test_rxpacket_too_short(void) {
  quic_initial_keys ik;
  quic_aes128       hp;
  u8                buf[4] = {0};
  const u8         *got;
  usz               got_len;
  CHECK(quic_rx_packet(&ik, &hp, buf, sizeof(buf), 1, &got, &got_len) == 0);
}

/* Build one valid Initial packet for the rejection tests. dcid is fixed. */
static usz build_pkt(quic_initial_keys *ik, quic_aes128 *hp, u8 *pkt, usz cap) {
  static const u8 dcid[8] = {9, 8, 7, 6, 5, 4, 3, 2};
  u8              frames[3];
  usz             fl = 0;
  quic_initial_derive(dcid, 8, 1, ik);
  quic_aes128_init(hp, ik->hp);
  fl += quic_frame_put_simple(frames + fl, sizeof(frames), QUIC_FRAME_PING);
  return quic_tx_packet(
      ik, hp, 0xc3, dcid, 8, (const u8 *)0, 0, 1, (const u8 *)0, 0, 5, frames,
      fl, pkt, cap);
}

/* RFC 9001 5.2: a packet whose AEAD tag is flipped must be dropped, not crash.
 */
static void test_rxpacket_tampered_tag(void) {
  quic_initial_keys ik;
  quic_aes128       hp;
  u8                pkt[256];
  const u8         *got;
  usz               got_len;
  usz               n = build_pkt(&ik, &hp, pkt, sizeof(pkt));
  CHECK(n != 0);
  pkt[n - 1] ^= 0x01; /* flip one tag byte */
  CHECK(quic_rx_packet(&ik, &hp, pkt, n, 1, &got, &got_len) == 0);
}

/* RFC 9001 5.2: a packet truncated below its tag must be dropped, not crash. */
static void test_rxpacket_truncated_payload(void) {
  quic_initial_keys ik;
  quic_aes128       hp;
  u8                pkt[256];
  const u8         *got;
  usz               got_len;
  usz               n = build_pkt(&ik, &hp, pkt, sizeof(pkt));
  CHECK(n != 0);
  CHECK(quic_rx_packet(&ik, &hp, pkt, n - 1, 1, &got, &got_len) == 0);
}

/* RFC 9001 5.2: an attacker Length that exceeds the remaining buffer must be
 * rejected by the bounds check, not used to read past the buffer. The Initial
 * built here is byte0|ver(4)|dcl|dcid(8)|scl|token_len(=0) then a one-byte
 * Length varint at offset 16; widen it so length > bytes that remain. */
static void test_rxpacket_oversized_length(void) {
  quic_initial_keys ik;
  quic_aes128       hp;
  u8                pkt[256];
  const u8         *got;
  usz               got_len;
  usz               n = build_pkt(&ik, &hp, pkt, sizeof(pkt));
  CHECK(n != 0);
  CHECK(pkt[15] == 0x00);     /* empty token length */
  CHECK((pkt[16] >> 6) == 0); /* one-byte Length varint */
  pkt[16] = 0x3f;             /* claim 63 bytes of payload; far more than n */
  CHECK(quic_rx_packet(&ik, &hp, pkt, n, 1, &got, &got_len) == 0);
}

/* RFC 9001 5.2: a packet opened with the wrong key fails authentication. */
static void test_rxpacket_wrong_key(void) {
  static const u8   other[8] = {1, 1, 1, 1, 1, 1, 1, 1};
  quic_initial_keys ik, wrong;
  quic_aes128       hp;
  u8                pkt[256];
  const u8         *got;
  usz               got_len;
  usz               n = build_pkt(&ik, &hp, pkt, sizeof(pkt));
  CHECK(n != 0);
  quic_initial_derive(other, 8, 1, &wrong);
  CHECK(quic_rx_packet(&wrong, &hp, pkt, n, 1, &got, &got_len) == 0);
}

void test_rxpacket(void) {
  test_rxpacket_payload_view();
  test_rxpacket_too_short();
  test_rxpacket_tampered_tag();
  test_rxpacket_truncated_payload();
  test_rxpacket_oversized_length();
  test_rxpacket_wrong_key();
}
