#include "transport/packet/frame/pipeline/txpacket.h"

#include "test.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/rxpacket.h"

/* RFC 9001 5: a packet sealed by quic_tx_packet unprotects under the same keys
 * back to the identical frame bytes. */
static void test_txpacket_roundtrip(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys ik;
  quic_aes128       hp;
  quic_initial_derive(dcid, 8, 0, &ik);
  quic_aes128_init(&hp, ik.hp);

  u8  ping[1];
  usz fl = quic_frame_put_simple(ping, sizeof(ping), QUIC_FRAME_PING);
  CHECK(fl == 1);

  u8  pkt[256];
  usz n = quic_tx_packet(
      &ik, &hp, 0xc3, dcid, 8, (const u8 *)0, 0, 1, (const u8 *)0, 0, 1, ping,
      fl, pkt, sizeof(pkt));
  CHECK(n != 0);

  const u8 *frames;
  usz       frames_len;
  CHECK(quic_rx_packet(&ik, &hp, pkt, n, 1, &frames, &frames_len) == 1);
  CHECK(frames_len == fl);
  CHECK(frames[0] == QUIC_FRAME_PING);
}

/* A tampered ciphertext fails authentication. */
static void test_txpacket_tamper(void) {
  const u8          dcid[4] = {1, 2, 3, 4};
  quic_initial_keys ik;
  quic_aes128       hp;
  quic_initial_derive(dcid, 4, 0, &ik);
  quic_aes128_init(&hp, ik.hp);

  u8  ping[1] = {QUIC_FRAME_PING};
  u8  pkt[256];
  usz n = quic_tx_packet(
      &ik, &hp, 0xc3, dcid, 4, (const u8 *)0, 0, 1, (const u8 *)0, 0, 7, ping,
      1, pkt, sizeof(pkt));
  CHECK(n != 0);
  pkt[n - 1] ^= 0x01; /* corrupt the tag */

  const u8 *frames;
  usz       frames_len;
  CHECK(quic_rx_packet(&ik, &hp, pkt, n, 1, &frames, &frames_len) == 0);
}

void test_txpacket(void) {
  test_txpacket_roundtrip();
  test_txpacket_tamper();
}
