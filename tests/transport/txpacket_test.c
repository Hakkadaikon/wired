#include "transport/packet/frame/pipeline/txpacket.h"

#include "test.h"
#include "tls/handshake/core/tls/initial.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/pipeline/rxpacket.h"

/* Seal one long-header packet (no SCID, no token). */
static usz t_tx(
    const quic_initial_keys* ik,
    const quic_aes128*       hp,
    quic_span                dcid,
    u64                      pn,
    quic_span                frames,
    u8*                      pkt,
    usz                      cap) {
  quic_protect_keys k    = {ik, hp};
  quic_span         none = quic_span_of((const u8*)0, 0);
  quic_tx_desc      d    = {0xc3, dcid, none, 1, none, pn, frames};
  return quic_tx_packet(&k, &d, quic_mspan_of(pkt, cap));
}

/* Open one Initial packet; returns 1 and the frames view on success. */
static int t_rx(
    const quic_initial_keys* ik,
    const quic_aes128*       hp,
    u8*                      pkt,
    usz                      n,
    quic_span*               frames) {
  quic_protect_keys k = {ik, hp};
  quic_rx_desc      d = {quic_mspan_of(pkt, n), 1};
  return quic_rx_packet(&k, &d, frames);
}

/* RFC 9001 5: a packet sealed by quic_tx_packet unprotects under the same keys
 * back to the identical frame bytes. */
static void test_txpacket_roundtrip(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys ik;
  quic_aes128       hp;
  quic_initial_derive(quic_span_of(dcid, 8), 0, &ik);
  quic_aes128_init(&hp, ik.hp);

  u8  ping[1];
  usz fl = quic_frame_put_simple(ping, sizeof(ping), QUIC_FRAME_PING);
  CHECK(fl == 1);

  u8  pkt[256];
  usz n = t_tx(
      &ik, &hp, quic_span_of(dcid, 8), 1, quic_span_of(ping, fl), pkt,
      sizeof(pkt));
  CHECK(n != 0);

  quic_span frames;
  CHECK(t_rx(&ik, &hp, pkt, n, &frames) == 1);
  CHECK(frames.n == fl);
  CHECK(frames.p[0] == QUIC_FRAME_PING);
}

/* A tampered ciphertext fails authentication. */
static void test_txpacket_tamper(void) {
  const u8          dcid[4] = {1, 2, 3, 4};
  quic_initial_keys ik;
  quic_aes128       hp;
  quic_initial_derive(quic_span_of(dcid, 4), 0, &ik);
  quic_aes128_init(&hp, ik.hp);

  u8  ping[1] = {QUIC_FRAME_PING};
  u8  pkt[256];
  usz n = t_tx(
      &ik, &hp, quic_span_of(dcid, 4), 7, quic_span_of(ping, 1), pkt,
      sizeof(pkt));
  CHECK(n != 0);
  pkt[n - 1] ^= 0x01; /* corrupt the tag */

  quic_span frames;
  CHECK(t_rx(&ik, &hp, pkt, n, &frames) == 0);
}

void test_txpacket(void) {
  test_txpacket_roundtrip();
  test_txpacket_tamper();
}
