#include "test.h"

/* RFC 9000 17.2 / RFC 9001 5: server-direction handshake wire codec. A TLS
 * flight handed to a srvwire seal comes back byte-for-byte from the matching
 * open (seal then open = identity); a tampered byte fails AEAD; the wrong keys
 * fail to open. The seal/open glue (CRYPTO-frame emit + extract) is what the
 * server orchestrator does not own. */

/* RFC 9001 5.2: server Initial. Sealed under the server Initial key derived
 * from the client's DCID; opened with the same DCID recovers the ServerHello.
 */
static void test_srvwire_initial_roundtrip(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  const u8 scid[6] = {'S', 'R', 'V', 'C', 'I', 'D'};
  const u8 sh[]    = {'S', 'e', 'r', 'v', 'e', 'r', 'H', 'e', 'l', 'l', 'o'};
  u8       pkt[1300];
  quic_obuf ob = {pkt, sizeof pkt, 0};
  quic_srvwire_seal_in in = {
      quic_span_of(dcid, 8), quic_span_of(scid, 6), 1, -1,
      quic_span_of(sh, sizeof sh)};
  CHECK(quic_srvwire_seal_initial(&in, &ob));
  CHECK(ob.len > sizeof(sh)); /* header + AEAD tag overhead present */

  quic_span tls = {0, 0};
  quic_srvwire_open_initial_in oin = {quic_span_of(dcid, 8), 1};
  CHECK(quic_srvwire_open_initial(&oin, quic_mspan_of(pkt, ob.len), &tls));
  CHECK(tls.n == sizeof(sh));
  for (usz i = 0; i < sizeof(sh); i++) CHECK(tls.p[i] == sh[i]);
}

/* A flipped ciphertext byte must fail AEAD on open. */
static void test_srvwire_initial_tamper(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  const u8 scid[6] = {'S', 'R', 'V', 'C', 'I', 'D'};
  const u8 sh[]    = {'S', 'e', 'r', 'v', 'e', 'r', 'H', 'e', 'l', 'l', 'o'};
  u8        pkt[1300];
  quic_obuf ob = {pkt, sizeof pkt, 0};
  quic_srvwire_seal_in in = {
      quic_span_of(dcid, 8), quic_span_of(scid, 6), 1, -1,
      quic_span_of(sh, sizeof sh)};
  CHECK(quic_srvwire_seal_initial(&in, &ob));
  pkt[ob.len - 1] ^= 0x01;
  quic_span tls = {0, 0};
  quic_srvwire_open_initial_in oin = {quic_span_of(dcid, 8), 1};
  CHECK(!quic_srvwire_open_initial(&oin, quic_mspan_of(pkt, ob.len), &tls));
}

/* A different DCID derives different keys: open must fail. */
static void test_srvwire_initial_wrong_key(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  const u8 bad[8]  = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
  const u8 scid[6] = {'S', 'R', 'V', 'C', 'I', 'D'};
  const u8 sh[]    = {'S', 'e', 'r', 'v', 'e', 'r', 'H', 'e', 'l', 'l', 'o'};
  u8        pkt[1300];
  quic_obuf ob = {pkt, sizeof pkt, 0};
  quic_srvwire_seal_in in = {
      quic_span_of(dcid, 8), quic_span_of(scid, 6), 1, -1,
      quic_span_of(sh, sizeof sh)};
  CHECK(quic_srvwire_seal_initial(&in, &ob));
  quic_span tls = {0, 0};
  quic_srvwire_open_initial_in oin = {quic_span_of(bad, 8), 1};
  CHECK(!quic_srvwire_open_initial(&oin, quic_mspan_of(pkt, ob.len), &tls));
}

/* Shared Handshake keys for the round-trip tests (RFC 9001 5). */
static void hs_keys(quic_initial_keys *k, quic_aes128 *hp) {
  for (usz i = 0; i < 16; i++) {
    k->key[i] = (u8)(0x10 + i);
    k->hp[i]  = (u8)(0x90 + i);
  }
  for (usz i = 0; i < 12; i++) k->iv[i] = (u8)(0x30 + i);
  quic_aes128_init(hp, k->hp);
}

/* RFC 9001 5: Handshake flight. Sealed and opened under the same caller-
 * supplied directional keys recovers the EE/Cert/CV/Fin bytes. */
static void test_srvwire_handshake_roundtrip(void) {
  const u8 dcid[6] = {'C', 'I', 'D', 'x', 'y', 'z'};
  const u8 scid[6] = {'S', 'R', 'V', 'C', 'I', 'D'};
  const u8 fl[]    = {'E', 'E', 'C', 'e', 'r', 't', 'C', 'V', 'F', 'i', 'n'};
  quic_initial_keys k;
  quic_aes128       hp;
  hs_keys(&k, &hp);
  u8        pkt[256];
  quic_obuf ob = {pkt, sizeof pkt, 0};
  quic_srvwire_seal_in in = {
      quic_span_of(dcid, 6), quic_span_of(scid, 6), 0, -1,
      quic_span_of(fl, sizeof fl)};
  quic_protect_keys pk = {&k, &hp};
  CHECK(quic_srvwire_seal_handshake(&pk, &in, &ob));
  quic_span tls = {0, 0};
  CHECK(quic_srvwire_open_handshake(&pk, quic_mspan_of(pkt, ob.len), &tls));
  CHECK(tls.n == sizeof(fl));
  for (usz i = 0; i < sizeof(fl); i++) CHECK(tls.p[i] == fl[i]);
}

/* Wrong Handshake keys must fail to open. */
static void test_srvwire_handshake_wrong_key(void) {
  const u8 dcid[6] = {'C', 'I', 'D', 'x', 'y', 'z'};
  const u8 scid[6] = {'S', 'R', 'V', 'C', 'I', 'D'};
  const u8 fl[]    = {'E', 'E', 'C', 'e', 'r', 't', 'C', 'V', 'F', 'i', 'n'};
  quic_initial_keys k, bad;
  quic_aes128       hp, badhp;
  hs_keys(&k, &hp);
  hs_keys(&bad, &badhp);
  bad.key[0] ^= 0xff;
  u8        pkt[256];
  quic_obuf ob = {pkt, sizeof pkt, 0};
  quic_srvwire_seal_in in = {
      quic_span_of(dcid, 6), quic_span_of(scid, 6), 0, -1,
      quic_span_of(fl, sizeof fl)};
  quic_protect_keys pk = {&k, &hp};
  CHECK(quic_srvwire_seal_handshake(&pk, &in, &ob));
  quic_span tls = {0, 0};
  quic_protect_keys badpk = {&bad, &hp};
  CHECK(!quic_srvwire_open_handshake(&badpk, quic_mspan_of(pkt, ob.len), &tls));
}

/* Walk the decrypted frames and decode the ACK frame among them (RFC
 * 9000 12.4), confirming the flight carries one. Returns 1 if found and
 * decoded. */
static int find_trailing_ack(const u8 *frames, usz n, quic_ack_frame *ack) {
  quic_framewalk      it;
  quic_framewalk_item fr;
  quic_framewalk_init(&it, frames, n);
  while (quic_framewalk_next(&it, &fr))
    if (fr.type == QUIC_FRAME_ACK)
      return quic_ack_decode(fr.start, fr.remaining, ack) != 0;
  return 0;
}

/* RFC 9000 13.2.1: an ack-eliciting client Initial (PN 0) must be acknowledged.
 * The server Initial flight carries an ACK frame (type 0x02) whose Largest
 * Acknowledged equals the received client packet number, alongside the CRYPTO.
 */
static void test_srvwire_initial_acks_client(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  const u8 scid[6] = {'S', 'R', 'V', 'C', 'I', 'D'};
  const u8 sh[]    = {'S', 'e', 'r', 'v', 'e', 'r', 'H', 'e', 'l', 'l', 'o'};
  quic_initial_keys ck, sk;
  quic_aes128       hp;
  u8                pkt[1300];
  quic_obuf         ob = {pkt, sizeof pkt, 0};
  const u8         *frames;
  usz               fl;
  quic_ack_frame    ack;
  quic_srvwire_seal_in in = {
      quic_span_of(dcid, 8), quic_span_of(scid, 6), 1, 0,
      quic_span_of(sh, sizeof sh)};
  CHECK(quic_srvwire_seal_initial(&in, &ob));
  quic_initpkt_derive(quic_span_of(dcid, 8), &ck, &sk);
  quic_aes128_init(&hp, sk.hp);
  quic_protect_keys pk = {&sk, &hp};
  quic_rx_desc      rd = {quic_mspan_of(pkt, ob.len), 1};
  quic_span         fv;
  CHECK(quic_rx_packet(&pk, &rd, &fv));
  frames = fv.p;
  fl     = fv.n;
  CHECK(find_trailing_ack(frames, fl, &ack));
  CHECK(ack.n_ranges == 1);
  CHECK(ack.ranges[0].hi == 0); /* Largest Acknowledged == client Initial PN */
  CHECK(ack.ranges[0].lo == 0);
}

/* RFC 9000 13.2.1: a Handshake flight likewise acknowledges a received
 * Handshake-space packet (here PN 3) with a trailing ACK frame. */
static void test_srvwire_handshake_acks_client(void) {
  const u8          dcid[6] = {'C', 'I', 'D', 'x', 'y', 'z'};
  const u8          scid[6] = {'S', 'R', 'V', 'C', 'I', 'D'};
  const u8          fl_in[] = {'E', 'E', 'F', 'i', 'n'};
  quic_initial_keys k;
  quic_aes128       hp;
  u8                pkt[512];
  quic_obuf         ob = {pkt, sizeof pkt, 0};
  const u8         *frames;
  usz               fl;
  quic_ack_frame    ack;
  hs_keys(&k, &hp);
  quic_srvwire_seal_in in = {
      quic_span_of(dcid, 6), quic_span_of(scid, 6), 0, 3,
      quic_span_of(fl_in, sizeof fl_in)};
  quic_protect_keys pk = {&k, &hp};
  CHECK(quic_srvwire_seal_handshake(&pk, &in, &ob));
  quic_protect_keys pk2 = {&k, &hp};
  quic_rx_desc      rd2 = {quic_mspan_of(pkt, ob.len), 0};
  quic_span         fv2;
  CHECK(quic_rx_packet(&pk2, &rd2, &fv2));
  frames = fv2.p;
  fl     = fv2.n;
  CHECK(find_trailing_ack(frames, fl, &ack));
  CHECK(ack.ranges[0].hi == 3);
}

void test_srvwire(void) {
  test_srvwire_initial_roundtrip();
  test_srvwire_initial_tamper();
  test_srvwire_initial_wrong_key();
  test_srvwire_handshake_roundtrip();
  test_srvwire_handshake_wrong_key();
  test_srvwire_initial_acks_client();
  test_srvwire_handshake_acks_client();
}
