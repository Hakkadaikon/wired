#include "transport/conn/loop/connio/connio.h"

#include "test.h"
#include "transport/packet/frame/frame/frame.h"

/* Test-only convenience over the connio_init_in param object. */
static void mk_connio(
    quic_connio *io, int is_server, u8 byte0, const u8 *dcid, u8 dcid_len,
    u64 initial_max_data) {
  quic_connio_init_in in = {is_server, byte0, initial_max_data};
  quic_connio_init(io, quic_span_of(dcid, dcid_len), &in);
}

/* Test-only convenience over the connio_send_in param object. */
static usz send_at(
    quic_connio *io, int level, const u8 *frames, usz frames_len, u8 *out,
    usz cap) {
  quic_connio_send_in sin = {level, quic_span_of(frames, frames_len)};
  quic_obuf            ob = quic_obuf_of(out, cap);
  return quic_connio_send(io, &sin, &ob);
}

/* RFC 9001 5: a STREAM frame sealed by one peer's connio_send opens under the
 * other peer's connio_recv (same installed keys) and lands in stream_read. */
static void test_connio_seal_open_roundtrip(void) {
  const u8    dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_connio cl, sv;
  mk_connio(&cl, 0, 0xc3, dcid, 8, 1u << 20);
  mk_connio(&sv, 1, 0xc3, dcid, 8, 1u << 20);
  cl.loop.validated   = 1;
  sv.loop.validated   = 1;
  quic_initial_keys k = {0};
  quic_keyset_install(&cl.loop.keys, QUIC_LEVEL_INITIAL, &k);
  quic_keyset_install(&sv.loop.keys, QUIC_LEVEL_INITIAL, &k);

  u8                frames[64];
  quic_stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 5,
      .data      = (const u8 *)"hello",
      .fin       = 1};
  usz fl = quic_frame_put_stream(frames, sizeof(frames), &sf);
  CHECK(fl != 0);

  u8  pkt[256];
  usz pn = send_at(&cl, QUIC_LEVEL_INITIAL, frames, fl, pkt, sizeof(pkt));
  CHECK(pn != 0);

  CHECK(quic_connio_recv(&sv, QUIC_LEVEL_INITIAL, quic_mspan_of(pkt, pn)) == 1);

  /* the STREAM bytes reached the server's read buffer in order */
  u8        got[16];
  quic_obuf ob = quic_obuf_of(got, sizeof(got));
  quic_stream_read_pull(&sv.stream, &ob);
  CHECK(ob.len == 5);
  CHECK(got[0] == 'h' && got[4] == 'o');
}

/* RFC 9001 4: with no key installed at a level, both send and recv are gated
 * out (return 0) before any cryptographic work. */
static void test_connio_gated_without_key(void) {
  const u8    dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_connio io;
  mk_connio(&io, 0, 0x43, dcid, 8, 1u << 20);
  io.loop.validated = 1;

  u8 frames[8] = {0x01}; /* a PING frame */
  u8 pkt[64];
  /* Handshake level has no key installed */
  CHECK(send_at(&io, QUIC_LEVEL_HANDSHAKE, frames, 1, pkt, sizeof(pkt)) == 0);
  CHECK(quic_connio_recv(&io, QUIC_LEVEL_HANDSHAKE, quic_mspan_of(pkt, 32)) == 0);
}

/* Install Initial + Handshake keys on io and lift its anti-amp gate so sends at
 * both levels are admitted. */
static void arm_two_levels(quic_connio *io) {
  quic_initial_keys k = {0};
  io->loop.validated  = 1;
  quic_keyset_install(&io->loop.keys, QUIC_LEVEL_INITIAL, &k);
  quic_keyset_install(&io->loop.keys, QUIC_LEVEL_HANDSHAKE, &k);
}

/* RFC 9000 12.3: each packet number space numbers from 0 independently. A send
 * in the Initial space and a send in the Handshake space both carry pn 0, and
 * each advances only its own space's counter. The send number must be drawn
 * from the SELECTED space's counter, never one shared across spaces. */
static void test_connio_per_space_pn(void) {
  const u8    dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_connio io;
  mk_connio(&io, 0, 0xc3, dcid, 8, 1u << 20);
  arm_two_levels(&io);

  u8 frames[8] = {0x01}; /* a PING frame */
  u8 pkt[256];

  CHECK(quic_connio_tx_next(&io, QUIC_LEVEL_INITIAL) == 0);
  CHECK(quic_connio_tx_next(&io, QUIC_LEVEL_HANDSHAKE) == 0);

  /* first send in Initial: advances Initial only, Handshake untouched */
  CHECK(send_at(&io, QUIC_LEVEL_INITIAL, frames, 1, pkt, sizeof(pkt)) != 0);
  CHECK(quic_connio_tx_next(&io, QUIC_LEVEL_INITIAL) == 1);
  CHECK(quic_connio_tx_next(&io, QUIC_LEVEL_HANDSHAKE) == 0);

  /* first send in Handshake: carries pn 0, advances Handshake only */
  CHECK(send_at(&io, QUIC_LEVEL_HANDSHAKE, frames, 1, pkt, sizeof(pkt)) != 0);
  CHECK(quic_connio_tx_next(&io, QUIC_LEVEL_HANDSHAKE) == 1);
  CHECK(quic_connio_tx_next(&io, QUIC_LEVEL_INITIAL) == 1);
}

/* RFC 9000 12.3: send packet numbers within a space increase strictly
 * monotonically; repeated sends never reuse a number. */
static void test_connio_pn_monotone(void) {
  const u8    dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_connio io;
  mk_connio(&io, 0, 0xc3, dcid, 8, 1u << 20);
  arm_two_levels(&io);

  u8 frames[8] = {0x01};
  u8 pkt[256];
  CHECK(send_at(&io, QUIC_LEVEL_INITIAL, frames, 1, pkt, 256) != 0);
  CHECK(send_at(&io, QUIC_LEVEL_INITIAL, frames, 1, pkt, 256) != 0);
  CHECK(send_at(&io, QUIC_LEVEL_INITIAL, frames, 1, pkt, 256) != 0);
  CHECK(quic_connio_tx_next(&io, QUIC_LEVEL_INITIAL) == 3);
}

/* RFC 9000 13.2: a received packet number never lowers a space's largest, and
 * each space tracks its own. recv increments only the selected space's expected
 * number, leaving the other spaces at 0. */
static void test_connio_recv_per_space(void) {
  const u8    dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_connio cl, sv;
  mk_connio(&cl, 0, 0xc3, dcid, 8, 1u << 20);
  mk_connio(&sv, 1, 0xc3, dcid, 8, 1u << 20);
  arm_two_levels(&cl);
  arm_two_levels(&sv);

  u8  frames[8] = {0x01};
  u8  pkt[256];
  usz n = send_at(&cl, QUIC_LEVEL_INITIAL, frames, 1, pkt, 256);
  CHECK(n != 0);
  CHECK(quic_connio_recv(&sv, QUIC_LEVEL_INITIAL, quic_mspan_of(pkt, n)) == 1);

  /* only the Initial space's expected number advanced */
  CHECK(quic_connio_rx_next(&sv, QUIC_LEVEL_INITIAL) == 1);
  CHECK(quic_connio_rx_next(&sv, QUIC_LEVEL_HANDSHAKE) == 0);
}

void test_connio(void) {
  test_connio_seal_open_roundtrip();
  test_connio_gated_without_key();
  test_connio_per_space_pn();
  test_connio_pn_monotone();
  test_connio_recv_per_space();
}
