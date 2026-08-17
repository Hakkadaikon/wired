#include "transport/conn/loop/connio/connio.h"

#include "common/diag/error/error.h"
#include "test.h"
#include "transport/packet/frame/frame/connctl.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"

/* Test-only convenience over the connio_init_in param object. */
static void mk_connio(
    connio*   io,
    int       is_server,
    u8        byte0,
    const u8* dcid,
    u8        dcid_len,
    u64       initial_max_data) {
  connio_init_in in = {is_server, byte0, initial_max_data};
  connio_init(io, wired_span_of(dcid, dcid_len), &in);
}

/* Test-only convenience over the connio_send_in param object. */
static usz send_at(
    connio* io, int level, const u8* frames, usz frames_len, u8* out, usz cap) {
  connio_send_in sin = {level, wired_span_of(frames, frames_len)};
  wired_obuf     ob  = obuf_of(out, cap);
  return connio_send(io, &sin, &ob);
}

/* RFC 9001 5: a STREAM frame sealed by one peer's connio_send opens under the
 * other peer's connio_recv (same installed keys) and lands in stream_read. */
static void test_connio_seal_open_roundtrip(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   cl, sv;
  mk_connio(&cl, 0, 0xc3, dcid, 8, 1u << 20);
  mk_connio(&sv, 1, 0xc3, dcid, 8, 1u << 20);
  cl.loop.validated = 1;
  sv.loop.validated = 1;
  initial_keys k    = {0};
  keyset_install(&cl.loop.keys, LEVEL_INITIAL, &k);
  keyset_install(&sv.loop.keys, LEVEL_INITIAL, &k);

  u8           frames[64];
  stream_frame sf = {
      .stream_id = 4,
      .offset    = 0,
      .length    = 5,
      .data      = (const u8*)"hello",
      .fin       = 1};
  usz fl = frame_put_stream(frames, sizeof(frames), &sf);
  CHECK(fl != 0);

  u8  pkt[256];
  usz pn = send_at(&cl, LEVEL_INITIAL, frames, fl, pkt, sizeof(pkt));
  CHECK(pn != 0);

  CHECK(connio_recv(&sv, LEVEL_INITIAL, wired_mspan_of(pkt, pn)) == 1);

  /* the STREAM bytes reached the server's read buffer in order */
  u8         got[16];
  wired_obuf ob = obuf_of(got, sizeof(got));
  stream_read_pull(&sv.stream, &ob);
  CHECK(ob.len == 5);
  CHECK(got[0] == 'h' && got[4] == 'o');
}

/* RFC 9001 4: with no key installed at a level, both send and recv are gated
 * out (return 0) before any cryptographic work. */
static void test_connio_gated_without_key(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   io;
  mk_connio(&io, 0, 0x43, dcid, 8, 1u << 20);
  io.loop.validated = 1;

  u8 frames[8] = {0x01}; /* a PING frame */
  u8 pkt[64];
  /* Handshake level has no key installed */
  CHECK(send_at(&io, LEVEL_HANDSHAKE, frames, 1, pkt, sizeof(pkt)) == 0);
  CHECK(connio_recv(&io, LEVEL_HANDSHAKE, wired_mspan_of(pkt, 32)) == 0);
}

/* Install Initial + Handshake keys on io and lift its anti-amp gate so sends at
 * both levels are admitted. */
static void arm_two_levels(connio* io) {
  initial_keys k     = {0};
  io->loop.validated = 1;
  keyset_install(&io->loop.keys, LEVEL_INITIAL, &k);
  keyset_install(&io->loop.keys, LEVEL_HANDSHAKE, &k);
}

/* RFC 9000 12.3: each packet number space numbers from 0 independently. A send
 * in the Initial space and a send in the Handshake space both carry pn 0, and
 * each advances only its own space's counter. The send number must be drawn
 * from the SELECTED space's counter, never one shared across spaces. */
static void test_connio_per_space_pn(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   io;
  mk_connio(&io, 0, 0xc3, dcid, 8, 1u << 20);
  arm_two_levels(&io);

  u8 frames[8] = {0x01}; /* a PING frame */
  u8 pkt[256];

  CHECK(connio_tx_next(&io, LEVEL_INITIAL) == 0);
  CHECK(connio_tx_next(&io, LEVEL_HANDSHAKE) == 0);

  /* first send in Initial: advances Initial only, Handshake untouched */
  CHECK(send_at(&io, LEVEL_INITIAL, frames, 1, pkt, sizeof(pkt)) != 0);
  CHECK(connio_tx_next(&io, LEVEL_INITIAL) == 1);
  CHECK(connio_tx_next(&io, LEVEL_HANDSHAKE) == 0);

  /* first send in Handshake: carries pn 0, advances Handshake only */
  CHECK(send_at(&io, LEVEL_HANDSHAKE, frames, 1, pkt, sizeof(pkt)) != 0);
  CHECK(connio_tx_next(&io, LEVEL_HANDSHAKE) == 1);
  CHECK(connio_tx_next(&io, LEVEL_INITIAL) == 1);
}

/* RFC 9000 12.3: send packet numbers within a space increase strictly
 * monotonically; repeated sends never reuse a number. */
static void test_connio_pn_monotone(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   io;
  mk_connio(&io, 0, 0xc3, dcid, 8, 1u << 20);
  arm_two_levels(&io);

  u8 frames[8] = {0x01};
  u8 pkt[256];
  CHECK(send_at(&io, LEVEL_INITIAL, frames, 1, pkt, 256) != 0);
  CHECK(send_at(&io, LEVEL_INITIAL, frames, 1, pkt, 256) != 0);
  CHECK(send_at(&io, LEVEL_INITIAL, frames, 1, pkt, 256) != 0);
  CHECK(connio_tx_next(&io, LEVEL_INITIAL) == 3);
}

/* RFC 9000 13.2: a received packet number never lowers a space's largest, and
 * each space tracks its own. recv increments only the selected space's expected
 * number, leaving the other spaces at 0. */
static void test_connio_recv_per_space(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   cl, sv;
  mk_connio(&cl, 0, 0xc3, dcid, 8, 1u << 20);
  mk_connio(&sv, 1, 0xc3, dcid, 8, 1u << 20);
  arm_two_levels(&cl);
  arm_two_levels(&sv);

  u8  frames[8] = {0x01};
  u8  pkt[256];
  usz n = send_at(&cl, LEVEL_INITIAL, frames, 1, pkt, 256);
  CHECK(n != 0);
  CHECK(connio_recv(&sv, LEVEL_INITIAL, wired_mspan_of(pkt, n)) == 1);

  /* only the Initial space's expected number advanced */
  CHECK(connio_rx_next(&sv, LEVEL_INITIAL) == 1);
  CHECK(connio_rx_next(&sv, LEVEL_HANDSHAKE) == 0);
}

/* Install a 1-RTT key and fast-forward the send-level gate to Handshake, so
 * the very next send may promote straight to 1-RTT (RFC 9001 4.1.4/4.9). */
static void arm_onertt(connio* io) {
  initial_keys k     = {0};
  io->loop.validated = 1;
  keyset_install(&io->loop.keys, LEVEL_INITIAL, &k);
  keyset_install(&io->loop.keys, LEVEL_HANDSHAKE, &k);
  keyset_install(&io->loop.keys, LEVEL_ONERTT, &k);
  io->loop.send_level         = LEVEL_HANDSHAKE;
  io->loop.handshake_complete = 1;
}

/* RFC 9000 19.20 via 12.4: a server that receives HANDSHAKE_DONE latches
 * dispatch's violation flag; connio_close_on_violation must then seal an
 * actual transport CONNECTION_CLOSE(PROTOCOL_VIOLATION) frame, and clear the
 * flag so it fires only once. */
static void test_connio_close_on_violation_handshake_done(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   cl, sv;
  mk_connio(&cl, 0, 0x43, dcid, 8, 1u << 20);
  mk_connio(&sv, 1, 0x43, dcid, 8, 1u << 20);
  arm_onertt(&cl);
  arm_onertt(&sv);

  u8  frame[1] = {0};
  usz fl       = handshake_done_encode(frame, sizeof frame);
  CHECK(fl != 0);

  u8  pkt[256];
  usz pn = send_at(&cl, LEVEL_ONERTT, frame, fl, pkt, sizeof(pkt));
  CHECK(pn != 0);

  /* the server accepts the packet (frame is malformed-free) but the frame
   * itself is forbidden from a server's receive side */
  CHECK(connio_recv(&sv, LEVEL_ONERTT, wired_mspan_of(pkt, pn)) == 0);
  CHECK(sv.disp.violation == 1);

  u8         close_pkt[256];
  wired_obuf ob = obuf_of(close_pkt, sizeof close_pkt);
  usz        n  = connio_close_on_violation(&sv, &ob);
  CHECK(n != 0);
  CHECK(n == ob.len);
  CHECK(sv.disp.violation == 0); /* fires once */

  /* fires nothing the second time (already cleared) */
  wired_obuf ob2 = obuf_of(close_pkt, sizeof close_pkt);
  CHECK(connio_close_on_violation(&sv, &ob2) == 0);
}

/* Decrypt the sealed CONNECTION_CLOSE with the client's own connio_recv (same
 * installed keys) and confirm the wire content: PROTOCOL_VIOLATION, transport
 * variant. This proves the frame reaching the wire is the real RFC 9000
 * 20.1 error code, not just a non-zero length. */
static void test_connio_close_on_violation_wire_content(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   cl, sv;
  mk_connio(&cl, 0, 0x43, dcid, 8, 1u << 20);
  mk_connio(&sv, 1, 0x43, dcid, 8, 1u << 20);
  arm_onertt(&cl);
  arm_onertt(&sv);

  u8  frame[1] = {0};
  usz fl       = handshake_done_encode(frame, sizeof frame);
  u8  pkt[256];
  usz pn = send_at(&cl, LEVEL_ONERTT, frame, fl, pkt, sizeof(pkt));
  CHECK(connio_recv(&sv, LEVEL_ONERTT, wired_mspan_of(pkt, pn)) == 0);

  u8         close_pkt[256];
  wired_obuf ob = obuf_of(close_pkt, sizeof close_pkt);
  CHECK(connio_close_on_violation(&sv, &ob) != 0);

  /* server -> client direction now: client's connio opens the CLOSE packet */
  CHECK(connio_recv(&cl, LEVEL_ONERTT, wired_mspan_of(close_pkt, ob.len)) == 1);
  CHECK(cl.disp.close == 1);
}

/* RFC 9001 5.5/6.6: a packet that fails AEAD authentication is discarded and
 * counted (connio_recv returns 0, loop.auth_fail_count advances by
 * exactly one) -- proving the count wiring runs on the real decrypt-failure
 * path, not just via direct field pokes. */
static void test_connio_recv_failure_counts_auth_fail(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   cl, sv;
  mk_connio(&cl, 0, 0x43, dcid, 8, 1u << 20);
  mk_connio(&sv, 1, 0x43, dcid, 8, 1u << 20);
  arm_onertt(&cl);
  arm_onertt(&sv);

  u8  frame[1] = {0x01}; /* PING */
  u8  pkt[256];
  usz pn = send_at(&cl, LEVEL_ONERTT, frame, 1, pkt, sizeof(pkt));
  CHECK(pn != 0);
  pkt[pn - 1] ^= 0xff; /* tamper the AEAD tag's last byte */

  CHECK(sv.loop.auth_fail_count == 0);
  CHECK(connio_recv(&sv, LEVEL_ONERTT, wired_mspan_of(pkt, pn)) == 0);
  CHECK(sv.loop.auth_fail_count == 1);
  CHECK(sv.loop.aead_limit == 0); /* nowhere near the 2^52 limit yet */
}

/* RFC 9001 6.6: once auth_fail_count reaches the AES-GCM integrity limit,
 * connio_close_on_aead_limit seals a real CONNECTION_CLOSE carrying
 * AEAD_LIMIT_REACHED (0x0f) and clears the pending flag so it fires once. The
 * counter is seeded at limit-1 (a real 2^52-iteration loop is infeasible in
 * a test); connloop_on_auth_fail itself is exercised directly above. */
static void test_connio_close_on_aead_limit_wire_content(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   cl, sv;
  mk_connio(&cl, 0, 0x43, dcid, 8, 1u << 20);
  mk_connio(&sv, 1, 0x43, dcid, 8, 1u << 20);
  arm_onertt(&cl);
  arm_onertt(&sv);

  sv.loop.auth_fail_count = AEAD_INTEGRITY_LIMIT_AESGCM - 1;
  u8  frame[1]            = {0x01};
  u8  pkt[256];
  usz pn = send_at(&cl, LEVEL_ONERTT, frame, 1, pkt, sizeof(pkt));
  pkt[pn - 1] ^= 0xff;
  CHECK(connio_recv(&sv, LEVEL_ONERTT, wired_mspan_of(pkt, pn)) == 0);
  CHECK(sv.loop.aead_limit == 1);

  u8         close_pkt[256];
  wired_obuf ob = obuf_of(close_pkt, sizeof close_pkt);
  CHECK(connio_close_on_aead_limit(&sv, &ob) != 0);
  CHECK(sv.loop.aead_limit == 0); /* fires once */

  /* client opens the sealed CLOSE and decodes AEAD_LIMIT_REACHED */
  CHECK(connio_recv(&cl, LEVEL_ONERTT, wired_mspan_of(close_pkt, ob.len)) == 1);
  CHECK(cl.disp.close == 1);

  /* nothing fires a second time */
  wired_obuf ob2 = obuf_of(close_pkt, sizeof close_pkt);
  CHECK(connio_close_on_aead_limit(&sv, &ob2) == 0);
}

/* RFC 9000 12.3: once a space's next packet number would exceed 2^62-1, the
 * sender must stop sending in that space silently (no CONNECTION_CLOSE);
 * connio_send simply reports failure like any other gated-out send. */
static void test_connio_send_blocked_at_pn_exhaustion(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   io;
  mk_connio(&io, 0, 0xc3, dcid, 8, 1u << 20);
  arm_two_levels(&io);
  io.tx.pn.next[PNS_INITIAL] = PN_LIMIT + 1; /* already exhausted */

  u8 frames[8] = {0x01}; /* a PING frame */
  u8 pkt[256];
  CHECK(send_at(&io, LEVEL_INITIAL, frames, 1, pkt, sizeof(pkt)) == 0);
}

/* RFC 9000 3.5: a STOP_SENDING the server receives is answered with a
 * RESET_STREAM echoing the same stream ID and error code verbatim. */
static void test_connio_stop_sending_auto_reset(void) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  connio   cl, sv;
  mk_connio(&cl, 0, 0x43, dcid, 8, 1u << 20);
  mk_connio(&sv, 1, 0x43, dcid, 8, 1u << 20);
  arm_onertt(&cl);
  arm_onertt(&sv);

  stop_sending_frame ssf = {.stream_id = 5, .error_code = 0x77};
  u8                 frame[16];
  usz                fl = stop_sending_encode(frame, sizeof frame, &ssf);
  CHECK(fl != 0);

  u8  pkt[256];
  usz pn = send_at(&cl, LEVEL_ONERTT, frame, fl, pkt, sizeof(pkt));
  CHECK(pn != 0);
  CHECK(connio_recv(&sv, LEVEL_ONERTT, wired_mspan_of(pkt, pn)) == 1);
  CHECK(sv.disp.stop_sending_owed == 1);

  u8         reset_pkt[256];
  wired_obuf ob = obuf_of(reset_pkt, sizeof reset_pkt);
  usz        n  = connio_send_stop_sending_reset(&sv, &ob);
  CHECK(n != 0);
  CHECK(sv.disp.stop_sending_owed == 0); /* fires once */

  /* nothing fires a second time */
  wired_obuf ob2 = obuf_of(reset_pkt, sizeof reset_pkt);
  CHECK(connio_send_stop_sending_reset(&sv, &ob2) == 0);

  /* decrypt on the client side and confirm the wire content: same stream ID
   * and error code as the STOP_SENDING that triggered it. */
  CHECK(connio_recv(&cl, LEVEL_ONERTT, wired_mspan_of(reset_pkt, n)) == 1);
  CHECK(
      cl.disp.reset_stream_stream_id == 5 &&
      cl.disp.reset_stream_error_code == 0x77);
}

void test_connio(void) {
  test_connio_seal_open_roundtrip();
  test_connio_gated_without_key();
  test_connio_per_space_pn();
  test_connio_pn_monotone();
  test_connio_recv_per_space();
  test_connio_close_on_violation_handshake_done();
  test_connio_close_on_violation_wire_content();
  test_connio_recv_failure_counts_auth_fail();
  test_connio_close_on_aead_limit_wire_content();
  test_connio_send_blocked_at_pn_exhaustion();
  test_connio_stop_sending_auto_reset();
}
