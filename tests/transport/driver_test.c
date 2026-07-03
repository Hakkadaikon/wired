#include "transport/conn/loop/driver/driver.h"

#include "test.h"

/* Shuttle one datagram from `from`'s outbox to `to`'s inbox, if any was
 * produced. Returns 1 if a datagram moved. */
static int pump(quic_driver *from, quic_driver *to) {
  u8  dg[QUIC_DRIVER_DGRAM_CAP];
  usz n = quic_driver_take(from, dg, sizeof(dg));
  if (n == 0) return 0;
  quic_driver_feed(to, dg, n);
  return 1;
}

/* RFC 9000 4 / RFC 9001 4: two drivers connected by an in-memory link reach a
 * complete handshake. Each round: both step (recv queued + seal next), then
 * datagrams are shuttled across. This exercises the real connio seal/open
 * round-trip, hsdriver order, and keyschedule key derivation in concert. */
static void test_driver_handshake_completes(void) {
  const u8    dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_driver cl, sv;
  int         round;
  quic_driver_init(&cl, 0, quic_span_of(dcid, 8));
  quic_driver_init(&sv, 1, quic_span_of(dcid, 8));

  for (round = 0; round < 32; round++) {
    quic_driver_step(&cl);
    quic_driver_step(&sv);
    pump(&cl, &sv);
    pump(&sv, &cl);
    if (quic_driver_handshake_complete(&cl) &&
        quic_driver_handshake_complete(&sv))
      break;
  }
  CHECK(quic_driver_handshake_complete(&cl) == 1);
  CHECK(quic_driver_handshake_complete(&sv) == 1);
  /* both promoted past Initial: 1-RTT keys were installed (RFC 9001 4) */
  CHECK(cl.io.loop.keys.installed[QUIC_LEVEL_ONERTT] == 1);
  CHECK(sv.io.loop.keys.installed[QUIC_LEVEL_ONERTT] == 1);
}

/* RFC 9001 4: a packet at a level whose key is not installed is dropped and
 * advances no handshake state (receive-path level gate). */
static void test_driver_rejects_uninstalled_level(void) {
  const u8    dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_driver cl, sv;
  u8          dg[QUIC_DRIVER_DGRAM_CAP];
  usz         n;
  quic_driver_init(&cl, 0, quic_span_of(dcid, 8));
  quic_driver_init(&sv, 1, quic_span_of(dcid, 8));

  /* server sends its first flight (ServerHello, Initial) but the client has
   * not yet sent ClientHello, so its order position expects ClientHello,
   * not ServerHello: feed a Handshake-level datagram the client cannot open
   * (no Handshake key) and confirm no progress. */
  quic_driver_step(&cl); /* client emits ClientHello */
  n = quic_driver_take(&cl, dg, sizeof(dg));
  CHECK(n != 0);
  quic_driver_feed(&sv, dg, n);
  quic_driver_step(&sv); /* server consumes ClientHello */
  quic_driver_step(&sv); /* server emits ServerHello */
  /* hand the ServerHello datagram back to the client but mislabel nothing:
   * the client has Handshake keys only after it processes ServerHello, so a
   * later Handshake-level packet fed before that is dropped. */
  n = quic_driver_take(&sv, dg, sizeof(dg));
  CHECK(n != 0);
  /* corrupt: feed at a position the client is not ready to open by clearing
   * its Handshake key explicitly, then attempt recv. */
  cl.io.loop.keys.installed[QUIC_LEVEL_HANDSHAKE] = 0;
  quic_driver_feed(&cl, dg, n);
  /* ServerHello is Initial-level so it still opens; instead verify the gate
   * directly: a recv at an uninstalled level returns 0 (no state change). */
  CHECK(
      quic_connio_recv(&cl.io, QUIC_LEVEL_HANDSHAKE, quic_mspan_of(dg, n)) ==
      0);
  CHECK(cl.io.loop.keys.installed[QUIC_LEVEL_HANDSHAKE] == 0);
}

/* ponytail: run's max_steps guard halts a driver that can never progress
 * (no peer to answer), proving the diverge guard (RFC 9000 4). */
static void test_driver_run_halts_at_max(void) {
  const u8    dcid[4] = {1, 2, 3, 4};
  quic_driver cl;
  usz         steps;
  quic_driver_init(&cl, 0, quic_span_of(dcid, 4));
  /* client alone: sends ClientHello, then stalls waiting for ServerHello.
   * run must stop, not spin, capped by max_steps. */
  steps = quic_driver_run(&cl, 5);
  CHECK(quic_driver_handshake_complete(&cl) == 0);
  CHECK(steps <= 5);
}

void test_driver(void) {
  test_driver_handshake_completes();
  test_driver_rejects_uninstalled_level();
  test_driver_run_halts_at_max();
}

#ifdef DRIVER_TEST_MAIN
int main(void) {
  test_driver();
  return TEST_REPORT();
}
#endif
