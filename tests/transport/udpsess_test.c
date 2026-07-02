#include "test.h"

/* A fresh session sends to the transport's original peer on path 0. */
static void test_udpsess_init_active_path(void) {
  quic_udp_transport t;
  quic_udpsess       s;
  static const u8    dcid0[3] = {1, 2, 3};
  t.fd                        = -1;
  t.peer_addr                 = 0x0a000001; /* 10.0.0.1 */
  t.peer_port                 = 4433;
  quic_udpsess_init(&s, &t, quic_span_of(dcid0, 3));
  CHECK(s.active == 0);
  CHECK(s.paths[0].peer_addr == 0x0a000001 && s.paths[0].peer_port == 4433);
  CHECK(s.paths[0].dcid == dcid0 && s.paths[0].dcid_len == 3);
}

/* RFC 9000 9.3: setting a candidate peer does not change the active target. */
static void test_udpsess_set_peer_keeps_old(void) {
  quic_udp_transport t;
  quic_udpsess       s;
  static const u8    dcid0[1] = {9};
  t.fd                        = -1;
  t.peer_addr                 = 0x0a000001;
  t.peer_port                 = 4433;
  quic_udpsess_init(&s, &t, quic_span_of(dcid0, 1));
  quic_udpsess_set_peer(&s, 1, &(quic_udpsess_peer){0x0b000002, 5555});
  CHECK(s.active == 0);             /* still old path */
  CHECK(t.peer_addr == 0x0a000001); /* transport untouched */
  CHECK(s.paths[1].peer_addr == 0x0b000002 && s.paths[1].peer_port == 5555);
}

/* RFC 9000 9.3: migration is gated on the new path being validated. */
static void test_udpsess_migrate_gate(void) {
  quic_udp_transport t;
  quic_udpsess       s;
  static const u8    dcid0[1] = {9};
  t.fd                        = -1;
  t.peer_addr                 = 0x0a000001;
  t.peer_port                 = 4433;
  quic_udpsess_init(&s, &t, quic_span_of(dcid0, 1));
  quic_udpsess_set_peer(&s, 1, &(quic_udpsess_peer){0x0b000002, 5555});
  CHECK(quic_udpsess_can_migrate(&s, 0) == 0);
  CHECK(quic_udpsess_can_migrate(&s, 1) == 1);
  CHECK(quic_udpsess_migrate(&s, 1, 0) == 0); /* unvalidated: refused */
  CHECK(s.active == 0 && t.peer_addr == 0x0a000001);
}

/* RFC 9000 9.3: once validated, migration switches the transport send target.
 */
static void test_udpsess_migrate_switches_target(void) {
  quic_udp_transport t;
  quic_udpsess       s;
  static const u8    dcid0[1] = {9};
  t.fd                        = -1;
  t.peer_addr                 = 0x0a000001;
  t.peer_port                 = 4433;
  quic_udpsess_init(&s, &t, quic_span_of(dcid0, 1));
  quic_udpsess_set_peer(&s, 1, &(quic_udpsess_peer){0x0b000002, 5555});
  CHECK(quic_udpsess_migrate(&s, 1, 1) == 1);
  CHECK(s.active == 1);
  CHECK(t.peer_addr == 0x0b000002 && t.peer_port == 5555);
}

/* RFC 9000 9.3: a validated path with no peer address cannot be migrated to. */
static void test_udpsess_migrate_needs_peer(void) {
  quic_udp_transport t;
  quic_udpsess       s;
  static const u8    dcid0[1] = {9};
  t.fd                        = -1;
  t.peer_addr                 = 0x0a000001;
  t.peer_port                 = 4433;
  quic_udpsess_init(&s, &t, quic_span_of(dcid0, 1));
  CHECK(quic_udpsess_migrate(&s, 1, 1) == 0); /* path 1 peer unset */
  CHECK(s.active == 0);
}

/* RFC 9000 9.5: each path exposes its own destination CID. */
static void test_udpsess_dcid_per_path(void) {
  quic_udp_transport t;
  quic_udpsess       s;
  static const u8    dcid0[2] = {1, 2};
  static const u8    dcid1[3] = {7, 8, 9};
  quic_span           out;
  t.fd        = -1;
  t.peer_addr = 0x0a000001;
  t.peer_port = 4433;
  quic_udpsess_init(&s, &t, quic_span_of(dcid0, 2));
  quic_udpsess_set_dcid(&s, 1, quic_span_of(dcid1, 3));
  CHECK(quic_udpsess_dcid_for_path(&s, 0, &out) == 1);
  CHECK(out.p == dcid0 && out.n == 2);
  CHECK(quic_udpsess_dcid_for_path(&s, 1, &out) == 1);
  CHECK(out.p == dcid1 && out.n == 3);
}

/* An out-of-range or unset path yields no DCID. */
static void test_udpsess_dcid_unset(void) {
  quic_udp_transport t;
  quic_udpsess       s;
  static const u8    dcid0[1] = {5};
  quic_span           out;
  t.fd        = -1;
  t.peer_addr = 0x0a000001;
  t.peer_port = 4433;
  quic_udpsess_init(&s, &t, quic_span_of(dcid0, 1));
  CHECK(quic_udpsess_dcid_for_path(&s, 1, &out) == 0); /* unset */
  CHECK(quic_udpsess_dcid_for_path(&s, 2, &out) == 0); /* out of range */
}

void test_udpsess(void) {
  test_udpsess_init_active_path();
  test_udpsess_set_peer_keeps_old();
  test_udpsess_migrate_gate();
  test_udpsess_migrate_switches_target();
  test_udpsess_migrate_needs_peer();
  test_udpsess_dcid_per_path();
  test_udpsess_dcid_unset();
}
