#include "test.h"

static void app_keys(initial_keys* k, aes128* hp) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  initial_derive(wired_span_of(dcid, 8), 1, VERSION_1, k);
  aes128_init(hp, k->hp);
}

/* RFC 9001 5 / RFC 9000 19.8: app_send seals a STREAM frame in a 1-RTT
 * packet; app_recv opens it and recovers stream id, fin, and bytes. */
static void test_app_roundtrip(void) {
  initial_keys k;
  aes128       hp;
  const u8     dcid[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  const u8     body[]  = {'H', 'T', 'T', 'P', '/', '3'};
  app_keys(&k, &hp);

  u8  pkt[128];
  usz total = 0;
  CHECK(appdata_send_flat(
      &k, &hp, dcid, 5, 42, 4, body, sizeof(body), 1, pkt, sizeof(pkt),
      &total));

  u64       sid = 0, off = 99;
  const u8* data = 0;
  usz       dlen = 0;
  int       fin  = 0;
  CHECK(appdata_recv_flat(
      &k, &hp, pkt, total, 5, &sid, &off, &data, &dlen, &fin));
  CHECK(sid == 4);
  CHECK(off == 0);
  CHECK(fin == 1);
  CHECK(dlen == sizeof(body));
  for (usz i = 0; i < sizeof(body); i++) {
    CHECK(data[i] == body[i]);
  }
}

/* A tampered ciphertext byte makes recv fail (AEAD authentication). */
static void test_app_tamper(void) {
  initial_keys k;
  aes128       hp;
  const u8     dcid[4] = {9, 8, 7, 6};
  const u8     body[]  = {'a', 'b', 'c'};
  app_keys(&k, &hp);

  u8  pkt[128];
  usz total = 0;
  CHECK(appdata_send_flat(
      &k, &hp, dcid, 4, 5, 0, body, sizeof(body), 0, pkt, sizeof(pkt), &total));
  pkt[total - 1] ^= 0x01;

  u64       sid = 0, off = 0;
  const u8* data = 0;
  usz       dlen = 0;
  int       fin  = 0;
  CHECK(!appdata_recv_flat(
      &k, &hp, pkt, total, 4, &sid, &off, &data, &dlen, &fin));
}

/* RFC 9000 19.8: data filling the whole 1500-byte frame scratch leaves no
 * room for the STREAM header, so nothing is sealed even with a big out. */
static void test_app_send_frame_too_big(void) {
  initial_keys    k;
  aes128          hp;
  static const u8 dcid[4]    = {1, 2, 3, 4};
  static const u8 data[1500] = {0};
  static u8       pkt[2048];
  protect_keys    pk = {&k, &hp};
  appdata_tx      tx = {
      wired_span_of(dcid, 4), 1, 0, wired_span_of(data, sizeof data), 0};
  wired_obuf ob = obuf_of(pkt, sizeof pkt);
  app_keys(&k, &hp);
  CHECK(appdata_send(&pk, &tx, &ob) == 0);
}

void test_app_send(void) {
  test_app_roundtrip();
  test_app_tamper();
  test_app_send_frame_too_big();
}
