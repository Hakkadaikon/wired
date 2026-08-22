#include "test.h"

/* Derive a pair of Handshake-level keys (same type as Initial keys; the
 * derivation label differs in production but the codec is identical). */
static void hspkt_keys(initial_keys* k, aes128* hp) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  initial_derive(wired_span_of(dcid, 8), 1, VERSION_1, k); /* server side */
  aes128_init(hp, k->hp);
}

/* RFC 9000 17.2.4 / RFC 9001 5: build a Handshake packet, then open it with
 * the same keys; the CRYPTO payload comes back byte-for-byte. */
static void test_hspkt_build_roundtrip(void) {
  initial_keys k;
  aes128       hp;
  const u8     dcid[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  const u8     scid[3] = {0x01, 0x02, 0x03};
  /* CRYPTO frame (type 0x06) carrying "EE" (EncryptedExtensions stand-in) */
  const u8 frames[] = {0x06, 0x00, 0x02, 'E', 'E'};
  hspkt_keys(&k, &hp);

  u8           pkt[128];
  protect_keys pk = {&k, &hp};
  hspkt_desc   d  = {
      wired_span_of(dcid, 5), wired_span_of(scid, 3), 9,
      wired_span_of(frames, sizeof(frames)), 0};
  wired_obuf o = obuf_of(pkt, sizeof(pkt));
  CHECK(hspkt_build(&pk, &d, &o));
  /* RFC 9000 17.2.4 complete header: byte0(1)+version(4)+dcid_len(1)+dcid(5)
   * +scid_len(1)+scid(3)+Length(1-byte varint)+pn(4) = 20, then payload+tag.
   * No Token field for Handshake. */
  CHECK(o.len == 20u + sizeof(frames) + 16u);

  wired_span out;
  CHECK(hspkt_open(&pk, wired_mspan_of(pkt, o.len), 0, &out));
  CHECK(out.n == sizeof(frames));
  for (usz i = 0; i < sizeof(frames); i++) CHECK(out.p[i] == frames[i]);
}

/* RFC 9000 17.2: long-header form (high bit set) with Handshake type bits
 * (5-4 = 0b10). After header protection the low 4 bits are masked, but the
 * top nibble (0b1110) is in the clear. */
static void test_hspkt_build_byte0(void) {
  initial_keys k;
  aes128       hp;
  const u8     dcid[4]  = {1, 2, 3, 4};
  const u8     frames[] = {0x06, 0x00, 0x01, 'X'};
  hspkt_keys(&k, &hp);

  u8           pkt[128];
  protect_keys pk = {&k, &hp};
  hspkt_desc   d  = {
      wired_span_of(dcid, 4), wired_span_of((const u8*)0, 0), 1,
      wired_span_of(frames, sizeof(frames)), 0};
  wired_obuf o = obuf_of(pkt, sizeof(pkt));
  CHECK(hspkt_build(&pk, &d, &o));
  CHECK((pkt[0] & 0x80) == 0x80); /* long header form */
  CHECK((pkt[0] & 0x30) == 0x20); /* type bits = Handshake (0x2) */
}

/* A tampered ciphertext byte makes open fail (AEAD authentication). */
static void test_hspkt_build_tamper(void) {
  initial_keys k;
  aes128       hp;
  const u8     dcid[4]  = {9, 8, 7, 6};
  const u8     frames[] = {0x06, 0x00, 0x02, 'h', 'i'};
  hspkt_keys(&k, &hp);

  u8           pkt[128];
  protect_keys pk = {&k, &hp};
  hspkt_desc   d  = {
      wired_span_of(dcid, 4), wired_span_of((const u8*)0, 0), 3,
      wired_span_of(frames, sizeof(frames)), 0};
  wired_obuf o = obuf_of(pkt, sizeof(pkt));
  CHECK(hspkt_build(&pk, &d, &o));
  pkt[o.len - 1] ^= 0x01;
  wired_span out;
  CHECK(!hspkt_open(&pk, wired_mspan_of(pkt, o.len), 0, &out));
}

void test_hspkt_build(void) {
  test_hspkt_build_roundtrip();
  test_hspkt_build_byte0();
  test_hspkt_build_tamper();
}
