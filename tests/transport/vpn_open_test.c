#include "transport/packet/build/vpn/vpn_open.h"

#include "test.h"
#include "transport/packet/header/packet/pnum.h"
#include "transport/packet/protect/protect/protect.h"

/* Build a long-header Initial header ending in a pn_len-byte packet number at
 * pn_off, seal it, then re-open with quic_vpn_open. The full pn equals its
 * truncated wire bytes (small values), so a self-contained roundtrip holds. */
static void roundtrip(usz pn_len, u64 pn) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys keys;
  quic_aes128       hp;
  quic_initial_derive(quic_span_of(dcid, 8), 0, QUIC_VERSION_1, &keys);
  quic_aes128_init(&hp, keys.hp);

  /* byte0 = 0xc0 | (pn_len-1); fixed-length prefix then the pn at pn_off. */
  u8 hdr[20] = {
      (u8)(0xc0 | (pn_len - 1)),
      0,
      0,
      0,
      1,
      8,
      0x83,
      0x94,
      0xc8,
      0xf0,
      0x3e,
      0x51,
      0x57,
      0x08,
      0};
  usz pn_off = 15;
  quic_pnum_encode(hdr + pn_off, pn, pn_len);
  usz      hdr_len   = pn_off + pn_len;
  const u8 payload[] = {0x06, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};

  u8                   pkt[80];
  quic_protect_keys    k   = {&keys, &hp};
  quic_protect_seal_io sio = {
      quic_span_of(hdr, hdr_len),
      pn_off,
      pn_len,
      pn,
      quic_span_of(payload, sizeof(payload)),
      quic_mspan_of(pkt, sizeof(pkt))};
  usz total = quic_protect_seal(&k, &sio);
  CHECK(total == hdr_len + sizeof(payload) + 16);

  u64           length = pn_len + sizeof(payload) + 16;
  quic_span     out;
  quic_vpn_desc vd = {quic_mspan_of(pkt, total), pn_off, length};
  CHECK(quic_vpn_open(&k, &vd, &out));
  CHECK(pkt[0] == (u8)(0xc0 | (pn_len - 1))); /* byte0 unmasked -> pn_len */
  CHECK((pkt[0] & 0x03) + 1 == pn_len);
  CHECK(out.n == sizeof(payload));
  for (usz i = 0; i < sizeof(payload); i++) CHECK(out.p[i] == payload[i]);
}

static void test_vpn_roundtrip_lengths(void) {
  roundtrip(1, 0x12);
  roundtrip(2, 0x1234);
  roundtrip(4, 0x12345678);
}

/* Tag tamper makes open fail. */
static void test_vpn_tamper(void) {
  const u8          dcid[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  quic_initial_keys keys;
  quic_aes128       hp;
  quic_initial_derive(quic_span_of(dcid, 8), 0, QUIC_VERSION_1, &keys);
  quic_aes128_init(&hp, keys.hp);
  u8 hdr[18] = {0xc1, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0x12, 0x34};
  const u8             payload[] = {1, 2, 3, 4};
  u8                   pkt[64];
  quic_protect_keys    k   = {&keys, &hp};
  quic_protect_seal_io sio = {
      quic_span_of(hdr, 18),
      16,
      2,
      0x1234,
      quic_span_of(payload, sizeof(payload)),
      quic_mspan_of(pkt, sizeof(pkt))};
  usz total = quic_protect_seal(&k, &sio);
  pkt[total - 1] ^= 0x80; /* flip a tag bit */
  quic_span     out;
  u64           length = 2 + sizeof(payload) + 16;
  quic_vpn_desc vd     = {quic_mspan_of(pkt, total), 16, length};
  CHECK(quic_vpn_open(&k, &vd, &out) == 0);
}

/* A pn_len=4 packet sealed by the existing protect path opens via vpn_open. */
static void test_vpn_protect_compat(void) {
  const u8          dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_keys keys;
  quic_aes128       hp;
  quic_initial_derive(quic_span_of(dcid, 8), 0, QUIC_VERSION_1, &keys);
  quic_aes128_init(&hp, keys.hp);
  u8       hdr[18]   = {0xc3, 0,    0,    0,    1,    8, 0x83, 0x94, 0xc8,
                        0xf0, 0x3e, 0x51, 0x57, 0x08, 0, 0,    0,    2};
  const u8 payload[] = {0x06, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'};
  u8       pkt[64];
  quic_protect_keys    k   = {&keys, &hp};
  quic_protect_seal_io sio = {
      quic_span_of(hdr, 18),
      14,
      4,
      2,
      quic_span_of(payload, sizeof(payload)),
      quic_mspan_of(pkt, sizeof(pkt))};
  usz           total = quic_protect_seal(&k, &sio);
  quic_span     out;
  u64           length = 4 + sizeof(payload) + 16;
  quic_vpn_desc vd     = {quic_mspan_of(pkt, total), 14, length};
  CHECK(quic_vpn_open(&k, &vd, &out));
  CHECK(out.n == sizeof(payload));
  for (usz i = 0; i < sizeof(payload); i++) CHECK(out.p[i] == payload[i]);
}

void test_vpn_open(void) {
  test_vpn_roundtrip_lengths();
  test_vpn_tamper();
  test_vpn_protect_compat();
}
