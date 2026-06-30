#include "test.h"

static void onertt_keys(quic_initial_keys *k, quic_aes128 *hp) {
  const u8 dcid[8] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};
  quic_initial_derive(dcid, 8, 1, k);
  quic_aes128_init(hp, k->hp);
}

/* RFC 9000 17.3 / RFC 9001 5: build a 1-RTT packet, then open it with the
 * same keys; the payload comes back byte-for-byte. */
static void test_onertt_roundtrip(void) {
  quic_initial_keys k;
  quic_aes128       hp;
  const u8          dcid[5] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  const u8 frames[] = {0x08, 'd', 'a', 't', 'a'}; /* STREAM-ish payload */
  onertt_keys(&k, &hp);

  u8  pkt[64];
  usz total = 0;
  CHECK(quic_hspkt_onertt_build(
      &k, &hp, dcid, 5, 12, frames, sizeof(frames), pkt, sizeof(pkt), &total));
  CHECK(total == 5u + 5u + sizeof(frames) + 16u); /* byte0+dcid+pn + ct + tag */

  const u8 *out  = 0;
  usz       olen = 0;
  CHECK(quic_hspkt_onertt_open(&k, &hp, pkt, total, 5, 0, &out, &olen));
  CHECK(olen == sizeof(frames));
  for (usz i = 0; i < sizeof(frames); i++) CHECK(out[i] == frames[i]);
}

/* RFC 9000 17.3: short-header form has the high bit of byte0 clear. After
 * header protection the low 5 bits are masked, but the high bit stays 0. */
static void test_onertt_byte0(void) {
  quic_initial_keys k;
  quic_aes128       hp;
  const u8          dcid[4]  = {1, 2, 3, 4};
  const u8          frames[] = {0x08, 'X'};
  onertt_keys(&k, &hp);

  u8  pkt[64];
  usz total = 0;
  CHECK(quic_hspkt_onertt_build(
      &k, &hp, dcid, 4, 1, frames, sizeof(frames), pkt, sizeof(pkt), &total));
  CHECK((pkt[0] & 0x80) == 0x00); /* short header form */
}

/* A tampered ciphertext byte makes open fail (AEAD authentication). */
static void test_onertt_tamper(void) {
  quic_initial_keys k;
  quic_aes128       hp;
  const u8          dcid[4]  = {9, 8, 7, 6};
  const u8          frames[] = {0x08, 'h', 'i'};
  onertt_keys(&k, &hp);

  u8  pkt[64];
  usz total = 0;
  CHECK(quic_hspkt_onertt_build(
      &k, &hp, dcid, 4, 5, frames, sizeof(frames), pkt, sizeof(pkt), &total));
  pkt[total - 1] ^= 0x01;
  const u8 *out  = 0;
  usz       olen = 0;
  CHECK(!quic_hspkt_onertt_open(&k, &hp, pkt, total, 4, 0, &out, &olen));
}

/* Seal a 1-RTT packet whose packet number is TRUNCATED to pn_len bytes (curl
 * does this: a non-zero PN sent in 1-2 bytes). The AEAD nonce uses the FULL pn,
 * the header carries only its low pn_len bytes. Mirrors onertt_build but with a
 * short PN. RFC 9000 17.3 / A.2, RFC 9001 5.3/5.4. */
static usz seal_truncated(
    const quic_initial_keys *k,
    const quic_aes128       *hp,
    const u8                *dcid,
    u8                       dcid_len,
    u64                      full_pn,
    usz                      pn_len,
    const u8                *pl,
    usz                      pl_len,
    u8                      *out) {
  u8          nonce[QUIC_INITIAL_IV], mask[5];
  quic_aes128 aead;
  usz         pn_off  = 1u + dcid_len;
  usz         hdr_len = pn_off + pn_len;
  usz         i;
  out[0] = 0x40u | (u8)(pn_len - 1u); /* short header, fixed bit, pn length */
  for (i = 0; i < dcid_len; i++) out[1 + i] = dcid[i];
  quic_pnum_encode(out + pn_off, full_pn, pn_len);
  quic_protect_nonce(k->iv, full_pn, nonce);
  quic_aes128_init(&aead, k->key);
  quic_gcm_seal(
      &aead, nonce, out, hdr_len, pl, pl_len, out + hdr_len,
      out + hdr_len + pl_len);
  quic_hp_mask(hp, out + pn_off + 4, mask);
  quic_hp_apply(mask, &out[0], out + pn_off, pn_len, QUIC_HP_SHORT_MASK);
  return hdr_len + pl_len + QUIC_GCM_TAG;
}

/* RFC 9000 A.3: a 1-RTT packet sealed with a non-zero PN that is truncated to
 * one byte opens only when the receiver recovers the FULL packet number from
 * largest_pn before building the nonce. The truncated header byte (44) differs
 * from the real PN (300); decoding against largest_pn=299 lifts it back to 300
 * so the nonce matches. With largest_pn=0 the recovery yields 44 and open
 * fails — proving the recovery, not the truncated value, is what authenticates.
 */
static void test_onertt_truncated_pn(void) {
  quic_initial_keys k;
  quic_aes128       hp;
  const u8          dcid[5]  = {0xaa, 0xbb, 0xcc, 0xdd, 0xee};
  const u8          frames[] = {0x08, 'c', 'u', 'r', 'l'};
  u8                pkt[64];
  const u8         *out  = 0;
  usz               olen = 0, total;
  onertt_keys(&k, &hp);

  total = seal_truncated(&k, &hp, dcid, 5, 300, 1, frames, sizeof frames, pkt);
  /* truncated byte (300 & 0xff == 44) != real PN 300, so largest_pn matters */
  CHECK(quic_hspkt_onertt_open(&k, &hp, pkt, total, 5, 299, &out, &olen));
  CHECK(olen == sizeof frames);
  for (usz i = 0; i < sizeof frames; i++) CHECK(out[i] == frames[i]);

  /* Without the right baseline the recovered PN is 44, the nonce is wrong,
   * and authentication fails — confirms the test exercises PN recovery. */
  total = seal_truncated(&k, &hp, dcid, 5, 300, 1, frames, sizeof frames, pkt);
  CHECK(!quic_hspkt_onertt_open(&k, &hp, pkt, total, 5, 0, &out, &olen));
}

void test_onertt(void) {
  test_onertt_roundtrip();
  test_onertt_byte0();
  test_onertt_tamper();
  test_onertt_truncated_pn();
}
