#include "transport/packet/build/vpn/vpn_open.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hpapply.h"
#include "transport/packet/protect/hp/hpsample.h"
#include "transport/packet/protect/protect/protect.h"

/* RFC 9001 5.4.1: pn_len lives in byte0's low two bits once unmasked. */
static usz pn_len_of(u8 byte0) { return (usz)(byte0 & 0x03) + 1; }

/* RFC 9000 17.1: read the recovered pn_len-byte packet number big-endian. */
static u64 read_pn(const u8 *pn, usz pn_len) {
  u64 v = 0;
  for (usz i = 0; i < pn_len; i++) v = (v << 8) | pn[i];
  return v;
}

/* True if the sample and the [pn_off, pn_off+length) region fit in pkt. */
static int region_ok(usz len, usz pn_off, u64 length) {
  usz sample = quic_hp_sample_offset(pn_off);
  if (!quic_hp_sample_ok(len, sample)) return 0;
  /* pn_off <= len (parse invariant), so len - pn_off cannot underflow; this
   * form rejects a huge attacker Length that would overflow pn_off + length. */
  return length >= 4 + QUIC_GCM_TAG && length <= len - pn_off;
}

/* RFC 9001 5.4.1: unmask byte0, then the pn bytes; returns recovered pn. */
static u64 remove_hp(const quic_aes128 *hp, u8 *pkt, usz pn_off, usz *pn_len) {
  u8 mask[5];
  quic_hp_mask(hp, pkt + quic_hp_sample_offset(pn_off), mask);
  pkt[0] ^= mask[0] & QUIC_HP_LONG_MASK;
  *pn_len = pn_len_of(pkt[0]);
  quic_hp_protect_pn(pkt + pn_off, *pn_len, mask);
  return read_pn(pkt + pn_off, *pn_len);
}

/* RFC 9001 5.3: nonce = iv XOR pn, then AEAD-open ct after the header. */
static int vpn_aead_open(
    const quic_initial_keys *keys, u8 *pkt, usz hdr_len, usz ct_len, u64 pn) {
  u8          nonce[QUIC_INITIAL_IV];
  quic_aes128 aead;
  quic_protect_nonce(keys->iv, pn, nonce);
  quic_aes128_init(&aead, keys->key);
  quic_gcm_ctx g = {&aead, nonce, {pkt, hdr_len}};
  return quic_gcm_open(
      &g, quic_span_of(pkt + hdr_len, ct_len + QUIC_GCM_TAG), pkt + hdr_len);
}

/* RFC 9001 5.4.1/5.3 */
int quic_vpn_open(
    const quic_initial_keys *keys,
    const quic_aes128       *hp,
    u8                      *pkt,
    usz                      len,
    usz                      pn_off,
    u64                      length,
    const u8               **payload,
    usz                     *payload_len) {
  usz pn_len, hdr_len, ct_len;
  u64 pn;
  if (!region_ok(len, pn_off, length)) return 0;
  pn      = remove_hp(hp, pkt, pn_off, &pn_len);
  hdr_len = pn_off + pn_len;
  ct_len  = (usz)length - pn_len - QUIC_GCM_TAG;
  if (!vpn_aead_open(keys, pkt, hdr_len, ct_len, pn)) return 0;
  *payload     = pkt + hdr_len;
  *payload_len = ct_len;
  return 1;
}
