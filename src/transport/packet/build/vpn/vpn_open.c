#include "transport/packet/build/vpn/vpn_open.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hpapply.h"
#include "transport/packet/protect/hp/hpsample.h"

/* RFC 9001 5.4.1: pn_len lives in byte0's low two bits once unmasked. */
static usz pn_len_of(u8 byte0) { return (usz)(byte0 & 0x03) + 1; }

/* RFC 9000 17.1: read the recovered pn_len-byte packet number big-endian. */
static u64 read_pn(const u8* pn, usz pn_len) {
  u64 v = 0;
  for (usz i = 0; i < pn_len; i++) v = (v << 8) | pn[i];
  return v;
}

/* True if the sample and the [pn_off, pn_off+length) region fit in pkt. */
static int region_ok(const quic_vpn_desc* d) {
  usz sample = quic_hp_sample_offset(d->pn_off);
  if (!quic_hp_sample_ok(d->pkt.n, sample)) return 0;
  /* pn_off <= pkt.n (parse invariant), so pkt.n - pn_off cannot underflow;
   * this form rejects a huge attacker Length that would overflow
   * pn_off + length. */
  return d->length >= 4 + QUIC_GCM_TAG && d->length <= d->pkt.n - d->pn_off;
}

/* RFC 9001 5.4.1: unmask byte0, then the pn bytes; returns recovered pn. */
static u64 remove_hp(
    const quic_aes128* hp, const quic_vpn_desc* d, usz* pn_len) {
  u8  mask[5];
  u8* pkt = d->pkt.p;
  quic_hp_mask(hp, pkt + quic_hp_sample_offset(d->pn_off), mask);
  pkt[0] ^= mask[0] & QUIC_HP_LONG_MASK;
  *pn_len = pn_len_of(pkt[0]);
  quic_hp_protect_pn(pkt + d->pn_off, *pn_len, mask);
  return read_pn(pkt + d->pn_off, *pn_len);
}

/* Header length, ciphertext length, and recovered full packet number. */
typedef struct {
  usz hdr_len;
  usz ct_len;
  u64 pn;
} vpnopen_dims;

/* RFC 9001 5.3: nonce = iv XOR pn, then AEAD-open ct after the header. */
static int vpn_aead_open(
    const quic_initial_keys* keys, u8* pkt, const vpnopen_dims* v) {
  u8          nonce[QUIC_INITIAL_IV];
  quic_aes128 aead;
  quic_protect_nonce(keys->iv, v->pn, nonce);
  quic_aes128_init(&aead, keys->key);
  quic_gcm_ctx g = {&aead, nonce, {pkt, v->hdr_len}};
  return quic_gcm_open(
      &g, quic_span_of(pkt + v->hdr_len, v->ct_len + QUIC_GCM_TAG),
      pkt + v->hdr_len);
}

/* RFC 9001 5.4.1/5.3 */
int quic_vpn_open(
    const quic_protect_keys* k, const quic_vpn_desc* d, quic_span* payload) {
  usz          pn_len;
  vpnopen_dims v;
  if (!region_ok(d)) return 0;
  v.pn      = remove_hp(k->hp, d, &pn_len);
  v.hdr_len = d->pn_off + pn_len;
  v.ct_len  = (usz)d->length - pn_len - QUIC_GCM_TAG;
  if (!vpn_aead_open(k->keys, d->pkt.p, &v)) return 0;
  *payload = quic_span_of(d->pkt.p + v.hdr_len, v.ct_len);
  return 1;
}
