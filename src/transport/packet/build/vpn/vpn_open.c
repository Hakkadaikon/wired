#include "transport/packet/build/vpn/vpn_open.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "tls/handshake/core/tls/aead_params.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hpapply.h"
#include "transport/packet/protect/hp/hpsample.h"
#include "transport/packet/protect/protect_suite/aead_suite.h"
#include "transport/packet/protect/protect_suite/hp_suite.h"

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

/* Suite-aware RFC 9001 5.4.1: unmask byte0, then the pn bytes, using
 * keys->hp's raw bytes under suite (AES-ECB or ChaCha20, RFC 9001 5.4.3).
 * Returns 0 on an unrecognized suite. */
static int remove_hp_suite(
    u16 suite, const u8* hp_key, const quic_vpn_desc* d, usz* pn_len) {
  u8  mask[5];
  u8* pkt = d->pkt.p;
  if (!quic_hp_suite_mask(
          suite, hp_key, pkt + quic_hp_sample_offset(d->pn_off), mask))
    return 0;
  pkt[0] ^= mask[0] & QUIC_HP_LONG_MASK;
  *pn_len = pn_len_of(pkt[0]);
  quic_hp_protect_pn(pkt + d->pn_off, *pn_len, mask);
  return 1;
}

/* AEAD-open ct after the header, under the negotiated suite. op.iv is the
 * raw key IV (quic_aead_suite_open derives the nonce itself: iv XOR pn, RFC
 * 9001 5.3), not a precomputed nonce. */
static int vpn_aead_open_suite(
    u16 suite, const quic_initial_keys* keys, u8* pkt, const vpnopen_dims* v) {
  quic_aead_suite_op op = {
      suite, keys->key, keys->iv, v->pn, {pkt, v->hdr_len}};
  return quic_aead_suite_open(
             &op, quic_span_of(pkt + v->hdr_len, v->ct_len),
             pkt + v->hdr_len) != 0;
}

/* d->length is a whole valid ciphertext+tag: at least a 4-byte pn plus one
 * tag, and not more than the buffer actually holds past pn_off. */
static int vpn_length_ok(const quic_vpn_desc* d, usz tag_len) {
  return d->length >= 4 + tag_len && d->length <= d->pkt.n - d->pn_off;
}

/* The length bound region_ok checks (RFC 9001 5.3) with a tag length sized
 * for suite rather than QUIC_GCM_TAG's fixed AES value; both suites this SDK
 * implements use a 16-byte tag (RFC 8446 5.3), so this is currently
 * equivalent, but derives it from suite rather than assuming AES. tag_len 0
 * (an unrecognized suite) also fails here. */
static int region_ok_suite(const quic_vpn_desc* d, usz tag_len) {
  usz sample = quic_hp_sample_offset(d->pn_off);
  if (tag_len == 0) return 0;
  if (!quic_hp_sample_ok(d->pkt.n, sample)) return 0;
  return vpn_length_ok(d, tag_len);
}

/* Header offset, ciphertext length, and recovered full packet number, once
 * header protection has been removed under suite. */
static int vpn_open_dims_suite(
    u16                  suite,
    const u8*            hp_key,
    const quic_vpn_desc* d,
    usz                  tag_len,
    vpnopen_dims*        v) {
  usz pn_len;
  if (!remove_hp_suite(suite, hp_key, d, &pn_len)) return 0;
  v->pn      = read_pn(d->pkt.p + d->pn_off, pn_len);
  v->hdr_len = d->pn_off + pn_len;
  v->ct_len  = (usz)d->length - pn_len - tag_len;
  return 1;
}

/* Region checked and header protection removed -- both required before the
 * AEAD open can run. */
static int vpn_open_suite_head(
    u16                      suite,
    const quic_protect_keys* k,
    const quic_vpn_desc*     d,
    usz                      tag_len,
    vpnopen_dims*            v) {
  if (!region_ok_suite(d, tag_len)) return 0;
  return vpn_open_dims_suite(suite, k->keys->hp, d, tag_len, v);
}

/* Same as quic_vpn_open, but opens under the given negotiated TLS 1.3 cipher
 * suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_vpn_open_suite(
    u16                      suite,
    const quic_protect_keys* k,
    const quic_vpn_desc*     d,
    quic_span*               payload) {
  usz          tag_len = quic_aead_tag_len(suite);
  vpnopen_dims v;
  if (!vpn_open_suite_head(suite, k, d, tag_len, &v)) return 0;
  if (!vpn_aead_open_suite(suite, k->keys, d->pkt.p, &v)) return 0;
  *payload = quic_span_of(d->pkt.p + v.hdr_len, v.ct_len);
  return 1;
}
