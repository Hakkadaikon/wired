#include "transport/packet/build/hspkt/onertt.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "tls/handshake/core/tls/aead_params.h"
#include "tls/keys/keyupdate/keyphase.h"
#include "transport/packet/build/hspkt/unprotect.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/protect_suite/aead_suite.h"
#include "transport/packet/protect/protect_suite/hp_suite.h"

/* RFC 9000 17.3: short-header byte0 has high bit 0 (short form), fixed bit
 * set (0x40), and a 4-byte packet-number length (low bits 0x03). RFC 9001 6:
 * bit 0x04 (quic_keyphase_set) then carries this packet's Key Phase. */
#define QUIC_ONERTT_BYTE0 0x43

/* RFC 9000 17.3 / RFC 9001 6: byte0 (with its Key Phase bit set), dcid, then
 * a 4-byte packet number. */
static usz build_short_header(u8* hdr, quic_span dcid, u64 pn, int phase_bit) {
  usz i;
  hdr[0] = quic_keyphase_set(QUIC_ONERTT_BYTE0, phase_bit);
  for (i = 0; i < dcid.n; i++) hdr[1 + i] = dcid.p[i];
  for (i = 0; i < 4; i++) hdr[1 + dcid.n + i] = (u8)(pn >> (8 * (3 - i)));
  return 5u + dcid.n;
}

/* RFC 9001 5.3/5.4: seal payload after the header, then header-protect with
 * the short-header byte0 mask. */
int quic_hspkt_onertt_build(
    const quic_protect_keys*      k,
    const quic_hspkt_onertt_desc* d,
    quic_obuf*                    out) {
  u8             nonce[QUIC_INITIAL_IV], mask[5];
  quic_aes128    aead;
  u8*            o       = out->p;
  usz            hdr_len = build_short_header(o, d->dcid, d->pn, d->phase_bit);
  usz            pn_off  = 1u + d->dcid.n;
  usz            need    = hdr_len + d->payload.n + QUIC_GCM_TAG;
  quic_hp_fields hf      = {o, o + pn_off, 4, QUIC_HP_SHORT_MASK};
  if (need > out->cap) return 0;
  quic_protect_nonce(k->keys->iv, d->pn, nonce);
  quic_aes128_init(&aead, k->keys->key);
  quic_gcm_ctx g = {&aead, nonce, {o, hdr_len}};
  quic_gcm_seal(&g, d->payload, o + hdr_len);
  quic_hp_mask(k->hp, o + pn_off + 4, mask);
  quic_hp_apply(mask, &hf);
  out->len = need;
  return 1;
}

/* RFC 9001 5 / RFC 9000 A.3 */
int quic_hspkt_onertt_open(
    const quic_protect_keys*           k,
    const quic_hspkt_onertt_open_desc* d,
    quic_span*                         payload) {
  quic_hspkt_unprotect_desc u = {
      d->pkt, 5u + (usz)d->dcid_len, 1u + (usz)d->dcid_len, QUIC_HP_SHORT_MASK,
      d->largest_pn};
  return quic_hspkt_unprotect(k, &u, payload);
}

/* Seal d->payload after the short header already written at o (build_short_
 * header), under suite. op.iv is the raw key IV (quic_aead_suite_seal
 * derives the nonce itself: iv XOR pn), not a precomputed nonce. Returns 1
 * on success, 0 on overflow/unknown suite. */
static int onertt_seal_suite(
    u16                           suite,
    const quic_protect_keys*      k,
    const quic_hspkt_onertt_desc* d,
    u8*                           o,
    usz                           hdr_len,
    usz                           need,
    quic_obuf*                    out) {
  quic_aead_suite_op op;
  if (need > out->cap) return 0;
  op = (quic_aead_suite_op){
      suite, k->keys->key, k->keys->iv, d->pn, {o, hdr_len}};
  return quic_aead_suite_seal(&op, d->payload, o + hdr_len) != 0;
}

/* Same as quic_hspkt_onertt_build, but seals under the given negotiated TLS
 * 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_hspkt_onertt_build_suite(
    u16                           suite,
    const quic_protect_keys*      k,
    const quic_hspkt_onertt_desc* d,
    quic_obuf*                    out) {
  u8             mask[5];
  u8*            o       = out->p;
  usz            hdr_len = build_short_header(o, d->dcid, d->pn, d->phase_bit);
  usz            pn_off  = 1u + d->dcid.n;
  usz            need    = hdr_len + d->payload.n + quic_aead_tag_len(suite);
  quic_hp_fields hf      = {o, o + pn_off, 4, QUIC_HP_SHORT_MASK};
  if (!onertt_seal_suite(suite, k, d, o, hdr_len, need, out)) return 0;
  if (!quic_hp_suite_mask(suite, k->keys->hp, o + pn_off + 4, mask)) return 0;
  quic_hp_apply(mask, &hf);
  out->len = need;
  return 1;
}

/* Same as quic_hspkt_onertt_open, but opens under the given negotiated TLS
 * 1.3 cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int quic_hspkt_onertt_open_suite(
    u16                                suite,
    const quic_protect_keys*           k,
    const quic_hspkt_onertt_open_desc* d,
    quic_span*                         payload) {
  quic_hspkt_unprotect_desc u = {
      d->pkt, 5u + (usz)d->dcid_len, 1u + (usz)d->dcid_len, QUIC_HP_SHORT_MASK,
      d->largest_pn};
  return quic_hspkt_unprotect_suite(suite, k, &u, payload);
}
