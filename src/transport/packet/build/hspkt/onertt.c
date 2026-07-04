#include "transport/packet/build/hspkt/onertt.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "transport/packet/build/hspkt/unprotect.h"
#include "transport/packet/protect/hp/hp.h"

/* RFC 9000 17.3: short-header byte0 has high bit 0 (short form), fixed bit
 * set (0x40), and a 4-byte packet-number length (low bits 0x03). */
#define QUIC_ONERTT_BYTE0 0x43

/* RFC 9000 17.3: byte0, dcid, then a 4-byte packet number. */
static usz build_short_header(u8* hdr, quic_span dcid, u64 pn) {
  usz i;
  hdr[0] = QUIC_ONERTT_BYTE0;
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
  usz            hdr_len = build_short_header(o, d->dcid, d->pn);
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
