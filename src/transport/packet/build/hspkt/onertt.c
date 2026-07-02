#include "transport/packet/build/hspkt/onertt.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "transport/packet/build/hspkt/unprotect.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/protect/protect.h"

/* RFC 9000 17.3: short-header byte0 has high bit 0 (short form), fixed bit
 * set (0x40), and a 4-byte packet-number length (low bits 0x03). */
#define QUIC_ONERTT_BYTE0 0x43

/* RFC 9000 17.3: byte0, dcid, then a 4-byte packet number. */
static usz build_short_header(u8 *hdr, const u8 *dcid, u8 dcid_len, u64 pn) {
  usz i;
  hdr[0] = QUIC_ONERTT_BYTE0;
  for (i = 0; i < dcid_len; i++) hdr[1 + i] = dcid[i];
  for (i = 0; i < 4; i++) hdr[1 + dcid_len + i] = (u8)(pn >> (8 * (3 - i)));
  return 5u + dcid_len;
}

/* RFC 9001 5.3/5.4: seal payload after the header, then header-protect with
 * the short-header byte0 mask. */
int quic_hspkt_onertt_build(
    const quic_initial_keys *keys,
    const quic_aes128       *hp,
    const u8                *dcid,
    u8                       dcid_len,
    u64                      pn,
    const u8                *payload,
    usz                      payload_len,
    u8                      *out,
    usz                      cap,
    usz                     *out_len) {
  u8          nonce[QUIC_INITIAL_IV], mask[5];
  quic_aes128 aead;
  usz         hdr_len = build_short_header(out, dcid, dcid_len, pn);
  usz         pn_off  = 1u + dcid_len;
  usz         need    = hdr_len + payload_len + QUIC_GCM_TAG;
  if (need > cap) return 0;
  quic_protect_nonce(keys->iv, pn, nonce);
  quic_aes128_init(&aead, keys->key);
  quic_gcm_ctx g = {&aead, nonce, {out, hdr_len}};
  quic_gcm_seal(&g, quic_span_of(payload, payload_len), out + hdr_len);
  quic_hp_mask(hp, out + pn_off + 4, mask);
  quic_hp_apply(mask, &out[0], &out[pn_off], 4, QUIC_HP_SHORT_MASK);
  *out_len = need;
  return 1;
}

/* RFC 9001 5 / RFC 9000 A.3 */
int quic_hspkt_onertt_open(
    const quic_initial_keys *keys,
    const quic_aes128       *hp,
    u8                      *pkt,
    usz                      len,
    u8                       dcid_len,
    u64                      largest_pn,
    const u8               **payload,
    usz                     *payload_len) {
  usz hdr_len = 5u + dcid_len;
  usz pn_off  = 1u + dcid_len;
  return quic_hspkt_unprotect(
      keys, hp, pkt, len, hdr_len, pn_off, QUIC_HP_SHORT_MASK, largest_pn,
      payload, payload_len);
}
