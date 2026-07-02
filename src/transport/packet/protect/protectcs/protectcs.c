#include "transport/packet/protect/protectcs/protectcs.h"

#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hpapply.h"
#include "transport/packet/protect/protect_suite/aead_suite.h"
#include "transport/packet/protect/protect_suite/hp_suite.h"

/* RFC 9001 5.4.1: long header (byte0 high bit set) masks 4 low bits, short 5.
 */
static u8 form_mask(u8 byte0) {
  return (byte0 & 0x80) ? QUIC_HP_LONG_MASK : QUIC_HP_SHORT_MASK;
}

/* Mask byte0 and the pn_len packet-number bytes at pn_off (RFC 9001 5.4.1). */
static int pcs_apply_hp(
    const quic_protectcs_keys *k, const quic_protectcs_seal_io *io) {
  u8             mask[5];
  quic_hp_fields f = {
      io->pkt, io->pkt + io->pn_off, io->pn_len, form_mask(io->pkt[0])};
  if (!quic_hp_suite_mask(k->suite, k->hp_key, io->pkt + io->pn_off + 4, mask))
    return 0;
  quic_hp_apply(mask, &f);
  return 1;
}

int quic_protectcs_seal(
    const quic_protectcs_keys    *k,
    const quic_protectcs_seal_io *io,
    usz                          *out_len) {
  usz                hdr_len = io->pn_off + io->pn_len;
  quic_aead_suite_op op      = {
      k->suite, k->key, k->iv, io->pn, quic_span_of(io->pkt, hdr_len)};
  usz n = quic_aead_suite_seal(
      &op, quic_span_of(io->pkt + hdr_len, io->payload_len), io->pkt + hdr_len);
  if (n == 0) return 0;
  if (!pcs_apply_hp(k, io)) return 0;
  *out_len = hdr_len + n;
  return 1;
}

/* Decode the pn_len-byte packet number at pkt+pn_off into a full value. */
static u64 pcs_read_pn(const u8 *pkt, usz pn_off, usz pn_len) {
  u64 pn = 0;
  for (usz i = 0; i < pn_len; i++) pn = (pn << 8) | pkt[pn_off + i];
  return pn;
}

/* RFC 9001 5.4.1: unmask byte0, recover pn_len from its low 2 bits, then
 * unmask that many packet-number bytes. Returns pn_len, or 0 on unknown suite.
 */
static usz pcs_remove_hp(const quic_protectcs_keys *k, u8 *pkt, usz pn_off) {
  u8 mask[5];
  if (!quic_hp_suite_mask(k->suite, k->hp_key, pkt + pn_off + 4, mask))
    return 0;
  pkt[0] ^= mask[0] & form_mask(pkt[0]);
  usz pn_len = (pkt[0] & 0x03) + 1;
  quic_hp_protect_pn(&pkt[pn_off], pn_len, mask);
  return pn_len;
}

int quic_protectcs_open(
    const quic_protectcs_keys    *k,
    const quic_protectcs_open_io *io,
    quic_span                    *payload) {
  u8 *pkt    = io->pkt.p;
  usz pn_len = pcs_remove_hp(k, pkt, io->pn_off);
  if (pn_len == 0) return 0;
  usz                hdr_len = io->pn_off + pn_len;
  usz                ct_len  = io->pkt.n - hdr_len - 16;
  quic_aead_suite_op op      = {
      k->suite, k->key, k->iv, pcs_read_pn(pkt, io->pn_off, pn_len),
      quic_span_of(pkt, hdr_len)};
  if (!quic_aead_suite_open(
          &op, quic_span_of(pkt + hdr_len, ct_len), pkt + hdr_len))
    return 0;
  *payload = quic_span_of(pkt + hdr_len, ct_len);
  return 1;
}
