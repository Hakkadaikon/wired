#include "transport/packet/build/hspkt/unprotect.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "transport/packet/header/packet/pnum.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hpapply.h"
#include "transport/packet/protect/hp/hpsample.h"

/* Keys, packet descriptor and HP mask threaded through one open. */
typedef struct {
  const quic_initial_keys*         keys;
  const quic_hspkt_unprotect_desc* d;
  u8                               mask[5];
} hsunprot_ctx;

/* RFC 9001 5.3: AEAD-open ciphertext at pkt+hdr_len using header as AAD.
 * hdr_len is the true header length (pn_off + recovered pn_len). */
static int aead_open(const hsunprot_ctx* c, usz hdr_len, u64 pn) {
  u8          nonce[QUIC_INITIAL_IV];
  quic_aes128 aead;
  u8*         pkt    = c->d->pkt.p;
  usz         ct_len = c->d->pkt.n - hdr_len - QUIC_GCM_TAG;
  quic_protect_nonce(c->keys->iv, pn, nonce);
  quic_aes128_init(&aead, c->keys->key);
  quic_gcm_ctx g = {&aead, nonce, {pkt, hdr_len}};
  return quic_gcm_open(
      &g, quic_span_of(pkt + hdr_len, ct_len + QUIC_GCM_TAG), pkt + hdr_len);
}

/* RFC 9001 5.4.1 / RFC 9000 17.3 / A.3: byte0 (already unmasked) carries the
 * true packet-number length in its low two bits. Unmask only that many pn
 * bytes, recover the FULL packet number from the truncated value using
 * largest_pn (the nonce/AEAD must use the full pn, not the truncated one; the
 * header bytes stay truncated as AAD), fix hdr_len and AEAD-open. */
static int open_pkt(const hsunprot_ctx* c, quic_span* payload) {
  u8* pkt     = c->d->pkt.p;
  usz pn_off  = c->d->pn_off;
  usz pn_len  = (pkt[0] & 0x03u) + 1u;
  usz hdr_len = pn_off + pn_len;
  quic_hp_protect_pn(pkt + pn_off, pn_len, c->mask);
  if (c->d->pkt.n <= hdr_len + QUIC_GCM_TAG) return 0;
  if (!aead_open(
          c, hdr_len, quic_pnum_decode(pkt + pn_off, pn_len, c->d->largest_pn)))
    return 0;
  *payload = quic_span_of(pkt + hdr_len, c->d->pkt.n - hdr_len - QUIC_GCM_TAG);
  return 1;
}

/* RFC 9001 5.4/5.3. d->hdr_len is the maximum header length (4-byte PN); the
 * true PN length is recovered from byte0 once header protection is removed.
 * The sample for header protection is always at pn_off+4 (RFC 9001 5.4.2).
 * Only byte0 is unmasked here; the pn bytes are unmasked in open_pkt once
 * their true count is known, so a short PN does not corrupt the ciphertext. */
int quic_hspkt_unprotect(
    const quic_protect_keys*         k,
    const quic_hspkt_unprotect_desc* d,
    quic_span*                       payload) {
  hsunprot_ctx c = {k->keys, d, {0}};
  /* RFC 9001 5.4.2: the only length bound this side may impose before the
   * true PN length is known is that the HP sample (16 bytes at pn_off+4)
   * fits. Demanding room for a maximal 4-byte packet number instead rejects
   * every minimum-size packet with a shorter PN -- the PN length is the
   * sender's choice (RFC 9000 17.3.1), and Chrome's ACK-only 1-RTT packets
   * are exactly that minimum shape. open_pkt re-checks against the true
   * header length once the PN length is unmasked. */
  if (!quic_hp_sample_ok(d->pkt.n, quic_hp_sample_offset(d->pn_off))) return 0;
  quic_hp_mask(k->hp, d->pkt.p + quic_hp_sample_offset(d->pn_off), c.mask);
  d->pkt.p[0] ^= c.mask[0] & d->bits_mask;
  return open_pkt(&c, payload);
}
