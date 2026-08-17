#include "transport/packet/build/hspkt/unprotect.h"

#include "crypto/symmetric/aead/gcm/gcm.h"
#include "tls/handshake/core/tls/aead_params.h"
#include "transport/packet/header/packet/pnum.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hpapply.h"
#include "transport/packet/protect/hp/hpsample.h"
#include "transport/packet/protect/protect_suite/aead_suite.h"
#include "transport/packet/protect/protect_suite/hp_suite.h"

/* Keys, packet descriptor and HP mask threaded through one open. */
typedef struct {
  const initial_keys*         keys;
  const hspkt_unprotect_desc* d;
  u8                          mask[5];
} hsunprot_ctx;

/* RFC 9001 5.3: AEAD-open ciphertext at pkt+hdr_len using header as AAD.
 * hdr_len is the true header length (pn_off + recovered pn_len). */
static int aead_open(const hsunprot_ctx* c, usz hdr_len, u64 pn) {
  u8     nonce[INITIAL_IV];
  aes128 aead;
  u8*    pkt    = c->d->pkt.p;
  usz    ct_len = c->d->pkt.n - hdr_len - GCM_TAG;
  protect_nonce(c->keys->iv, pn, nonce);
  aes128_init(&aead, c->keys->key);
  gcm_ctx g = {&aead, nonce, {pkt, hdr_len}};
  return gcm_open(
      &g, wired_span_of(pkt + hdr_len, ct_len + GCM_TAG), pkt + hdr_len);
}

/* RFC 9001 5.4.1 / RFC 9000 17.3 / A.3: byte0 (already unmasked) carries the
 * true packet-number length in its low two bits. Unmask only that many pn
 * bytes, recover the FULL packet number from the truncated value using
 * largest_pn (the nonce/AEAD must use the full pn, not the truncated one; the
 * header bytes stay truncated as AAD), fix hdr_len and AEAD-open. */
static int open_pkt(const hsunprot_ctx* c, wired_span* payload) {
  u8* pkt     = c->d->pkt.p;
  usz pn_off  = c->d->pn_off;
  usz pn_len  = (pkt[0] & 0x03u) + 1u;
  usz hdr_len = pn_off + pn_len;
  hp_protect_pn(pkt + pn_off, pn_len, c->mask);
  if (c->d->pkt.n <= hdr_len + GCM_TAG) return 0;
  if (!aead_open(
          c, hdr_len, pnum_decode(pkt + pn_off, pn_len, c->d->largest_pn)))
    return 0;
  *payload = wired_span_of(pkt + hdr_len, c->d->pkt.n - hdr_len - GCM_TAG);
  return 1;
}

/* RFC 9001 5.4/5.3. d->hdr_len is the maximum header length (4-byte PN); the
 * true PN length is recovered from byte0 once header protection is removed.
 * The sample for header protection is always at pn_off+4 (RFC 9001 5.4.2).
 * Only byte0 is unmasked here; the pn bytes are unmasked in open_pkt once
 * their true count is known, so a short PN does not corrupt the ciphertext. */
int hspkt_unprotect(
    const protect_keys* k, const hspkt_unprotect_desc* d, wired_span* payload) {
  hsunprot_ctx c = {k->keys, d, {0}};
  /* RFC 9001 5.4.2: the only length bound this side may impose before the
   * true PN length is known is that the HP sample (16 bytes at pn_off+4)
   * fits. Demanding room for a maximal 4-byte packet number instead rejects
   * every minimum-size packet with a shorter PN -- the PN length is the
   * sender's choice (RFC 9000 17.3.1), and Chrome's ACK-only 1-RTT packets
   * are exactly that minimum shape. open_pkt re-checks against the true
   * header length once the PN length is unmasked. */
  if (!hp_sample_ok(d->pkt.n, hp_sample_offset(d->pn_off))) return 0;
  hp_mask(k->hp, d->pkt.p + hp_sample_offset(d->pn_off), c.mask);
  d->pkt.p[0] ^= c.mask[0] & d->bits_mask;
  return open_pkt(&c, payload);
}

/* Same context as hsunprot_ctx, plus the negotiated suite (RFC 8446 B.4). */
typedef struct {
  u16                         suite;
  const initial_keys*         keys;
  const hspkt_unprotect_desc* d;
  u8                          mask[5];
} hsunprot_suite_ctx;

/* RFC 9001 5.3: AEAD-open ciphertext at pkt+hdr_len using header as AAD,
 * under c->suite. hdr_len is the true header length (pn_off + recovered
 * pn_len). op.iv is the raw key IV (aead_suite_open derives the nonce
 * itself: iv XOR pn), not a precomputed nonce. */
static int aead_open_suite(const hsunprot_suite_ctx* c, usz hdr_len, u64 pn) {
  usz           tag_len = aead_tag_len(c->suite);
  u8*           pkt     = c->d->pkt.p;
  usz           ct_len  = c->d->pkt.n - hdr_len - tag_len;
  aead_suite_op op = {c->suite, c->keys->key, c->keys->iv, pn, {pkt, hdr_len}};
  return aead_suite_open(
             &op, wired_span_of(pkt + hdr_len, ct_len), pkt + hdr_len) != 0;
}

/* pn_len/hdr_len for c under suite, and whether the buffer is long enough
 * for hdr_len+tag_len -- both required before the AEAD open in
 * open_pkt_suite can run. Unmasks the pn bytes as a side effect (RFC 9001
 * 5.4.1), same as open_pkt. */
static int open_pkt_suite_head(
    const hsunprot_suite_ctx* c, usz tag_len, usz* hdr_len) {
  u8* pkt    = c->d->pkt.p;
  usz pn_off = c->d->pn_off;
  usz pn_len = (pkt[0] & 0x03u) + 1u;
  if (tag_len == 0) return 0;
  hp_protect_pn(pkt + pn_off, pn_len, c->mask);
  *hdr_len = pn_off + pn_len;
  return c->d->pkt.n > *hdr_len + tag_len;
}

/* Same as open_pkt, but resolves pn_len/hdr_len/AEAD under c->suite. */
static int open_pkt_suite(const hsunprot_suite_ctx* c, wired_span* payload) {
  usz tag_len = aead_tag_len(c->suite);
  u8* pkt     = c->d->pkt.p;
  usz hdr_len;
  if (!open_pkt_suite_head(c, tag_len, &hdr_len)) return 0;
  if (!aead_open_suite(
          c, hdr_len,
          pnum_decode(
              pkt + c->d->pn_off, hdr_len - c->d->pn_off, c->d->largest_pn)))
    return 0;
  *payload = wired_span_of(pkt + hdr_len, c->d->pkt.n - hdr_len - tag_len);
  return 1;
}

/* Same as hspkt_unprotect, but opens under the given negotiated TLS 1.3
 * cipher suite (RFC 8446 B.4). Returns 0 on an unrecognized suite. */
int hspkt_unprotect_suite(
    u16                         suite,
    const protect_keys*         k,
    const hspkt_unprotect_desc* d,
    wired_span*                 payload) {
  hsunprot_suite_ctx c = {suite, k->keys, d, {0}};
  if (!hp_sample_ok(d->pkt.n, hp_sample_offset(d->pn_off))) return 0;
  if (!hp_suite_mask(
          suite, k->keys->hp, d->pkt.p + hp_sample_offset(d->pn_off), c.mask))
    return 0;
  d->pkt.p[0] ^= c.mask[0] & d->bits_mask;
  return open_pkt_suite(&c, payload);
}
