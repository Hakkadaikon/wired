#include "hspkt/unprotect.h"
#include "protect/protect.h"
#include "gcm/gcm.h"
#include "hp/hp.h"
#include "hp/hpapply.h"
#include "packet/pnum.h"

/* RFC 9001 5.3: AEAD-open ciphertext at pkt+hdr_len using header as AAD. */
static int aead_open(const quic_initial_keys *keys, u8 *pkt, usz hdr_len,
                     usz ct_len, u64 pn)
{
    u8 nonce[QUIC_INITIAL_IV];
    quic_aes128 aead;
    quic_protect_nonce(keys->iv, pn, nonce);
    quic_aes128_init(&aead, keys->key);
    return quic_gcm_open(&aead, nonce, pkt, hdr_len, pkt + hdr_len, ct_len,
                         pkt + hdr_len + ct_len, pkt + hdr_len);
}

/* RFC 9001 5.4.1 / RFC 9000 17.3 / A.3: byte0 (already unmasked) carries the
 * true packet-number length in its low two bits. Unmask only that many pn
 * bytes, recover the FULL packet number from the truncated value using
 * largest_pn (the nonce/AEAD must use the full pn, not the truncated one; the
 * header bytes stay truncated as AAD), fix hdr_len and AEAD-open. */
static int open_pkt(const quic_initial_keys *keys, u8 *pkt, usz len,
                    usz pn_off, const u8 mask[5], u64 largest_pn,
                    const u8 **payload, usz *payload_len)
{
    usz pn_len = (pkt[0] & 0x03u) + 1u;
    usz hdr_len = pn_off + pn_len;
    usz ct_len;
    quic_hp_protect_pn(pkt + pn_off, pn_len, mask);
    if (len <= hdr_len + QUIC_GCM_TAG) return 0;
    ct_len = len - hdr_len - QUIC_GCM_TAG;
    if (!aead_open(keys, pkt, hdr_len, ct_len,
                   quic_pnum_decode(pkt + pn_off, pn_len, largest_pn)))
        return 0;
    *payload = pkt + hdr_len;
    *payload_len = ct_len;
    return 1;
}

/* RFC 9001 5.4/5.3. hdr_len is the maximum header length (4-byte PN); the true
 * PN length is recovered from byte0 once header protection is removed. The
 * sample for header protection is always at pn_off+4 (RFC 9001 5.4.2). Only
 * byte0 is unmasked here; the pn bytes are unmasked in open_pkt once their
 * true count is known, so a short PN does not corrupt the ciphertext. */
int quic_hspkt_unprotect(const quic_initial_keys *keys, const quic_aes128 *hp,
                         u8 *pkt, usz len, usz hdr_len, usz pn_off,
                         u8 bits_mask, u64 largest_pn,
                         const u8 **payload, usz *payload_len)
{
    u8 mask[5];
    if (len <= hdr_len + QUIC_GCM_TAG) return 0;
    quic_hp_mask(hp, pkt + pn_off + 4, mask);
    pkt[0] ^= mask[0] & bits_mask;
    return open_pkt(keys, pkt, len, pn_off, mask, largest_pn,
                    payload, payload_len);
}
