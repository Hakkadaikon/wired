#include "transport/packet/protect/protect/protect.h"
#include "crypto/symmetric/aead/gcm/gcm.h"
#include "transport/packet/protect/hp/hp.h"

void quic_protect_nonce(const u8 iv[QUIC_INITIAL_IV], u64 pn,
                        u8 nonce[QUIC_INITIAL_IV])
{
    for (usz i = 0; i < QUIC_INITIAL_IV; i++) nonce[i] = iv[i];
    /* XOR the 64-bit pn into the low 8 bytes (iv is left-padded). */
    for (usz i = 0; i < 8; i++)
        nonce[QUIC_INITIAL_IV - 1 - i] ^= (u8)(pn >> (8 * i));
}

/* Copy the header into out and seal the payload after it, returning the
 * total length (header + ciphertext + tag) or 0 on overflow. */
static usz seal_into(const quic_initial_keys *keys, const u8 *hdr, usz hdr_len,
                     u64 pn, const u8 *payload, usz pl, u8 *out, usz cap)
{
    u8 nonce[QUIC_INITIAL_IV];
    quic_aes128 aead;
    usz need = hdr_len + pl + QUIC_GCM_TAG;
    if (need > cap) return 0;
    for (usz i = 0; i < hdr_len; i++) out[i] = hdr[i];
    quic_protect_nonce(keys->iv, pn, nonce);
    quic_aes128_init(&aead, keys->key);
    quic_gcm_seal(&aead, nonce, hdr, hdr_len, payload, pl,
                  out + hdr_len, out + hdr_len + pl);
    return need;
}

/* Apply header protection: sample 16 bytes at pn_off+4, mask byte0 and pn. */
static void protect_header(const quic_aes128 *hp_aes, u8 *out, usz pn_off,
                           usz pn_len)
{
    u8 mask[5];
    quic_hp_mask(hp_aes, out + pn_off + 4, mask);
    quic_hp_apply(mask, &out[0], &out[pn_off], pn_len, QUIC_HP_LONG_MASK);
}

usz quic_protect_seal(const quic_initial_keys *keys, const quic_aes128 *hp_aes,
                      const u8 *hdr, usz hdr_len, usz pn_off, usz pn_len, u64 pn,
                      const u8 *payload, usz payload_len, u8 *out, usz cap)
{
    usz total = seal_into(keys, hdr, hdr_len, pn, payload, payload_len, out, cap);
    if (total == 0) return 0;
    protect_header(hp_aes, out, pn_off, pn_len);
    return total;
}

usz quic_protect_open(const quic_initial_keys *keys, const quic_aes128 *hp_aes,
                      u8 *pkt, usz pkt_len, usz hdr_len, usz pn_off, usz pn_len,
                      u64 pn)
{
    u8 nonce[QUIC_INITIAL_IV];
    quic_aes128 aead;
    usz ct_len = pkt_len - hdr_len - QUIC_GCM_TAG;
    protect_header(hp_aes, pkt, pn_off, pn_len); /* XOR self-inverse: removes HP */
    quic_protect_nonce(keys->iv, pn, nonce);
    quic_aes128_init(&aead, keys->key);
    if (!quic_gcm_open(&aead, nonce, pkt, hdr_len, pkt + hdr_len, ct_len,
                       pkt + hdr_len + ct_len, pkt + hdr_len))
        return 0;
    return ct_len;
}
