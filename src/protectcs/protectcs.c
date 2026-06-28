#include "protectcs/protectcs.h"
#include "protect_suite/aead_suite.h"
#include "protect_suite/hp_suite.h"
#include "hp/hp.h"
#include "hp/hpapply.h"

/* RFC 9001 5.4.1: long header (byte0 high bit set) masks 4 low bits, short 5. */
static u8 form_mask(u8 byte0)
{
    return (byte0 & 0x80) ? QUIC_HP_LONG_MASK : QUIC_HP_SHORT_MASK;
}

int quic_protectcs_seal(u16 suite, const u8 *key, const u8 *iv,
                        const u8 *hp_key, u64 pn, u8 *pkt, usz pn_off,
                        u8 pn_len, usz payload_len, usz *out_len)
{
    u8 mask[5];
    usz hdr_len = pn_off + pn_len;
    usz n = quic_aead_suite_seal(suite, key, iv, pn, pkt, hdr_len,
                                 pkt + hdr_len, payload_len, pkt + hdr_len);
    if (n == 0) return 0;
    if (!quic_hp_suite_mask(suite, hp_key, pkt + pn_off + 4, mask)) return 0;
    quic_hp_apply(mask, &pkt[0], &pkt[pn_off], pn_len, form_mask(pkt[0]));
    *out_len = hdr_len + n;
    return 1;
}

/* Decode the pn_len-byte packet number at pkt+pn_off into a full value. */
static u64 pcs_read_pn(const u8 *pkt, usz pn_off, usz pn_len)
{
    u64 pn = 0;
    for (usz i = 0; i < pn_len; i++) pn = (pn << 8) | pkt[pn_off + i];
    return pn;
}

/* RFC 9001 5.4.1: unmask byte0, recover pn_len from its low 2 bits, then
 * unmask that many packet-number bytes. Returns pn_len, or 0 on unknown suite. */
static usz pcs_remove_hp(u16 suite, const u8 *hp_key, u8 *pkt, usz pn_off)
{
    u8 mask[5];
    if (!quic_hp_suite_mask(suite, hp_key, pkt + pn_off + 4, mask)) return 0;
    pkt[0] ^= mask[0] & form_mask(pkt[0]);
    usz pn_len = (pkt[0] & 0x03) + 1;
    quic_hp_protect_pn(&pkt[pn_off], pn_len, mask);
    return pn_len;
}

int quic_protectcs_open(u16 suite, const u8 *key, const u8 *iv,
                        const u8 *hp_key, u8 *pkt, usz len, usz pn_off,
                        const u8 **payload, usz *payload_len)
{
    usz pn_len = pcs_remove_hp(suite, hp_key, pkt, pn_off);
    if (pn_len == 0) return 0;
    usz hdr_len = pn_off + pn_len;
    usz ct_len = len - hdr_len - 16;
    u64 pn = pcs_read_pn(pkt, pn_off, pn_len);
    if (!quic_aead_suite_open(suite, key, iv, pn, pkt, hdr_len,
                              pkt + hdr_len, ct_len, pkt + hdr_len))
        return 0;
    *payload = pkt + hdr_len;
    *payload_len = ct_len;
    return 1;
}
