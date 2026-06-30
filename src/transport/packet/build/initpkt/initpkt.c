#include "transport/packet/build/initpkt/initpkt.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "crypto_stream/crypto_tx.h"
#include "transport/packet/frame/pipeline/txpacket.h"
#include "crypto/symmetric/aead/aes/aes.h"

/* RFC 9000 14.1: the protected datagram must reach 1200 bytes. The complete
 * 17.2.2 header (byte0+version+DCID+SCID+empty Token+2-byte Length+4-byte PN)
 * plus the 16-byte AEAD tag forms the overhead; the plaintext payload is padded
 * with PADDING frames (0x00) so header + payload + tag is at least 1200. The
 * 2-byte Length varint holds for any ~1200-byte Initial. */
static usz pad_target(u8 dcid_len, u8 scid_len)
{
    usz overhead = 30u + dcid_len + scid_len;
    return overhead < 1200u ? 1200u - overhead : 0u;
}

static usz initpkt_min_usz(usz a, usz b) { return a < b ? a : b; }

/* Build the CRYPTO frame for the ClientHello, then PADDING-fill to target. */
static int build_payload(const u8 *crypto_payload, usz payload_len,
                         usz target, u8 *buf, usz cap, usz *plen)
{
    usz n, fill = initpkt_min_usz(target, cap);
    if (!quic_crypto_stream_emit(crypto_payload, payload_len, 0,
                                 payload_len, buf, cap, &n))
        return 0;
    for (; n < fill; n++) buf[n] = 0x00;
    *plen = n;
    return 1;
}

/* RFC 9000 17.2.2: emit a complete Initial long header carrying the SCID and an
 * empty Token, padded to the 1200-byte datagram floor. */
int quic_initpkt_build(const u8 *dcid, u8 dcid_len,
                       const u8 *scid, u8 scid_len,
                       const u8 *crypto_payload, usz payload_len, u64 pn,
                       u8 *out, usz cap, usz *out_len)
{
    quic_initial_keys ck, sk;
    quic_aes128 hp;
    u8 payload[1200];
    usz plen, total;
    quic_initpkt_derive(dcid, dcid_len, &ck, &sk);
    quic_aes128_init(&hp, ck.hp);
    if (!build_payload(crypto_payload, payload_len,
                       pad_target(dcid_len, scid_len), payload,
                       sizeof(payload), &plen))
        return 0;
    total = quic_tx_packet(&ck, &hp, 0xc3, dcid, dcid_len, scid, scid_len, 1,
                           (const u8 *)0, 0, pn, payload, plen, out, cap);
    if (total == 0) return 0;
    *out_len = total;
    return 1;
}
