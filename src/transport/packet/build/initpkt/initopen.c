#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/build/initpkt/initkeys.h"
#include "transport/packet/frame/pipeline/rxpacket.h"
#include "crypto/symmetric/aead/aes/aes.h"

/* RFC 9001 5.2 */
int quic_initpkt_open(const u8 *dcid, u8 dcid_len, u8 *pkt, usz len, u64 pn,
                      const u8 **crypto_out, usz *crypto_len)
{
    quic_initial_keys ck, sk;
    quic_aes128 hp;
    quic_initpkt_derive(dcid, dcid_len, &ck, &sk);
    quic_aes128_init(&hp, ck.hp);
    (void)sk;
    (void)pn;
    return quic_rx_packet(&ck, &hp, pkt, len, 1, crypto_out, crypto_len);
}
