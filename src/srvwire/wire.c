#include "srvwire/wire.h"
#include "crypto_stream/crypto_tx.h"
#include "initpkt/initkeys.h"
#include "initpkt/initopen.h"
#include "hspkt/hspkt_build.h"
#include "hspkt/hspkt_open.h"
#include "pipeline/txpacket.h"
#include "pipeline/rxpacket.h"
#include "frame/frame.h"
#include "aes/aes.h"

/* Recover the TLS flight from a packet's CRYPTO frame bytes (RFC 9000 19.6). */
static int srvwire_take_crypto(const u8 *frames, usz n, const u8 **tls, usz *tls_len)
{
    quic_crypto_frame cf;
    if (!quic_frame_get_crypto(frames, n, &cf))
        return 0;
    *tls = cf.data;
    *tls_len = (usz)cf.length;
    return 1;
}

/* RFC 9001 5.2 */
int quic_srvwire_seal_initial(const u8 *dcid, u8 dcid_len,
                              const u8 *scid, u8 scid_len, u64 pn,
                              const u8 *tls, usz tls_len,
                              u8 *out, usz cap, usz *out_len)
{
    quic_initial_keys ck, sk;
    quic_aes128 hp;
    u8 frames[1024];
    usz fl, total;
    quic_initpkt_derive(dcid, dcid_len, &ck, &sk);
    quic_aes128_init(&hp, sk.hp);
    if (!quic_crypto_stream_emit(tls, tls_len, 0, tls_len, frames, sizeof frames, &fl))
        return 0;
    total = quic_tx_packet(&sk, &hp, 0xc3, dcid, dcid_len, scid, scid_len, 1,
                           (const u8 *)0, 0, pn, frames, fl, out, cap);
    if (total == 0)
        return 0;
    *out_len = total;
    return 1;
}

/* RFC 9001 5.2 */
int quic_srvwire_open_initial(const u8 *dcid, u8 dcid_len, u8 *pkt, usz len,
                              u64 pn, const u8 **tls, usz *tls_len)
{
    quic_initial_keys ck, sk;
    quic_aes128 hp;
    const u8 *frames;
    usz fl;
    (void)pn;
    quic_initpkt_derive(dcid, dcid_len, &ck, &sk);
    quic_aes128_init(&hp, sk.hp);
    if (!quic_rx_packet(&sk, &hp, pkt, len, 1, &frames, &fl))
        return 0;
    return srvwire_take_crypto(frames, fl, tls, tls_len);
}

/* RFC 9001 5 */
int quic_srvwire_seal_handshake(const quic_initial_keys *keys,
                                const quic_aes128 *hp,
                                const u8 *dcid, u8 dcid_len,
                                const u8 *scid, u8 scid_len, u64 pn,
                                const u8 *tls, usz tls_len,
                                u8 *out, usz cap, usz *out_len)
{
    u8 frames[2048];
    usz fl;
    if (!quic_crypto_stream_emit(tls, tls_len, 0, tls_len, frames, sizeof frames, &fl))
        return 0;
    return quic_hspkt_build(keys, hp, dcid, dcid_len, scid, scid_len, pn,
                            frames, fl, out, cap, out_len);
}

/* RFC 9001 5 */
int quic_srvwire_open_handshake(const quic_initial_keys *keys,
                                const quic_aes128 *hp,
                                u8 *pkt, usz len, u8 dcid_len,
                                const u8 **tls, usz *tls_len)
{
    const u8 *frames;
    usz fl;
    if (!quic_hspkt_open(keys, hp, pkt, len, dcid_len, &frames, &fl))
        return 0;
    return srvwire_take_crypto(frames, fl, tls, tls_len);
}
