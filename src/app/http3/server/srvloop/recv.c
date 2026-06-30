#include "app/http3/server/srvloop/recv.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "crypto/kdf/keys/keyset.h"
#include "app/http3/server/srvloop/keys.h"

/* RFC 9001 5.1: open a received Initial under the keys derived from the client's
 * original DCID; the raw frame payload is returned (the dispatcher walks it).
 * largest_pn is unused outside the 1-RTT space (the Initial uses a 4-byte PN). */
static int recv_initial(quic_server *s, u8 *pkt, usz len, u64 largest_pn,
                        const u8 **pl, usz *pl_len)
{
    (void)largest_pn;
    return quic_initpkt_open(s->sdrv.odcid, s->sdrv.odcid_len, pkt, len, 0,
                             pl, pl_len);
}

/* RFC 9001 5.1: open a Handshake packet with the peer-direction CLIENT_HS key.
 * The DCID the client wrote is the server's source id (iscid). */
static int recv_handshake(quic_server *s, u8 *pkt, usz len, u64 largest_pn,
                          const u8 **pl, usz *pl_len)
{
    const quic_initial_keys *k;
    quic_aes128 hp;
    (void)largest_pn;
    if (!quic_srvloop_open_keys(s, QUIC_LEVEL_HANDSHAKE, &k, &hp))
        return 0;
    return quic_hspkt_open(k, &hp, pkt, len, s->sdrv.iscid_len, pl, pl_len);
}

/* RFC 9001 5.1 / RFC 9000 A.3: open a 1-RTT packet with the peer-direction
 * CLIENT_AP key, recovering the full packet number from its truncated form
 * relative to largest_pn (the largest 1-RTT PN received so far). */
static int recv_onertt(quic_server *s, u8 *pkt, usz len, u64 largest_pn,
                       const u8 **pl, usz *pl_len)
{
    const quic_initial_keys *k;
    quic_aes128 hp;
    if (!quic_srvloop_open_keys(s, QUIC_LEVEL_ONERTT, &k, &hp))
        return 0;
    return quic_hspkt_onertt_open(k, &hp, pkt, len, s->sdrv.iscid_len,
                                  largest_pn, pl, pl_len);
}

/* RFC 9000 17.2: dispatch the open by level (table keeps CCN low). */
static int recv_at_level(quic_server *s, int level, u8 *pkt, usz len,
                         u64 largest_pn, const u8 **pl, usz *pl_len)
{
    static int (*const open_at[])(quic_server *, u8 *, usz, u64,
                                  const u8 **, usz *) = {
        recv_initial,
        recv_handshake,
        recv_onertt,
    };
    return open_at[level](s, pkt, len, largest_pn, pl, pl_len);
}

int quic_srvloop_recv(quic_server *s, u8 *dgram, usz len, u64 largest_pn,
                      int *level, const u8 **payload, usz *payload_len)
{
    if (len == 0 || !quic_connrunner_packet_level(dgram[0], level))
        return 0;
    return recv_at_level(s, *level, dgram, len, largest_pn, payload, payload_len);
}
