#include "session/session.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/x25519.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/protect/protect/protect.h"
#include "transport/io/socket/net/udp4.h"
#include "transport/io/socket/net/ipv4.h"

#define QUIC_SESSION_CA 0x0a000001u
#define QUIC_SESSION_SA 0x0a000002u

/* Wrap a QUIC packet in UDP+IPv4 and push it onto the link (no syscall). */
static int link_tx(quic_memlink *l, const u8 *qpkt, usz qlen, u32 src, u32 dst)
{
    u8 udp[1500], ip[20], frame[1520];
    usz un = quic_udp4_build(udp, sizeof(udp), 4433, 4433, src, dst, qpkt, qlen);
    quic_ipv4_build(ip, (u16)(20 + un), src, dst, QUIC_IP_PROTO_UDP);
    for (usz i = 0; i < 20; i++) frame[i] = ip[i];
    for (usz i = 0; i < un; i++) frame[20 + i] = udp[i];
    return quic_memlink_send(l, frame, 20 + un);
}

/* Validate a received frame's IP+UDP envelope. Returns 1 if it checks out. */
static int env_ok(const u8 *frame, usz fn, u32 src, u32 dst)
{
    if (fn == 0 || !quic_ipv4_check(frame)) return 0;
    return quic_udp4_check(frame + 20, fn - 20, src, dst);
}

/* Copy n bytes from src to dst. */
static void copy_n(u8 *dst, const u8 *src, usz n)
{
    for (usz i = 0; i < n; i++) dst[i] = src[i];
}

/* Pull a frame, verify IP/UDP, copy out the QUIC payload. Returns its len. */
static usz link_rx(quic_memlink *l, u8 *qpkt, usz cap, u32 src, u32 dst)
{
    u8 frame[1520];
    usz fn = quic_memlink_recv(l, frame, sizeof(frame));
    if (!env_ok(frame, fn, src, dst)) return 0;
    usz qlen = fn - 20 - QUIC_UDP_HDR;
    usz n = (qlen < cap) ? qlen : cap;
    copy_n(qpkt, frame + 20 + QUIC_UDP_HDR, n);
    return qlen;
}

/* Fill an 18-byte protected-packet header (byte0, version, DCID len, DCID,
 * then the 4-byte packet number at offset 14) for packet number pn. */
static void fill_header(u8 hdr[18], u8 byte0, const u8 dcid[8], u8 pn_low)
{
    for (usz i = 0; i < 18; i++) hdr[i] = 0;
    hdr[0] = byte0;
    hdr[4] = 1;       /* version 1 */
    hdr[5] = 8;       /* DCID length */
    for (usz i = 0; i < 8; i++) hdr[6 + i] = dcid[i];
    hdr[17] = pn_low; /* low byte of the 4-byte packet number */
}

void quic_session_init(quic_session *s, const u8 priv[32], const u8 dcid[8],
                       quic_memlink *link, int is_server)
{
    quic_endpoint_init(&s->ep, priv, dcid);
    quic_conn_init(&s->conn);
    quic_initial_derive(dcid, 8, 0, &s->ikeys);
    quic_aes128_init(&s->ihp, s->ikeys.hp);
    s->link = link;
    s->is_server = is_server;
    s->have_peer = 0;
    for (usz i = 0; i < 8; i++) s->dcid[i] = dcid[i];
}

int quic_session_client_hello(quic_session *s)
{
    u8 hello[256], crypto[300], hdr[18], out[1200];
    u8 rnd[32] = {0};
    usz hl = quic_hs_build_hello(hello, sizeof(hello), QUIC_HS_CLIENT_HELLO,
                                 rnd, s->ep.pub);
    quic_crypto_frame cf = {.offset = 0, .length = hl, .data = hello};
    usz cl = quic_frame_put_crypto(crypto, sizeof(crypto), &cf);
    fill_header(hdr, 0xc3, s->dcid, 1);
    usz pn = quic_protect_seal(&s->ikeys, &s->ihp, hdr, 18, 14, 4, 1,
                               crypto, cl, out, sizeof(out));
    if (pn == 0) return 0;
    return link_tx(s->link, out, pn, QUIC_SESSION_CA, QUIC_SESSION_SA);
}

/* Decode a received Initial's CRYPTO frame and extract the peer's share. */
static int read_share(u8 *pkt, usz pl, u8 peer_pub[32])
{
    quic_crypto_frame cf;
    u8 type;
    usz body_len;
    if (quic_frame_get_crypto(pkt + 18, pl, &cf) == 0) return 0;
    if (quic_hs_parse(cf.data, cf.length, &type, &body_len) == 0) return 0;
    return quic_hs_peer_share(cf.data + 4, body_len, peer_pub);
}

/* Unprotect a received Initial of rn bytes in place; returns plaintext len. */
static usz open_initial(quic_session *s, u8 *pkt, usz rn)
{
    if (rn == 0) return 0;
    return quic_protect_open(&s->ikeys, &s->ihp, pkt, rn, 18, 14, 4, 1);
}

int quic_session_accept(quic_session *s)
{
    u8 pkt[1200];
    usz rn = link_rx(s->link, pkt, sizeof(pkt), QUIC_SESSION_CA, QUIC_SESSION_SA);
    usz pl = open_initial(s, pkt, rn);
    if (pl == 0) return 0;
    if (!read_share(pkt, pl, s->peer_pub)) return 0;
    s->have_peer = 1;
    quic_conn_step(&s->conn, QUIC_CONN_EV_HS_PROGRESS);
    return 1;
}

/* Derive the server-direction 1-RTT keys both ends use, and the matching
 * header-protection cipher, into the session. */
static void agree_dir(quic_session *s, const u8 peer_pub[32],
                      const u8 *tr, usz trlen)
{
    quic_endpoint_agree(&s->ep, peer_pub, tr, trlen, 1); /* server direction */
    quic_aes128_init(&s->hshp, s->ep.hs_keys.hp);
}

int quic_session_finish(quic_session *client, quic_session *server,
                        const u8 *transcript, usz transcript_len)
{
    if (!server->have_peer) return 0;
    /* Both derive the server-direction keys from the same ECDHE inputs. */
    agree_dir(server, server->peer_pub, transcript, transcript_len);
    agree_dir(client, server->ep.pub, transcript, transcript_len);
    quic_conn_step(&client->conn, QUIC_CONN_EV_HS_CONFIRMED);
    quic_conn_step(&server->conn, QUIC_CONN_EV_HS_CONFIRMED);
    return 1;
}

/* Our own IPv4 address on the link, by role. */
static u32 my_addr(int is_server)
{
    return is_server ? QUIC_SESSION_SA : QUIC_SESSION_CA;
}

/* The peer's IPv4 address on the link, by role. */
static u32 peer_addr(int is_server)
{
    return is_server ? QUIC_SESSION_CA : QUIC_SESSION_SA;
}

int quic_session_send_stream(quic_session *s, u64 stream_id,
                             const u8 *data, usz len, int fin)
{
    u8 fr[1024], hdr[18], out[1200];
    quic_stream_frame sf = {.stream_id = stream_id, .offset = 0,
                            .length = len, .data = data, .fin = fin};
    usz fl = quic_frame_put_stream(fr, sizeof(fr), &sf);
    fill_header(hdr, 0x43, s->dcid, 7); /* short-header form, pn 7 */
    usz pn = quic_protect_seal(&s->ep.hs_keys, &s->hshp, hdr, 18, 14, 4, 7,
                               fr, fl, out, sizeof(out));
    if (pn == 0) return 0;
    return link_tx(s->link, out, pn, my_addr(s->is_server),
                   peer_addr(s->is_server));
}

/* Unprotect a received 1-RTT packet of rn bytes in place; plaintext len. */
static usz open_1rtt(quic_session *s, u8 *pkt, usz rn)
{
    if (rn == 0) return 0;
    return quic_protect_open(&s->ep.hs_keys, &s->hshp, pkt, rn, 18, 14, 4, 7);
}

int quic_session_recv_stream(quic_session *s, quic_stream_frame *out)
{
    static u8 pkt[1200];
    usz rn = link_rx(s->link, pkt, sizeof(pkt), peer_addr(s->is_server),
                     my_addr(s->is_server));
    usz pl = open_1rtt(s, pkt, rn);
    if (pl == 0) return 0;
    return quic_frame_get_stream(pkt + 18, pl, out) != 0;
}
