/* Real-UDP HTTP/3 server. libc-free, x86_64-linux, direct syscalls, own _start,
 * static.
 *
 * Binds 0.0.0.0:4433 and drives the in-tree server real-wire loop
 * (quic_srvloop_step, the socket-free core of src/srvloop) from a client
 * Initial through a full handshake to an HTTP/3 200, all under real AEAD
 * protection on the wire (RFC 9001 4 / 5, RFC 9000 17.2, RFC 9114 4.1):
 *
 *   - recover the ClientHello from the protected Initial and build the server
 *     flight (quic_server_recv_initial / quic_server_build_flight): ServerHello
 *     + EncryptedExtensions(ALPN h3 + transport params) / Certificate / Cert-
 *     ificateVerify / Finished (RFC 8446 4.4),
 *   - seal ServerHello into a server Initial and the flight into a Handshake
 *     packet (quic_srvloop_send_initial / _send_handshake) and send them,
 *   - hand every later datagram to quic_srvloop_step: it opens the packet with
 *     the peer-direction key, verifies the client Finished and confirms, seals
 *     HANDSHAKE_DONE, then on a 1-RTT GET seals a :status 200 — each sealed
 *     reply is sent straight back with quic_udp_send.
 *
 * Each step logs to stderr. See examples/README.md for what completes here vs.
 * what an external HTTP/3 client (curl/quiche) additionally needs. */

#include "ed25519/ed25519.h"
#include "frame/frame.h"
#include "h3srv/state.h"
#include "initpkt/initopen.h"
#include "io/udp.h"
#include "salpn/ch_ext.h"
#include "salpn/negotiate.h"
#include "server/server.h"
#include "srvloop/send.h"
#include "srvloop/srvloop.h"
#include "sys/syscall.h"
#include "tls/x25519.h"

#define PORT 4433

/* The server's chosen Source Connection ID, echoed in every header it sends
 * (RFC 9000 17.2) and the DCID a peer writes back. Fixed for a demo. */
static const u8 SERVER_SCID[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

/* The compiler emits memcpy/memset for struct/array copies even under
 * -ffreestanding; with -nostdlib we must supply them. */
void *memcpy(void *dst, const void *src, usz n)
{
    u8 *d = dst;
    const u8 *s = src;
    for (usz i = 0; i < n; i++)
        d[i] = s[i];
    return dst;
}

void *memset(void *dst, int c, usz n)
{
    u8 *d = dst;
    for (usz i = 0; i < n; i++)
        d[i] = (u8)c;
    return dst;
}

static void logs(const char *s)
{
    usz n = 0;
    while (s[n])
        n++;
    syscall3(SYS_write, 2, (i64)s, (i64)n);
}

static void die(const char *msg)
{
    logs(msg);
    syscall1(SYS_exit, 1);
}

/* The fixed 32-byte ServerHello.random. Deterministic for reproducibility. */
static void fill_random(u8 r[32])
{
    for (usz i = 0; i < 32; i++)
        r[i] = (u8)(0xa0 + i);
}

/* Fixed server identity: X25519 handshake key and the Ed25519 signing seed.
 * A demo needs no rotation; deterministic keys keep it reproducible. */
static void server_keys(u8 priv[32], u8 pub[32], u8 cert_seed[32])
{
    for (usz i = 0; i < 32; i++) {
        priv[i] = (u8)(0x40 + i);
        cert_seed[i] = (u8)(0x80 + i);
    }
    quic_x25519_base(pub, priv);
}

/* RFC 5280 4.1: minimal Ed25519 end-entity cert carrying pub in its SPKI. */
static usz ed_cert(u8 *out, const u8 pub[32])
{
    static const u8 head[] = {
        0x30, 0x48, 0x30, 0x3c, 0xa0, 0x03, 0x02, 0x01, 0x02,
        0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00,
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    };
    static const u8 tail[] = {
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x01, 0x00,
    };
    memcpy(out, head, sizeof head);
    memcpy(out + sizeof head, pub, 32);
    memcpy(out + sizeof head + 32, tail, sizeof tail);
    return sizeof head + 32 + sizeof tail;
}

/* Note ALPN "h3" if the ClientHello offers it (informational only). */
static void log_alpn(const u8 *ch, usz ch_len)
{
    const u8 *ext;
    usz extl;
    if (quic_salpn_find_extension(ch, ch_len, QUIC_SALPN_EXT_TYPE, &ext, &extl) &&
        quic_salpn_select_h3(ext, extl))
        logs("ALPN: h3 selected\n");
    else
        logs("ALPN: h3 not offered\n");
}

/* Seal a packet and, if non-empty, send it with a log line. */
static void send_pkt(i64 fd, const quic_sockaddr_in *peer, const u8 *pkt,
                     usz n, const char *what)
{
    if (n) {
        quic_udp_send(fd, peer, pkt, n);
        logs(what);
    }
}

/* A long-header datagram big enough to hold byte0 + version + dcid_len + DCID. */
static int valid_initial(const u8 *dg, usz len)
{
    if (len < 6 || (dg[0] & 0x80) == 0)
        return 0;
    return len >= (usz)6 + dg[5];
}

/* Open the client Initial and recover the ClientHello CRYPTO (RFC 9000 17.2:
 * the DCID is unprotected at the front). Returns 1 and fills *cf on success. */
static int open_initial(u8 *dg, usz len, quic_crypto_frame *cf)
{
    const u8 *crypto;
    usz clen;
    if (!valid_initial(dg, len))
        return 0;
    if (!quic_initpkt_open(dg + 6, dg[5], dg, len, 0, &crypto, &clen))
        return logs("Initial open failed\n"), 0;
    logs("Initial received and opened\n");
    return quic_frame_get_crypto(crypto, clen, cf);
}

/* Init the orchestrator and loop with the fixed server identity and the
 * client's DCID as the ODCID. Returns 1 on success. */
static int init_server(quic_server *s, quic_srvloop *l, const u8 *dcid,
                       u8 dcid_len)
{
    u8 priv[32], pub[32], seed[32], cert_pub[32];
    static u8 cert[128];
    usz cert_len;
    server_keys(priv, pub, seed);
    if (!quic_ed25519_keypair(seed, cert_pub))
        return 0;
    cert_len = ed_cert(cert, cert_pub);
    quic_server_init(s, priv, pub, seed, cert, cert_len);
    if (!quic_server_set_cids(s, dcid, dcid_len, SERVER_SCID, sizeof SERVER_SCID))
        return 0;
    return quic_srvloop_init(l, dcid, dcid_len);
}

/* Seal the ServerHello (Initial) and the rest of the flight (Handshake) under
 * the server's own-direction keys and send each that sealed. */
static void seal_and_send(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                          const u8 *sh, usz shl, const u8 *flight, usz fll)
{
    u8 pkt[1500];
    usz n = 0;
    if (quic_srvloop_send_initial(s, SERVER_SCID, sizeof SERVER_SCID, 1,
                                  sh, shl, pkt, sizeof pkt, &n))
        send_pkt(fd, peer, pkt, n, "ServerHello (Initial) sent\n");
    if (quic_srvloop_send_handshake(s, SERVER_SCID, sizeof SERVER_SCID, 0,
                                    flight, fll, pkt, sizeof pkt, &n))
        send_pkt(fd, peer, pkt, n, "server flight (Handshake) sent\n");
}

/* Build the server flight and seal+send it. Returns 1 on success. */
static int send_flight(i64 fd, const quic_sockaddr_in *peer, quic_server *s)
{
    u8 rnd[32], sh[512], flight[2048];
    usz shl, fll;
    fill_random(rnd);
    if (!quic_server_build_flight(s, rnd, sh, sizeof sh, &shl,
                                  flight, sizeof flight, &fll))
        return logs("flight build failed\n"), 0;
    logs("server flight built\n");
    seal_and_send(fd, peer, s, sh, shl, flight, fll);
    return 1;
}

/* Set up the orchestrator from the client's DCID and fold the ClientHello.
 * Returns 1 on success. */
static int accept_client(quic_server *s, quic_srvloop *l, const u8 *dcid,
                         u8 dcid_len, const quic_crypto_frame *cf)
{
    if (!init_server(s, l, dcid, dcid_len))
        return logs("server init failed\n"), 0;
    if (!quic_server_recv_initial(s, cf->data, (usz)cf->length))
        return logs("ClientHello rejected\n"), 0;
    logs("ClientHello received\n");
    return 1;
}

/* First datagram: open the Initial, fold the ClientHello, send the flight. */
static int on_initial(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                      quic_srvloop *l, u8 *dg, usz len)
{
    quic_crypto_frame cf;
    if (!open_initial(dg, len, &cf))
        return 0;
    log_alpn(cf.data, (usz)cf.length);
    if (!accept_client(s, l, dg + 6, dg[5], &cf))
        return 0;
    return send_flight(fd, peer, s);
}

/* Note confirmation once the server has verified the client Finished. */
static void log_confirmed(quic_server *s)
{
    if (quic_server_is_confirmed(s))
        logs("handshake confirmed\n");
}

/* A later datagram: run one real-wire step and send any sealed reply. */
static void on_step(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                    quic_srvloop *l, u8 *dg, usz len)
{
    u8 out[1500];
    usz n = 0;
    if (!quic_srvloop_step(l, s, dg, len, out, sizeof out, &n))
        return;
    send_pkt(fd, peer, out, n, "1-RTT reply sealed and sent\n");
    log_confirmed(s);
}

static i64 listen_udp(void)
{
    quic_sockaddr_in sa;
    i64 fd = quic_udp_socket();
    if (fd < 0)
        die("socket failed\n");
    quic_udp_addr(&sa, PORT, 0, 0, 0, 0);
    if (quic_udp_bind(fd, &sa) < 0)
        die("bind failed\n");
    logs("listening on 0.0.0.0:4433\n");
    return fd;
}

/* Drive one datagram: the first (long header) opens a connection and sends the
 * flight; later (short header) ones step the real-wire loop. */
static void serve(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                  quic_srvloop *l, int *up, u8 *dg, usz len)
{
    if (!*up)
        *up = on_initial(fd, peer, s, l, dg, len);
    else
        on_step(fd, peer, s, l, dg, len);
}

/* The kernel enters _start with RSP 16-byte aligned, but the SysV ABI assumes a
 * return address was pushed (RSP%16==8). Force re-alignment so SSE moves in
 * x25519/AEAD do not fault. */
__attribute__((force_align_arg_pointer)) void _start(void)
{
    i64 fd = listen_udp();
    quic_sockaddr_in peer;
    quic_server s;
    quic_srvloop l;
    u8 buf[2048];
    int up = 0;
    for (;;) {
        i64 r = quic_udp_recvfrom(fd, buf, sizeof buf, &peer);
        if (r > 0)
            serve(fd, &peer, &s, &l, &up, buf, (usz)r);
    }
}
