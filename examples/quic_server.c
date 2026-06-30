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

#include "crecv/collect.h"
#include "crecv/message.h"
#include "app/http3/server/h3srv/state.h"
#include "initpkt/initopen.h"
#include "io/udp.h"
#include "packet/header.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/handshake/roles/server/server.h"
#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/tls/x25519.h"

#define PORT 4433

static void die(const char *msg);

/* In-memory message store. POST bodies are appended here (newline-separated);
 * GET returns the whole log. Lives outside the connection state on purpose:
 * re-initing a connection (RFC 9000 7) does NOT clear it, so a POST on one
 * connection is visible to a GET on a later reconnect.
 * ponytail: fixed 8 KiB, in-RAM only — a POST past the cap is silently
 * truncated; persistence/eviction would need a real store. */
#define HISTORY_MAX 8192
static u8 g_history[HISTORY_MAX];
static usz g_history_len;

/* RFC 9110 9.3.3: append the POST body (a view into per-step scratch) to the
 * history, newline-separated, truncating at the cap. */
static void history_append(const u8 *body, usz n)
{
    usz i;
    if (g_history_len < HISTORY_MAX)
        g_history[g_history_len++] = '\n';
    for (i = 0; i < n && g_history_len < HISTORY_MAX; i++)
        g_history[g_history_len++] = body[i];
}

/* Copy up to cap bytes of src into dst, returning the count copied. */
static usz copy_capped(u8 *dst, usz cap, const u8 *src, usz n)
{
    usz i;
    for (i = 0; i < n && i < cap; i++)
        dst[i] = src[i];
    return i;
}

/* RFC 9110 9.3.1 (GET) returns the whole message log; 9.3.3 (POST) appends the
 * body and echoes it back. The request body is a scratch view, so both paths
 * copy out before returning. Returns 1 (always sends a body). */
static int app_on_request(void *ctx, const quic_h3reqdrive_req *req,
                          u8 *body_out, usz cap, usz *body_len)
{
    (void)ctx;
    if (req->method_len == 4 && req->method[0] == 'P') {
        history_append(req->body, req->body_len);
        *body_len = copy_capped(body_out, cap, req->body, req->body_len);
        return 1;
    }
    *body_len = copy_capped(body_out, cap, g_history, g_history_len);
    return 1;
}

/* Self-check (ponytail: the only non-trivial logic here is the store/echo). */
static void app_selfcheck(void)
{
    u8 out[64];
    usz n = 0;
    quic_h3reqdrive_req post = {(const u8 *)"POST", 4, 0, 0, 0, 0, 0, 0,
                               (const u8 *)"hi", 2};
    quic_h3reqdrive_req get = {(const u8 *)"GET", 3, 0, 0, 0, 0, 0, 0, 0, 0};
    g_history_len = 0;
    app_on_request(0, &post, out, sizeof out, &n);
    if (n != 2 || out[0] != 'h')
        die("selfcheck: echo failed\n");
    app_on_request(0, &get, out, sizeof out, &n);
    if (n != 3 || out[1] != 'h' || out[2] != 'i')
        die("selfcheck: history failed\n");
    g_history_len = 0;
}

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

/* Cross-cutting trace logging, isolated here so the body stays clean: callers
 * write QUIC_LOG("...") and need not know about timestamps or the build flag.
 * Compiled in only with -DQUIC_DEBUG (just build-debug); a release build expands
 * QUIC_LOG to nothing, so there is no cost and no output. die() is separate and
 * always prints — a fatal error must surface even in a release build. */
#ifdef QUIC_DEBUG
/* CLOCK_REALTIME seconds.nanoseconds, no libc: kernel fills two i64 in a buffer
 * we own (struct timespec is {tv_sec, tv_nsec}; both are i64 on x86_64). */
static void put_u64(char *out, usz *at, u64 v, usz width)
{
    char tmp[20];
    usz k = 0;
    do {
        tmp[k++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);
    while (k < width)
        tmp[k++] = '0';
    while (k)
        out[(*at)++] = tmp[--k];
}

static void logt(const char *s)
{
    i64 ts[2] = {0, 0};
    char p[24];
    usz at = 0;
    syscall3(SYS_clock_gettime, 0, (i64)ts, 0);
    put_u64(p, &at, (u64)ts[0], 1);
    p[at++] = '.';
    put_u64(p, &at, (u64)ts[1], 9);
    p[at++] = ' ';
    syscall3(SYS_write, 2, (i64)p, (i64)at);
    logs(s);
}
#define QUIC_LOG(s) logt(s)
#else
#define QUIC_LOG(s) ((void)0)
#endif

/* The fixed 32-byte ServerHello.random. Deterministic for reproducibility. */
static void fill_random(u8 r[32])
{
    for (usz i = 0; i < 32; i++)
        r[i] = (u8)(0xa0 + i);
}

/* Fixed server identity: X25519 handshake key and the ECDSA P-256 signing
 * scalar (cert_seed). A demo needs no rotation; deterministic keys keep it
 * reproducible. */
static void server_keys(u8 priv[32], u8 pub[32], u8 cert_seed[32])
{
    for (usz i = 0; i < 32; i++) {
        priv[i] = (u8)(0x40 + i);
        cert_seed[i] = (u8)(0x80 + i);
    }
    quic_x25519_base(pub, priv);
}

/* Note ALPN "h3" if the ClientHello offers it (informational only). */
static void log_alpn(const u8 *ch, usz ch_len)
{
    const u8 *ext;
    usz extl;
    if (quic_salpn_find_extension(ch, ch_len, QUIC_SALPN_EXT_TYPE, &ext, &extl) &&
        quic_salpn_select_h3(ext, extl))
        QUIC_LOG("ALPN: h3 selected\n");
    else
        QUIC_LOG("ALPN: h3 not offered\n");
}

/* Seal a packet and, if non-empty, send it with a log line. */
static void send_pkt(i64 fd, const quic_sockaddr_in *peer, const u8 *pkt,
                     usz n, const char *what)
{
    if (n) {
        quic_udp_send(fd, peer, pkt, n);
        QUIC_LOG(what);
    }
}

/* A long-header Initial datagram big enough to hold byte0 + version + dcid_len
 * + DCID. The type bits (byte0 0x30) must be 00 = Initial (RFC 9000 17.2): a
 * Handshake packet is also long-header but is the same connection continuing,
 * so it must NOT be mistaken for a new connection's Initial. */
static int is_long_initial(u8 byte0)
{
    return (byte0 & 0x80) != 0 && (byte0 & 0x30) == 0;
}

static int valid_initial(const u8 *dg, usz len)
{
    if (len < 6 || !is_long_initial(dg[0]))
        return 0;
    return len >= (usz)6 + dg[5];
}

/* Walk the opened Initial payload's frames and reassemble the ClientHello from
 * its CRYPTO frame(s). curl/quiche lead with PADDING/ACK and may split the
 * ClientHello across CRYPTO frames, so crecv (framewalk + offset reassembly) is
 * used rather than assuming a single CRYPTO at the front (RFC 9000 12.4 / 19.6).
 * Returns 1 and points *msg at the contiguous ClientHello of *mlen bytes. */
static int collect_ch(quic_crecv *cr, const u8 *payload, usz plen,
                      const u8 **msg, usz *mlen)
{
    quic_crecv_init(cr);
    if (!quic_crecv_collect(cr, payload, plen))
        return QUIC_LOG("CRYPTO collect failed\n"), 0;
    if (!quic_crecv_complete_message(cr))
        return QUIC_LOG("ClientHello incomplete\n"), 0;
    quic_crecv_message(cr, msg, mlen);
    return 1;
}

/* Open the client Initial and recover the ClientHello (RFC 9000 17.2: the DCID
 * is unprotected at the front). Returns 1 and points *msg at it on success. */
static int open_initial(u8 *dg, usz len, quic_crecv *cr,
                        const u8 **msg, usz *mlen)
{
    const u8 *payload;
    usz plen;
    if (!valid_initial(dg, len))
        return 0;
    if (!quic_initpkt_open(dg + 6, dg[5], dg, len, 0, &payload, &plen))
        return QUIC_LOG("Initial open failed\n"), 0;
    QUIC_LOG("Initial received and opened\n");
    return collect_ch(cr, payload, plen, msg, mlen);
}

/* Init the orchestrator and loop with the fixed server identity. The client's
 * DCID is the ODCID (Initial keys, RFC 9001 5.2); the client's SCID is the DCID
 * the server writes back in every packet toward the client (RFC 9000 17.2 /
 * 5.1), so the loop is seeded with the SCID, not the DCID. The server driver
 * builds its own end-entity certificate from cert_seed, so no cert DER is passed
 * in. Returns 1 on success. */
static int init_server(quic_server *s, quic_srvloop *l, const u8 *dcid,
                       u8 dcid_len, const u8 *scid, u8 scid_len)
{
    u8 priv[32], pub[32], seed[32];
    server_keys(priv, pub, seed);
    quic_server_init(s, priv, pub, seed, 0, 0);
    if (!quic_server_set_cids(s, dcid, dcid_len, SERVER_SCID, sizeof SERVER_SCID))
        return 0;
    if (!quic_srvloop_init(l, scid, scid_len))
        return 0;
    quic_srvloop_set_handler(l, app_on_request, 0);
    return 1;
}

/* The client opens with its first Initial at packet number 0 (the start of the
 * Initial space), which open_initial assumes; the server acknowledges it in the
 * ServerHello Initial so curl/quiche stop retransmitting (RFC 9000 13.2.1). The
 * Handshake space has no received packets when this flight is built, so it
 * carries no ACK (-1). */
#define CLIENT_INITIAL_PN 0

/* Seal the ServerHello (Initial) and the rest of the flight (Handshake) under
 * the server's own-direction keys and send each that sealed. The Initial
 * acknowledges the client Initial (RFC 9000 13.2.1). */
static void seal_and_send(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                          const u8 *sh, usz shl, const u8 *flight, usz fll)
{
    u8 pkt[1500];
    usz n = 0;
    if (quic_srvloop_send_initial(s, SERVER_SCID, sizeof SERVER_SCID, 1,
                                  CLIENT_INITIAL_PN, sh, shl, pkt, sizeof pkt, &n))
        send_pkt(fd, peer, pkt, n, "ServerHello (Initial) sent\n");
    if (quic_srvloop_send_handshake(s, SERVER_SCID, sizeof SERVER_SCID, 0, -1,
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
        return QUIC_LOG("flight build failed\n"), 0;
    QUIC_LOG("server flight built\n");
    seal_and_send(fd, peer, s, sh, shl, flight, fll);
    return 1;
}

/* Set up the orchestrator from the client's DCID (ODCID) and SCID (the response
 * DCID) and fold the ClientHello. Returns 1 on success. */
static int accept_client(quic_server *s, quic_srvloop *l, const quic_header *h,
                         const u8 *ch, usz ch_len)
{
    if (!init_server(s, l, h->dcid, h->dcid_len, h->scid, h->scid_len))
        return QUIC_LOG("server init failed\n"), 0;
    if (!quic_server_recv_initial(s, ch, ch_len))
        return QUIC_LOG("ClientHello rejected\n"), 0;
    QUIC_LOG("ClientHello received\n");
    return 1;
}

/* First datagram: open the Initial, recover the client's CIDs from the long
 * header (RFC 9000 17.2: DCID then SCID), fold the ClientHello, send the flight.
 * The client's SCID becomes the DCID of every server reply (RFC 9000 5.1), so a
 * peer that checks the reply DCID against its own SCID (curl does) accepts it. */
static int on_initial(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                      quic_srvloop *l, u8 *dg, usz len)
{
    quic_crecv cr;
    quic_header h;
    const u8 *ch;
    usz ch_len;
    if (!open_initial(dg, len, &cr, &ch, &ch_len) ||
        !quic_header_parse(dg, len, &h))
        return 0;
    log_alpn(ch, ch_len);
    if (!accept_client(s, l, &h, ch, ch_len))
        return 0;
    return send_flight(fd, peer, s);
}

/* Note confirmation once the server has verified the client Finished. */
static void log_confirmed(quic_server *s)
{
    if (quic_server_is_confirmed(s))
        QUIC_LOG("handshake confirmed\n");
}

/* A later datagram: run one real-wire step and send any sealed reply (the
 * HANDSHAKE_DONE confirmation, or a :status 200 to a decoded GET). */
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
    QUIC_LOG("listening on 0.0.0.0:4433\n");
    return fd;
}

/* Self-check for the Initial-routing predicate: an Initial (0xc0) can start a
 * new connection, but a Handshake packet (0xe0) and a short header (0x40) are
 * the live connection continuing and must never be taken for a new Initial. */
static void cid_selfcheck(void)
{
    if (!is_long_initial(0xc0) || is_long_initial(0xe0) || is_long_initial(0x40))
        die("selfcheck: is_long_initial type bits failed\n");
}

/* RFC 9000 7: each connection is independent. A long-header Initial only starts
 * a NEW connection (a reconnect or a different client) once the live one has
 * reached HANDSHAKE_DONE. While a connection is still establishing, every Initial
 * is the same connection continuing — and its DCID legitimately changes from the
 * client's original DCID to the server's chosen SCID once ServerHello lands
 * (RFC 9000 7.2), so an ODCID comparison would wrongly see it as new. Gate the
 * reconnect decision on confirmation, not on the DCID, to avoid that.
 * ponytail: one connection at a time — reconnects are handled in arrival order,
 * not concurrent peers. A per-peer/per-DCID state table is out of scope. */
static int is_new_initial(int up, quic_server *s, u8 *dg, usz len)
{
    if (!valid_initial(dg, len))
        return 0;
    if (!up)
        return 1;
    return quic_server_is_confirmed(s);
}

/* Drive one datagram: a new Initial (re)opens a connection and sends the flight;
 * any other datagram (short header, or a same-DCID Initial retransmit) steps the
 * live real-wire loop. */
static void serve(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                  quic_srvloop *l, int *up, u8 *dg, usz len)
{
    if (is_new_initial(*up, s, dg, len))
        *up = on_initial(fd, peer, s, l, dg, len);
    else if (*up)
        on_step(fd, peer, s, l, dg, len);
}

/* The kernel enters _start with RSP 16-byte aligned, but the SysV ABI assumes a
 * return address was pushed (RSP%16==8). Force re-alignment so SSE moves in
 * x25519/AEAD do not fault. */
__attribute__((force_align_arg_pointer)) void _start(void)
{
    i64 fd;
    quic_sockaddr_in peer;
    quic_server s;
    quic_srvloop l;
    u8 buf[2048];
    int up = 0;
    app_selfcheck();
    cid_selfcheck();
    fd = listen_udp();
    for (;;) {
        i64 r = quic_udp_recvfrom(fd, buf, sizeof buf, &peer);
        if (r > 0)
            serve(fd, &peer, &s, &l, &up, buf, (usz)r);
    }
}
