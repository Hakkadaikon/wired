/* Real-UDP HTTP/3 server. libc-free, x86_64-linux, direct syscalls, own _start,
 * static. Driven by the single SDK header <wired.h>.
 *
 * Binds 0.0.0.0:4433. A client Initial cold-starts a connection via
 * wired_srvboot_accept (recover ClientHello -> build+seal the server flight);
 * every later datagram runs one quic_srvloop_step (confirm the handshake, then
 * answer a 1-RTT GET/POST). Each sealed reply is sent straight back. The app
 * logic is a message log: POST appends and echoes, GET returns the whole log.
 * See examples/README.md for what completes here vs. what an external HTTP/3
 * client additionally needs. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "wired.h"

#define PORT 4433

static void die(const char *msg);

/* In-memory message store. POST bodies are appended (newline-separated); GET
 * returns the whole log. Outside the connection state on purpose: re-initing a
 * connection (RFC 9000 7) does NOT clear it, so a POST is visible to a later
 * GET on a reconnect.
 * ponytail: fixed 8 KiB, in-RAM only — a POST past the cap is truncated. */
#define HISTORY_MAX 8192
static u8  g_history[HISTORY_MAX];
static usz g_history_len;

/* RFC 9110 9.3.3: append the POST body, newline-separated, truncating at cap. */
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

/* RFC 9110 9.3.1 (GET) returns the log; 9.3.3 (POST) appends and echoes. The
 * request body is a scratch view, so both paths copy out. Always sends a body. */
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

/* Self-check (ponytail: the only non-trivial app logic is the store/echo). */
static void app_selfcheck(void)
{
    u8  out[64];
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

/* The server's Source Connection ID, written in every reply (RFC 9000 17.2).
 * Fixed for a demo. */
static const u8 SERVER_SCID[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

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

/* Trace logging under -DQUIC_DEBUG (just build-debug); a release build expands
 * QUIC_LOG to nothing. die() always prints — a fatal error must surface. */
#ifdef QUIC_DEBUG
static void put_u64(char *out, usz *at, u64 v, usz width)
{
    char tmp[20];
    usz  k = 0;
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
    i64  ts[2] = {0, 0};
    char p[24];
    usz  at = 0;
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

/* Fixed, deterministic server identity for wired_srvboot_accept: X25519
 * handshake key pair, the ECDSA P-256 signing scalar (cert_seed), the server
 * SCID, and a fixed ServerHello random. A demo needs no rotation. */
static void server_identity(wired_srvboot_id *id, u8 priv[32], u8 pub[32],
                            u8 seed[32], u8 rnd[32])
{
    for (usz i = 0; i < 32; i++) {
        priv[i] = (u8)(0x40 + i);
        seed[i] = (u8)(0x80 + i);
        rnd[i]  = (u8)(0xa0 + i);
    }
    quic_x25519_base(pub, priv);
    id->priv      = priv;
    id->pub       = pub;
    id->cert_seed = seed;
    id->scid      = SERVER_SCID;
    id->scid_len  = sizeof SERVER_SCID;
    id->random    = rnd;
}

/* Send a sealed buffer with a log line (skip an empty one). */
static void send_pkt(i64 fd, const quic_sockaddr_in *peer, const u8 *pkt,
                     usz n, const char *what)
{
    if (n) {
        quic_udp_send(fd, peer, pkt, n);
        QUIC_LOG(what);
    }
}

/* First datagram: cold-start the connection and send the sealed flight. Returns
 * 1 once the server is up. */
static int on_initial(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                      quic_srvloop *l, u8 *dg, usz len)
{
    wired_srvboot_id id;
    u8  priv[32], pub[32], seed[32], rnd[32], out[1500];
    usz n = 0;
    server_identity(&id, priv, pub, seed, rnd);
    if (!wired_srvboot_accept(s, l, &id, dg, len, out, sizeof out, &n))
        return QUIC_LOG("srvboot accept failed\n"), 0;
    quic_srvloop_set_handler(l, app_on_request, 0);
    send_pkt(fd, peer, out, n, "server flight sent\n");
    return 1;
}

/* A later datagram: one real-wire step, send any sealed reply. */
static void on_step(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                    quic_srvloop *l, u8 *dg, usz len)
{
    u8  out[1500];
    usz n = 0;
    if (quic_srvloop_step(l, s, dg, len, out, sizeof out, &n))
        send_pkt(fd, peer, out, n, "1-RTT reply sealed and sent\n");
}

static i64 listen_udp(void)
{
    quic_sockaddr_in sa;
    i64              fd = quic_udp_socket();
    if (fd < 0)
        die("socket failed\n");
    quic_udp_addr(&sa, PORT, 0, 0, 0, 0);
    if (quic_udp_bind(fd, &sa) < 0)
        die("bind failed\n");
    QUIC_LOG("listening on 0.0.0.0:4433\n");
    return fd;
}

/* RFC 9000 7: a long-header Initial only starts a NEW connection once the live
 * one is confirmed; while establishing, every Initial is the same connection
 * continuing (its DCID legitimately changes after ServerHello, so gate on
 * confirmation, not the DCID).
 * ponytail: one connection at a time, handled in arrival order. */
static int is_new_initial(int up, quic_server *s, u8 *dg, usz len)
{
    if (!wired_srvboot_is_initial(dg, len))
        return 0;
    if (!up)
        return 1;
    return quic_server_is_confirmed(s);
}

/* Drive one datagram: a new Initial (re)opens the connection; anything else
 * steps the live loop. */
static void serve(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                  quic_srvloop *l, int *up, u8 *dg, usz len)
{
    if (is_new_initial(*up, s, dg, len))
        *up = on_initial(fd, peer, s, l, dg, len);
    else if (*up)
        on_step(fd, peer, s, l, dg, len);
}

/* The kernel enters _start 16-byte aligned, but the SysV ABI assumes a return
 * address was pushed (RSP%16==8). Force re-alignment so SSE moves in
 * x25519/AEAD do not fault. */
__attribute__((force_align_arg_pointer)) void _start(void)
{
    i64              fd;
    quic_sockaddr_in peer;
    quic_server      s;
    quic_srvloop     l;
    u8               buf[2048];
    int              up = 0;
    app_selfcheck();
    fd = listen_udp();
    for (;;) {
        i64 r = quic_udp_recvfrom(fd, buf, sizeof buf, &peer);
        if (r > 0)
            serve(fd, &peer, &s, &l, &up, buf, (usz)r);
    }
}
