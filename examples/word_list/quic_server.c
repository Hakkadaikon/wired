/* Real-UDP HTTP/3 server. libc-free, x86_64-linux, direct syscalls, own _start,
 * static. Driven by the single SDK header <wired.h>.
 *
 * The whole server — bind, receive, cold-start each client Initial, drive the
 * handshake, answer HTTP/3 requests, seal every reply — is wired_server_run.
 * This file is just the application: a message log (POST appends and echoes,
 * GET returns the whole log), the demo server identity, and the freestanding
 * entry point. See examples/README.md for what completes here vs. what an
 * external HTTP/3 client additionally needs. */

#define WIRED_MAIN /* this TU emits the libc memcpy/memset shim */
#include "wired.h"

#define PORT 4433

/* A fatal error: print and exit (freestanding, no libc atexit). */
static void die(const char *msg)
{
    wired_log_str(msg);
    syscall1(SYS_exit, 1);
}

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

/* Copy up to out->cap bytes of src into out, setting out->len to the count
 * copied. */
static void copy_capped(quic_obuf *out, quic_span src)
{
    usz i;
    for (i = 0; i < src.n && i < out->cap; i++)
        out->p[i] = src.p[i];
    out->len = i;
}

/* RFC 9110 9.3.1 (GET) returns the log; 9.3.3 (POST) appends and echoes. The
 * request body is a scratch view, so both paths copy out. Always sends a body. */
static int app_on_request(
    void *ctx, const quic_h3reqdrive_req *req, quic_obuf *body_out)
{
    (void)ctx;
    if (req->method_len == 4 && req->method[0] == 'P') {
        history_append(req->body, req->body_len);
        copy_capped(body_out, quic_span_of(req->body, req->body_len));
        return 1;
    }
    copy_capped(body_out, quic_span_of(g_history, g_history_len));
    return 1;
}

/* Self-check (ponytail: the only non-trivial app logic is the store/echo). */
static void app_selfcheck(void)
{
    u8  out[64];
    quic_obuf ob = {out, sizeof out, 0};
    quic_h3reqdrive_req post = {(const u8 *)"POST", 4, 0, 0, 0, 0, 0, 0,
                               (const u8 *)"hi", 2};
    quic_h3reqdrive_req get = {(const u8 *)"GET", 3, 0, 0, 0, 0, 0, 0, 0, 0};
    g_history_len = 0;
    app_on_request(0, &post, &ob);
    if (ob.len != 2 || out[0] != 'h')
        die("selfcheck: echo failed\n");
    app_on_request(0, &get, &ob);
    if (ob.len != 3 || out[1] != 'h' || out[2] != 'i')
        die("selfcheck: history failed\n");
    g_history_len = 0;
}

/* Fixed, deterministic server identity for wired_server_run: X25519 handshake
 * key pair, the ECDSA P-256 signing scalar (cert_seed), the server SCID, and a
 * fixed ServerHello random. A demo needs no rotation. */
static const u8 SERVER_SCID[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

/* The demo server's fixed key material buffers, owned by the caller (_start)
 * so they outlive wired_server_run. */
typedef struct {
    u8 priv[32];
    u8 pub[32];
    u8 seed[32];
    u8 rnd[32];
} server_keys;

static void server_identity(wired_srvboot_id *id, server_keys *k)
{
    for (usz i = 0; i < 32; i++) {
        k->priv[i] = (u8)(0x40 + i);
        k->seed[i] = (u8)(0x80 + i);
        k->rnd[i]  = (u8)(0xa0 + i);
    }
    quic_x25519_base(k->pub, k->priv);
    id->priv      = k->priv;
    id->pub       = k->pub;
    id->cert_seed = k->seed;
    id->scid      = SERVER_SCID;
    id->scid_len  = sizeof SERVER_SCID;
    id->random    = k->rnd;
}

/* The kernel enters _start 16-byte aligned, but the SysV ABI assumes a return
 * address was pushed (RSP%16==8). Force re-alignment so SSE moves in
 * x25519/AEAD do not fault. */
__attribute__((force_align_arg_pointer)) void _start(void)
{
    wired_srvboot_id id;
    server_keys      keys;
    wired_srvrun_handler h = {app_on_request, 0};
    app_selfcheck();
    server_identity(&id, &keys);
    if (!wired_server_run(PORT, &id, h))
        die("listen failed\n");
    syscall1(SYS_exit, 0);
}
