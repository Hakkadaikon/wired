/* Real-UDP HTTP/3 server. libc-free, x86_64-linux, direct syscalls, own _start,
 * static.
 *
 * Binds 0.0.0.0:4433 and drives the in-tree server orchestrator
 * (quic_server_*, the symmetric peer of src/client) from a client Initial
 * toward an HTTP/3 response:
 *
 *   - recover the ClientHello from the Initial (quic_server_recv_initial),
 *   - build the server flight and install the Handshake key
 *     (quic_server_build_flight): ServerHello + EncryptedExtensions(ALPN h3 +
 *     transport params) / Certificate(ECDSA P-256) / CertificateVerify(0x0403)
 *     / Finished (RFC 8446 4.4),
 *   - seal ServerHello into a server Initial and the rest into a Handshake
 *     packet (RFC 9000 17.2) and send them,
 *   - verify the client Finished and confirm (quic_server_feed →
 *     quic_server_is_confirmed), then emit HANDSHAKE_DONE,
 *   - over 1-RTT, send SETTINGS first, decode the GET and build :status 200
 *     with a body (quic_h3srv_*).
 *
 * Each step logs to stderr. See examples/README.md for what is verified here
 * vs. what needs an external HTTP/3 client.
 *
 * ponytail: the Initial/Handshake AEAD seal/open below is the wire codec the
 * orchestrator does not own; 1-RTT STREAM protection (client Finished receipt
 * over the wire and the 1-RTT response) routes through connio and is not wired
 * here. This sample seals and sends the server flight and builds the 1-RTT
 * HANDSHAKE_DONE / HTTP/3 200 bytes; the connio 1-RTT round trip is the
 * upgrade path. */

#include "crypto_stream/crypto_tx.h"
#include "frame/frame.h"
#include "h3srv/control.h"
#include "h3srv/respond.h"
#include "h3srv/state.h"
#include "h3reqdrive/request_drive.h"
#include "hspkt/hspkt_build.h"
#include "initpkt/initkeys.h"
#include "initpkt/initopen.h"
#include "io/udp.h"
#include "pipeline/txpacket.h"
#include "salpn/ch_ext.h"
#include "salpn/negotiate.h"
#include "server/server.h"
#include "sys/syscall.h"
#include "tls/initial.h"
#include "tls/schedule.h"
#include "tls/x25519.h"

#define PORT 4433

/* The server's chosen Source Connection ID, echoed in every long header it
 * sends (RFC 9000 17.2). Fixed for a demo; swap for quic_rng_bytes per-run. */
static const u8 SERVER_SCID[8] = {0x53, 0x52, 0x56, 0x43, 0x49, 0x44, 0x30, 0x31};

/* The HTTP/3 body this server answers a GET with (RFC 9114 4.1). */
static const u8 H3_BODY[14] = {'H', 'e', 'l', 'l', 'o', ',', ' ',
                               'H', 'T', 'T', 'P', '/', '3', '!'};

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

/* Fixed server identity: X25519 handshake key and the ECDSA P-256 signing
 * scalar (cert_seed). A demo needs no rotation; deterministic keys keep it
 * reproducible.
 * ponytail: fixed seeds; swap for quic_rng_bytes if per-run keys matter. */
static void server_keys(u8 priv[32], u8 pub[32], u8 cert_seed[32])
{
    for (usz i = 0; i < 32; i++) {
        priv[i] = (u8)(0x40 + i);
        cert_seed[i] = (u8)(0x80 + i);
    }
    quic_x25519_base(pub, priv);
}

/* Seal the EE/Cert/CertVerify/Finished flight into a Handshake packet under the
 * handshake keys derived from hs_secret over ch||sh. Returns the length or 0. */
static usz seal_handshake(const u8 *hs_secret, const u8 *ch_sh, usz ch_sh_len,
                          const u8 *dcid, u8 dcid_len,
                          const u8 *flight, usz flight_len, u8 *out, usz cap)
{
    quic_initial_keys hk;
    quic_aes128 hp;
    u8 frames[2048];
    usz fl, total = 0;
    quic_tls_handshake_keys(hs_secret, ch_sh, ch_sh_len, 1, &hk);
    quic_aes128_init(&hp, hk.hp);
    if (!quic_crypto_stream_emit(flight, flight_len, 0, flight_len,
                                 frames, sizeof frames, &fl))
        return 0;
    if (!quic_hspkt_build(&hk, &hp, dcid, dcid_len,
                          SERVER_SCID, sizeof SERVER_SCID, 0,
                          frames, fl, out, cap, &total))
        return 0;
    return total;
}

/* Seal the ServerHello into a server Initial packet under the server Initial
 * keys derived from the client's DCID. Returns the length or 0. */
static usz seal_initial(const u8 *dcid, u8 dcid_len, const u8 *sh, usz sh_len,
                        u8 *out, usz cap)
{
    quic_initial_keys ck, sk;
    quic_aes128 hp;
    u8 frames[1024];
    usz fl;
    quic_initpkt_derive(dcid, dcid_len, &ck, &sk);
    quic_aes128_init(&hp, sk.hp);
    if (!quic_crypto_stream_emit(sh, sh_len, 0, sh_len, frames, sizeof frames, &fl))
        return 0;
    return quic_tx_packet(&sk, &hp, 0xc3, dcid, dcid_len,
                          SERVER_SCID, sizeof SERVER_SCID, 1,
                          (const u8 *)0, 0, 0, frames, fl, out, cap);
}

/* Note ALPN "h3" if the ClientHello offers it (informational only). */
static void log_alpn(const u8 *ch, usz ch_len)
{
    const u8 *ext;
    usz extl;
    if (quic_salpn_find_extension(ch, ch_len, QUIC_SALPN_EXT_TYPE, &ext, &extl) && quic_salpn_select_h3(ext, extl))
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

/* Drive the orchestrator from the ClientHello to FLIGHT_SENT, capturing the
 * ServerHello and the rest of the flight. Returns 1 on success. */
static int build_flight(quic_server *s, const u8 *ch, usz ch_len,
                        u8 *sh, usz *sh_len, u8 *flight, usz *fl_len)
{
    u8 rnd[32];
    fill_random(rnd);
    if (!quic_server_recv_initial(s, ch, ch_len))
        return logs("ClientHello rejected\n"), 0;
    logs("ClientHello received\n");
    if (!quic_server_build_flight(s, rnd, sh, 512, sh_len, flight, 2048, fl_len))
        return logs("flight build failed\n"), 0;
    logs("server flight built\n");
    return 1;
}

/* Seal and send the server Initial (ServerHello) and Handshake (flight). */
static void send_flight(i64 fd, const quic_sockaddr_in *peer, quic_server *s,
                        const u8 *dcid, u8 dcid_len, const u8 *ch, usz ch_len,
                        const u8 *sh, usz sh_len, const u8 *fl, usz fl_len)
{
    const u8 *hs;
    u8 pkt[1500], chsh[1024];
    quic_sdrv_handshake_secret(&s->sdrv, &hs);
    send_pkt(fd, peer, pkt, seal_initial(dcid, dcid_len, sh, sh_len, pkt, sizeof pkt),
             "ServerHello (Initial) sent\n");
    memcpy(chsh, ch, ch_len);
    memcpy(chsh + ch_len, sh, sh_len);
    send_pkt(fd, peer, pkt,
             seal_handshake(hs, chsh, ch_len + sh_len, dcid, dcid_len, fl, fl_len,
                            pkt, sizeof pkt),
             "server flight (Handshake) sent\n");
}

/* Open the server control stream (SETTINGS first) and encode a GET / request,
 * returning its length in *rlen. Returns 1 on success. */
static int h3_settings_and_get(quic_h3srv_state *st, u8 *req, usz cap, usz *rlen)
{
    const u8 path[1] = {'/'}, auth[2] = {'h', '1'};
    u8 ctrl[64];
    usz clen;
    if (!quic_h3srv_open_control(st, ctrl, sizeof ctrl, &clen))
        return 0;
    logs("HTTP/3 SETTINGS built (sent first)\n");
    return quic_h3reqdrive_send_get(0, path, sizeof path, auth, sizeof auth,
                                    req, cap, rlen);
}

/* Decode the GET into on_request and build the :status 200 + body response. */
static void h3_decode_and_respond(quic_h3srv_state *st, const u8 *req, usz rlen)
{
    u8 scratch[128], resp[256];
    usz plen;
    quic_h3reqdrive_req r;
    if (!quic_h3srv_on_request(st, req, rlen, scratch, sizeof scratch, &r))
        return;
    logs("GET decoded\n");
    if (quic_h3srv_build_response(st, 0, 200, H3_BODY, sizeof H3_BODY,
                                  resp, sizeof resp, &plen))
        logs("HTTP/3 :status 200 built\n");
}

/* RFC 9114 4.1: build the 1-RTT HTTP/3 bytes this server answers a GET with
 * once confirmed — SETTINGS first, then a 200 + body — logging each step and
 * self-decoding the GET to drive the response layer end to end without a peer.
 * ponytail: built and logged at startup to demonstrate the response layer;
 * sending these under 1-RTT AEAD (and receiving the real client GET) routes
 * through connio and is not wired here. */
static void answer_http3(void)
{
    quic_h3srv_state st = {0};
    u8 req[256];
    usz rlen;
    if (h3_settings_and_get(&st, req, sizeof req, &rlen))
        h3_decode_and_respond(&st, req, rlen);
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

/* Init the orchestrator with the fixed server identity (cert built internally
 * from the ECDSA P-256 seed) and the client's DCID as the ODCID. */
static void init_server(quic_server *s, const u8 *dcid, u8 dcid_len)
{
    u8 priv[32], pub[32], seed[32];
    server_keys(priv, pub, seed);
    quic_server_init(s, priv, pub, seed, (const u8 *)0, 0);
    quic_server_set_cids(s, dcid, dcid_len, SERVER_SCID, sizeof SERVER_SCID);
}

/* One client Initial: open it, build+send the flight, confirm and answer. */
static void handle(i64 fd, const quic_sockaddr_in *peer, u8 *dg, usz len)
{
    quic_server s;
    quic_crypto_frame cf;
    u8 sh[512], flight[2048];
    usz shl, fll;
    if (!open_initial(dg, len, &cf))
        return;
    log_alpn(cf.data, (usz)cf.length);
    init_server(&s, dg + 6, dg[5]);
    if (!build_flight(&s, cf.data, (usz)cf.length, sh, &shl, flight, &fll))
        return;
    send_flight(fd, peer, &s, dg + 6, dg[5], cf.data, (usz)cf.length, sh, shl,
                flight, fll);
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

/* The kernel enters _start with RSP 16-byte aligned, but the SysV ABI assumes a
 * return address was pushed (RSP%16==8). Force re-alignment so SSE moves in
 * x25519/AEAD do not fault. */
__attribute__((force_align_arg_pointer)) void _start(void)
{
    i64 fd = listen_udp();
    quic_sockaddr_in peer;
    u8 buf[2048];
    answer_http3();          /* demonstrate the HTTP/3 200 response bytes */
    for (;;) {
        i64 r = quic_udp_recvfrom(fd, buf, sizeof buf, &peer);
        if (r > 0)
            handle(fd, &peer, buf, (usz)r);
    }
}
