/* Real TLS 1.3 server-flight QUIC server. libc-free, x86_64-linux, direct
 * syscalls, own _start, static.
 *
 * Binds 0.0.0.0:4433, receives a client Initial datagram, opens it with the
 * Initial keys derived from the client's DCID (RFC 9001 5.2), recovers the
 * ClientHello from its CRYPTO frame, negotiates ALPN "h3", builds a runtime
 * self-signed Ed25519 certificate, and drives the server handshake driver to
 * emit the *real* TLS bytes of the server flight (ServerHello +
 * EncryptedExtensions/Certificate/CertificateVerify/Finished, RFC 8446 4.4).
 * ServerHello is sealed into a server Initial packet; the rest is carried in a
 * Handshake packet (RFC 9000 17.2.4) under the derived handshake keys. Both
 * are sent back to the peer. Each step logs to stderr.
 *
 * This repository's packet codec uses a simplified long header (no SCID/token/
 * length), so it does not interoperate with curl --http3 on the wire; this
 * binary demonstrates building and sending real server-flight bytes. See
 * examples/README.md. */

#include "aes/aes.h"
#include "crypto_stream/crypto_tx.h"
#include "frame/frame.h"
#include "hspkt/hspkt_build.h"
#include "initpkt/initkeys.h"
#include "initpkt/initopen.h"
#include "io/udp.h"
#include "pipeline/txpacket.h"
#include "salpn/ch_ext.h"
#include "salpn/negotiate.h"
#include "sdrv/sdrv.h"
#include "selfcert/selfcert.h"
#include "stp/server_tp.h"
#include "sys/syscall.h"
#include "tls/initial.h"
#include "tls/schedule.h"
#include "tls/x25519.h"

#define PORT 4433

/* The compiler emits memcpy for struct/array copies even under -ffreestanding;
 * with -nostdlib we must supply it. */
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

/* Fixed server identity: x25519 handshake key and Ed25519 certificate seed.
 * A demo server needs no key rotation; deterministic keys keep it reproducible.
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
 * handshake keys derived from hs_secret over ch||sh. Returns the packet length
 * or 0. */
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
    if (!quic_hspkt_build(&hk, &hp, dcid, dcid_len, 0, 0, 0,
                          frames, fl, out, cap, &total))
        return 0;
    return total;
}

/* Seal the ServerHello into a server Initial packet under the server Initial
 * keys derived from the client's DCID. Returns the packet length or 0. */
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
    return quic_tx_packet(&sk, &hp, 0xc3, dcid, dcid_len, 0, frames, fl, out, cap);
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

/* The bytes the server flight produces, plus the handshake secret needed to
 * seal them. */
typedef struct {
    u8 sh[512];
    usz sh_len;
    u8 flight[2048];
    usz fl_len;
    const u8 *hs_secret;
} server_flight;

/* Build the server's self-signed cert into cert (caller-owned; sdrv keeps the
 * pointer, so it must outlive the driver) and init the driver. Returns 1 ok. */
static int setup_sdrv(quic_sdrv *s, u8 *cert, usz cert_cap)
{
    u8 priv[32], pub[32], seed[32];
    usz cert_len;
    server_keys(priv, pub, seed);
    if (!quic_selfcert_build(seed, cert, cert_cap, &cert_len))
        return logs("cert build failed\n"), 0;
    logs("certificate built\n");
    quic_sdrv_init(s, priv, pub, seed, cert, cert_len);
    return 1;
}

/* Feed the ClientHello and emit the flight bytes. Returns 1 on success. */
static int run_sdrv(quic_sdrv *s, const u8 *ch, usz ch_len, server_flight *out)
{
    u8 srv_random[32];
    fill_random(srv_random);
    if (!quic_sdrv_recv_client_hello(s, ch, ch_len))
        return logs("ClientHello rejected\n"), 0;
    if (!quic_sdrv_build_server_flight(s, srv_random, out->sh, sizeof out->sh,
                                       &out->sh_len, out->flight,
                                       sizeof out->flight, &out->fl_len))
        return logs("flight build failed\n"), 0;
    return 1;
}

/* Drive sdrv from the ClientHello into a server_flight. Returns 1 on success;
 * on failure the called helper logs the reason. */
static int build_flight(const u8 *ch, usz ch_len, server_flight *out)
{
    quic_sdrv s;
    u8 cert[1024]; /* sdrv keeps this pointer; must outlive run_sdrv */
    if (!setup_sdrv(&s, cert, sizeof cert) || !run_sdrv(&s, ch, ch_len, out))
        return 0;
    logs("server flight built\n");
    quic_sdrv_handshake_secret(&s, &out->hs_secret);
    return 1;
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

/* Build the full server flight from the ClientHello and send the Initial
 * (ServerHello) and Handshake (EE/Cert/CV/Fin) packets to the peer. */
static void respond(i64 fd, const quic_sockaddr_in *peer, const u8 *dcid,
                    u8 dcid_len, const u8 *ch, usz ch_len)
{
    server_flight f;
    u8 pkt[1500], chsh[1024];
    if (!build_flight(ch, ch_len, &f))
        return;
    send_pkt(fd, peer, pkt,
             seal_initial(dcid, dcid_len, f.sh, f.sh_len, pkt, sizeof pkt),
             "ServerHello (Initial) sent\n");
    memcpy(chsh, ch, ch_len);
    memcpy(chsh + ch_len, f.sh, f.sh_len);
    send_pkt(fd, peer, pkt,
             seal_handshake(f.hs_secret, chsh, ch_len + f.sh_len, dcid, dcid_len,
                            f.flight, f.fl_len, pkt, sizeof pkt),
             "server flight (Handshake) sent\n");
}

/* A long-header datagram big enough to hold the simplified header and its DCID. */
static int valid_initial(const u8 *dg, usz len)
{
    if (len < 6 || (dg[0] & 0x80) == 0)
        return 0;
    return len >= (usz)10 + dg[5];
}

/* Open the client Initial and recover the ClientHello CRYPTO. The DCID sits
 * unprotected in the simplified long header (byte0, 4-byte version, dcid_len,
 * dcid, 4-byte pn) emitted by quic_tx_packet; read it directly rather than via
 * the RFC-invariant parser, which expects an SCID the wire format omits and
 * would misread a header-protected packet-number byte. Returns 1 and fills
 * *cf on success. */
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

static void handle(i64 fd, const quic_sockaddr_in *peer, u8 *dg, usz len)
{
    quic_crypto_frame cf;
    if (!open_initial(dg, len, &cf))
        return;
    log_alpn(cf.data, (usz)cf.length);
    respond(fd, peer, dg + 6, dg[5], cf.data, (usz)cf.length);
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

/* The kernel enters _start with RSP 16-byte aligned, but the SysV ABI's
 * in-function alignment assumes a return address was pushed (RSP%16==8). Force
 * the entry to re-align so SSE moves in x25519/AEAD do not fault. */
__attribute__((force_align_arg_pointer)) void _start(void)
{
    i64 fd = listen_udp();
    quic_sockaddr_in peer;
    u8 buf[2048];
    for (;;) {
        i64 r = quic_udp_recvfrom(fd, buf, sizeof buf, &peer);
        if (r > 0)
            handle(fd, &peer, buf, (usz)r);
    }
}
