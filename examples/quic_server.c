/* Real-UDP QUIC server sample. libc-free, x86_64-linux, direct syscalls.
 *
 * Binds 0.0.0.0:4433, receives QUIC datagrams, recovers the DCID from the
 * first Initial long header, drives the handshake through quic_driver, and
 * sends each produced flight datagram back to the peer. Logs progress to
 * stderr. This is a handshake-driving demo, not a full HTTP/3 server: a real
 * certificate chain (PKI) is not wired, so curl --http3 reaches the Initial
 * exchange but does not complete TLS verification. See examples/README.md. */

#include "sys/syscall.h"
#include "io/udp.h"
#include "packet/header.h"
#include "driver/driver.h"

#define PORT 4433

/* The compiler emits memcpy for struct/array copies even under -ffreestanding;
 * with -nostdlib we must provide it ourselves. */
void *memcpy(void *dst, const void *src, usz n)
{
    u8 *d = dst;
    const u8 *s = src;
    for (usz i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

/* Write a NUL-terminated string to stderr. */
static void logs(const char *s)
{
    usz n = 0;
    while (s[n]) n++;
    syscall3(SYS_write, 2, (i64)s, (i64)n);
}

/* Log msg and exit(1). */
static void die(const char *msg)
{
    logs(msg);
    syscall1(SYS_exit, 1);
}

/* Recover the DCID from the first datagram's long header. Returns dcid_len,
 * or 0 if the datagram is not a parseable long header. */
static u8 peer_dcid(const u8 *dg, usz n, u8 *dcid)
{
    quic_header h;
    if (quic_header_parse(dg, n, &h) == 0 || h.form != QUIC_FORM_LONG)
        return 0;
    memcpy(dcid, h.dcid, h.dcid_len);
    return h.dcid_len;
}

/* Drive the server driver one round and send back the flight it produces.
 * Returns 1 if state advanced, 0 once it stalls. */
static int pump(i64 fd, quic_driver *sv, const quic_sockaddr_in *peer)
{
    u8 out[QUIC_DRIVER_DGRAM_CAP];
    usz n;
    if (quic_driver_step(sv) == 0) return 0;
    n = quic_driver_take(sv, out, sizeof out);
    if (n) quic_udp_send(fd, peer, out, n);
    return 1;
}

/* Drive the handshake to completion (or stall) for one received datagram.
 * pump returns 0 once stalled; further calls are cheap no-ops, so a fixed
 * bound needs no early break (keeps the control flow flat). */
static void serve(i64 fd, quic_driver *sv, const quic_sockaddr_in *peer)
{
    for (int i = 0; i < 32; i++) pump(fd, sv, peer);
    if (quic_driver_handshake_complete(sv)) logs("handshake complete\n");
}

/* Create and bind the listening UDP socket, or die. */
static i64 listen_udp(void)
{
    quic_sockaddr_in sa;
    i64 fd = quic_udp_socket();
    if (fd < 0) die("socket failed\n");
    quic_udp_addr(&sa, PORT, 0, 0, 0, 0);
    if (quic_udp_bind(fd, &sa) < 0) die("bind failed\n");
    logs("listening on 0.0.0.0:4433\n");
    return fd;
}

/* Bring the driver up from the first Initial if not already live. Returns 1
 * once the driver is usable for this datagram. */
static int ensure_up(quic_driver *sv, int *up, const u8 *buf, usz len)
{
    u8 dcid[QUIC_MAX_CID_LEN];
    u8 dlen;
    if (*up) return 1;
    dlen = peer_dcid(buf, len, dcid);
    if (dlen == 0) return 0;
    quic_driver_init(sv, 1, dcid, dlen);
    *up = 1;
    logs("Initial received, driving handshake\n");
    return 1;
}

/* Bring the driver up if needed, then feed and drive this datagram. */
static void handle(i64 fd, quic_driver *sv, int *up,
                   const u8 *buf, usz len, const quic_sockaddr_in *peer)
{
    if (!ensure_up(sv, up, buf, len)) return;
    quic_driver_feed(sv, buf, len);
    serve(fd, sv, peer);
}

void _start(void)
{
    i64 fd = listen_udp();
    quic_sockaddr_in peer;
    quic_driver sv;
    u8 buf[2048];
    int up = 0;
    for (;;) {
        i64 r = quic_udp_recvfrom(fd, buf, sizeof buf, &peer);
        if (r > 0) handle(fd, &sv, &up, buf, (usz)r, &peer);
    }
}
