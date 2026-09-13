#ifndef CLIENT_CLIENT_H
#define CLIENT_CLIENT_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/fullhs/fullhs.h"
#include "tls/handshake/core/tlsdriver/tlsdriver.h"
#include "transport/io/socket/io/udp.h"

/* RFC 9000 5/7: top-level QUIC client. Opens a real UDP socket, connects to a
 * server, and drives the TLS 1.3 handshake to confirmation by orchestrating the
 * verified components (tlsdriver agrees the ECDHE secret over ClientHello/
 * ServerHello; fullhs sequences Certificate/CertificateVerify/Finished to
 * complete, install 1-RTT keys and confirm). All policy lives in those layers;
 * the client only wires the socket to them and dispatches each inbound TLS
 * message to the right entry point.
 *
 * Socket I/O is the only part that enters the kernel (via io/udp syscall
 * wrappers). The data-path logic is libc-free and split out so it can be driven
 * by buffer injection (client_feed) without a real socket. */

#define CLIENT_HELLO_MAX 1024
#define CLIENT_DATAGRAM_MAX 1500

enum {
  CLIENT_HS_INITIAL = 0, /* exchanging ClientHello/ServerHello */
  CLIENT_HS_AUTH,        /* handshake secret ready, fullhs driving */
  CLIENT_HS_CONFIRMED
};

/** RFC 9000 5/7: a UDP-socket-backed QUIC client driving the TLS 1.3
 * handshake to confirmation, plus the peer address and handshake state. */
typedef struct {
  i64       fd; /* UDP socket; <0 until init succeeds */
  sockaddr  peer;
  tlsdriver tls;
  fullhs    hs;
  int       phase;              /* CLIENT_HS_* */
  u8        sh_transcript[512]; /* ClientHello..ServerHello bytes for fullhs */
  usz       sh_len;
  u8        my_priv[ECDHE_LEN];
  u8        my_pub[ECDHE_LEN];
  const u8* host;         /* expected server name, view (caller-owned) */
  usz       host_len;     /* 0 skips the SAN hostname check */
  u64       now;          /* YYYYMMDDHHMMSS; 0 skips the validity check */
  const castore* castore; /* NULL skips chain validation */
} client;

/** Everything client_init needs besides the client: the server address
 * to connect to and the SNI host name to offer. */
typedef struct {
  const u8*  server_ip; /* 4-byte IPv4 octets */
  u16        port;
  wired_span server_name; /* SNI host name, view (caller-owned) */
} client_init_in;

/* Open a UDP socket, connect to in->server_ip:in->port, generate our X25519
 * key pair and initialize the handshake drivers. in->server_name names the
 * host: it is carried as SNI in the ClientHello AND enforced against the
 * server certificate's SAN (RFC 6125). server_name is a view; keep it alive
 * for the connection. init also reads the wall clock so the certificate
 * validity window (RFC 5280 6.1) is enforced by default; a clock failure
 * fails init. Returns 1 on success, 0 on RNG/clock/socket failure. */
int client_init(client* c, const client_init_in* in);

/* Override the wall clock used for the certificate validity check (packed
 * decimal YYYYMMDDHHMMSS), e.g. for deterministic tests. Passing 0 DISABLES
 * the validity check — never do that with a real peer. */
void client_set_now(client* c, u64 now);

/* RFC 5280 6.1: set the trust store the server's certificate chain must
 * anchor to. The SDK does no I/O, so the roots always come from the app;
 * without a store (the default) the chain is NOT validated — only the
 * end-entity policy (validity/SAN) and the CertificateVerify signature are.
 * store is borrowed and must outlive the connection. */
void client_set_castore(client* c, const castore* store);

/* RFC 9000 7: emit our real ClientHello, frame it, build the Initial datagram
 * (padded to 1200 per RFC 9000 14.1) and send it. Returns 1 on success. */
int client_start(client* c);

/* Build the Initial datagram into out (cap bytes): ClientHello as CRYPTO
 * frame(s), padded to 1200. Socket-free; returns the datagram length or 0. */
usz client_build_initial(client* c, u8* out, usz cap);

/* Drive the handshake with one already-received TLS-message-bearing CRYPTO
 * frame payload (socket-free injection). Dispatches by phase: a ServerHello to
 * the tlsdriver, then Certificate/CertificateVerify/Finished/HANDSHAKE_DONE to
 * fullhs. Returns 1 if it advanced the handshake, 0 otherwise.
 *
 * HelloRetryRequest (RFC 8446 4.1.4) is NOT negotiated: this client offers
 * one group (x25519) and always sends its key_share, so any HRR selects a
 * group it never advertised or already shared, and both are illegal_parameter
 * by 4.1.4. There is deliberately no second-ClientHello path (no cookie echo,
 * no PSK re-offer/omission): an HRR -- recognised by its random sentinel, so a
 * cookie-only one included -- is a clean abort, tlsdriver_last_error reports
 * err_crypto(47), the phase stays CLIENT_HS_INITIAL and the connection is
 * dead. A server that needs a cookie round-trip cannot be reached until an
 * HRR retry path is added alongside a second offered group. */
int client_feed(client* c, const u8* crypto_payload, usz len);

/* One receive iteration: pull a datagram off the socket and feed it. Returns 1
 * if the handshake advanced, 0 if nothing was read or it did not advance. */
int client_pump(client* c);

/* Pump until the handshake is confirmed or max_iterations is reached (RFC 9000:
 * bounded so a silent/hostile peer cannot wedge the client). Returns 1 if
 * confirmed. */
int client_run_handshake(client* c, int max_iterations);

/* 1 once the handshake is complete and confirmed. */
int client_is_connected(const client* c);

/* Close the UDP socket and wipe the key schedule's retained secrets
 * (RFC 8446 E.1.4: the exporter_master_secret is erased at teardown). */
void client_close(client* c);

#endif
