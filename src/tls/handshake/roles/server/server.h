#ifndef QUIC_SERVER_SERVER_H
#define QUIC_SERVER_SERVER_H

#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/sdrv/sdrv.h"
#include "tls/handshake/roles/srvfin/complete.h"
#include "transport/conn/loop/crecv/collect.h"
#include "transport/io/socket/io/udp.h"

/* RFC 9001 4 / 4.1.2, RFC 8446 4 / 4.4.4, RFC 9000 7: server-side handshake
 * orchestrator, the symmetric peer of quic_client. Drives the verified parts
 * (sdrv folds the ClientHello and emits the server flight; srvfin verifies the
 * client Finished and, only on success, advances to Master, installs the 1-RTT
 * key set and confirms) to handshake confirmation and HANDSHAKE_DONE.
 *
 * All policy lives in those layers; the server wires them and gates 1-RTT
 * promotion on a verified client Finished. The data path (quic_server_feed)
 * is socket-free so it can be driven by buffer injection without a socket;
 * only quic_server_pump enters the kernel via io/udp. */

#define QUIC_SERVER_FLIGHT_MAX 2048
#define QUIC_SERVER_TRANSCRIPT_MAX 4096
#define QUIC_SERVER_DATAGRAM_MAX 1500

enum {
  QUIC_SERVER_HS_INITIAL = 0, /* awaiting the ClientHello */
  QUIC_SERVER_HS_CH_RECVD,    /* ClientHello folded, flight not sent */
  QUIC_SERVER_HS_FLIGHT_SENT, /* server flight sent, Handshake key ready */
  QUIC_SERVER_HS_CONFIRMED    /* client Finished verified, 1-RTT armed */
};

typedef struct {
  i64               fd; /* UDP socket; <0 until a socket is opened */
  quic_sockaddr_in  peer;
  quic_sdrv         sdrv;
  quic_keysched     sched;
  quic_keyset       keys;
  quic_srvfin_state fin;
  quic_crecv        crecv;
  int               phase;        /* QUIC_SERVER_HS_* */
  int               hs_done_sent; /* HANDSHAKE_DONE emitted (at most once) */
  u8  server_priv[32];            /* RFC 7748 x25519 private (owns the ECDHE) */
  u8  tr[QUIC_SERVER_TRANSCRIPT_MAX]; /* raw handshake transcript bytes */
  usz tr_len;            /* bytes through the latest folded message */
  usz tr_through_sh;     /* transcript length through ServerHello */
  usz tr_through_flight; /* transcript length through server Finished */
} quic_server;

/* Initialize the orchestrator with the server key material.
 * server_priv_x25519/server_pub_x25519 are the static ECDHE pair; cert_seed is
 * the ECDSA P-256 signing scalar (big-endian). cert_der/cert_len are ignored:
 * the driver builds its own self-signed P-256 end-entity certificate from
 * cert_seed (sdrv). No socket is opened. */
void quic_server_init(
    quic_server *s,
    const u8     server_priv_x25519[32],
    const u8     server_pub_x25519[32],
    const u8     cert_seed[32],
    const u8    *cert_der,
    usz          cert_len);

/* RFC 9000 7.3: record the DCID of the client's first Initial (the ODCID the
 * server echoes) and the server's source connection id (ISCID) so the
 * EncryptedExtensions transport parameters carry the real connection ids. Must
 * be called before build_flight. Returns 1 ok, 0 if either length exceeds 20.
 */
int quic_server_set_cids(
    quic_server *s,
    const u8    *odcid,
    u8           odcid_len,
    const u8    *iscid,
    u8           iscid_len);

/* RFC 8446 4.4.1: fold a received ClientHello (TLS handshake message bytes)
 * into the transcript. Advances INITIAL -> CH_RECVD. Returns 1 on success,
 * 0 if the message is not a usable ClientHello or out of phase. */
int quic_server_recv_initial(quic_server *s, const u8 *ch_msg, usz ch_len);

/* RFC 8446 4.4 / RFC 9001 4: build the server flight (ServerHello into sh_out,
 * EncryptedExtensions||Certificate||CertificateVerify||Finished into
 * flight_out) and derive the Handshake key. Only valid after the ClientHello
 * was received. Advances CH_RECVD -> FLIGHT_SENT. Returns 1 on success, 0
 * otherwise. */
int quic_server_build_flight(
    quic_server *s,
    const u8    *server_random,
    u8          *sh_out,
    usz          sh_cap,
    usz         *sh_len,
    u8          *flight_out,
    usz          flight_cap,
    usz         *flight_len);

/* RFC 8446 4.4.4 / RFC 9001 4.1.2: drive the handshake with one received
 * Handshake-packet CRYPTO payload (socket-free injection). Reassembles the
 * client Finished, verifies its verify_data, and ONLY on a match advances to
 * Master, installs the 1-RTT key set and confirms (CH_RECVD/FLIGHT_SENT ->
 * CONFIRMED). A forged Finished promotes nothing. Returns 1 if it advanced
 * the handshake, 0 otherwise. */
int quic_server_feed(quic_server *s, const u8 *crypto_payload, usz len);

/* RFC 9001 4.1.2 / RFC 9000 19.20: write the HANDSHAKE_DONE frame, at most
 * once and only after confirmation. Returns 1 and sets *out_len, or 0 if not
 * confirmed, already sent, or cap is 0. */
int quic_server_handshake_done(quic_server *s, u8 *out, usz cap, usz *out_len);

/* 1 once the client Finished verified and the handshake is confirmed. */
int quic_server_is_confirmed(const quic_server *s);

/* Open a UDP socket bound to port and wait for the ClientHello. Returns 1 on
 * success, 0 on socket/bind failure. */
int quic_server_listen(quic_server *s, u16 port);

/* One receive iteration: pull a datagram off the socket and feed it. Returns
 * 1 if the handshake advanced, 0 otherwise. */
int quic_server_pump(quic_server *s);

/* Pump until confirmed or max_iterations is reached (bounded so a silent or
 * hostile peer cannot wedge the server). Returns 1 if confirmed. */
int quic_server_run_handshake(quic_server *s, int max_iterations);

/* Close the UDP socket. */
void quic_server_close(quic_server *s);

#endif
