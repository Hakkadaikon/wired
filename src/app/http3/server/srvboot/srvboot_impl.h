#ifndef APP_HTTP3_SERVER_SRVBOOT_SRVBOOT_IMPL_H
#define APP_HTTP3_SERVER_SRVBOOT_SRVBOOT_IMPL_H

/* Internal to the srvboot*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvwire/wire.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/num.h"
#include "common/platform/clock/clock.h"
#include "tls/keys/keyring/keyring.h"
#include "transport/conn/cid/sreset/sreset.h"
#include "transport/conn/loop/crecv/collect.h"
#include "transport/conn/loop/crecv/message.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"
#include "transport/packet/header/packet/header.h"
#include "transport/packet/header/packet/pnum.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/packet/header/packet/vneg.h"
#include "transport/version/version/compat.h"
#include "transport/version/versmgr/avail.h"

/* The two pieces of a server flight: the ServerHello (Initial space) and the
 * Handshake-space flight (Certificate/CertificateVerify/Finished). */
typedef struct {
  wired_span sh;
  wired_span flight;
} srvboot_flight_bytes;

/* The server and its fixed identity, threaded together through flight
 * sealing (they always travel as a pair). cli_scid is the client's SCID from
 * its Initial: the DCID every reply is addressed to (RFC 9000 7.2), possibly
 * zero-length (Chrome). */
typedef struct {
  wired_server*           s;
  const wired_srvboot_id* id;
  u64                     ack_pn;   /**< client Initial pn the flight ACKs */
  wired_span              cli_scid; /**< reply DCID (RFC 9000 7.2) */
  u32 version; /**< the version the whole flight is sealed in: the
                * compatible version negotiated from the ClientHello's
                * version_information, else the accepted Initial's own
                * version (RFC 9368 2.2/2.3, no VN round trip) */
  u64 ini_pn;  /**< the flight's server Initial pn (wired_srvboot_flight_pn:
                * 1, or the next unused one once the space moved past it) */
  usz ini_off; /**< the ServerHello's crypto-stream offset (past the HRR
                * when one was sent, else 0 -- RFC 9000 19.6) */
  u64 ect0;    /**< RFC 9000 13.4.1: Initial ACK's cumulative ECN counts */
  u64 ect1;
  u64 ce;
} srvboot_server;

/* RFC 9000 19.6 / 14.1: TLS bytes per Handshake flight datagram. 1100 keeps
 * each sealed packet (long header + CRYPTO framing + AEAD tag) well under a
 * 1500-byte MTU datagram. */
#define SRVBOOT_HS_CHUNK 1100

/* flight sized past a real 9-cert amplificationlimit chain's Handshake
 * flight (EncryptedExtensions + 9 CERTIFICATE entries + CertificateVerify +
 * Finished) with headroom -- matches srvrun_conn.boot_hs, the buffer this
 * flight is copied into for retransmission. See
 * TLS_CERT_CHAIN_MAX/WIRED_CERTRELOAD_CHAIN_MAX. */
#define SRVBOOT_SH_MAX 512
#define SRVBOOT_HS_FLIGHT_MAX 16384

/* Coalesced packets per boot datagram (RFC 9000 12.2). */
#define SRVBOOT_ACC_PKTS 4

/* RFC 9001 4.8: 0x128 (TLS handshake_failure) when the caller has no more
 * specific sdrv_last_error cause on hand. */
#define SRVBOOT_REFUSAL_DEFAULT_ERROR 0x128

int srvboot_is_long_initial(u8 byte0, u32 version);
int srvboot_is_initial_sized(const u8* dg, usz len);
int srvboot_init(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    const wired_header*       h);
u64 srvboot_initial_pn(wired_mspan dg, u64 largest_pn);
int srvboot_flight(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out);
int srvboot_acc_admit(wired_srvboot_acc* a, wired_mspan dg);
int srvboot_acc_take(wired_srvboot_acc* a, wired_mspan pkt);

#endif
