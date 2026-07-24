#ifndef WIRED_SRVBOOT_SRVBOOT_H
#define WIRED_SRVBOOT_SRVBOOT_H

#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/span/span.h"
#include "tls/handshake/roles/server/server.h"
#include "transport/conn/loop/crecv/collect.h"
#include "transport/packet/header/packet/header.h"

/** @file
 * RFC 9000 17.2 / RFC 9001 5 / RFC 8446 4.4: cold-start a server connection
 * from a client Initial datagram. The symmetric partner of
 * wired_srvloop_step: srvloop_step drives the live connection, this bootstraps
 * it. Both are socket-free (buffer in, sealed replies out) so the SDK core
 * stays kernel-free; the caller does the UDP send. */

/** The fixed server identity a bootstrap needs: the X25519 handshake key pair,
 * the ECDSA P-256 signing scalar the server builds its end-entity certificate
 * from, the server's source connection id (written in every reply), and the
 * ServerHello random. chain/chain_count, when non-empty, are an externally
 * issued certificate chain (leaf first) to send instead of a self-signed
 * certificate. All views; the caller keeps them alive for the call. */
typedef struct {
  const u8*        priv;        /**< X25519 private, 32 bytes */
  const u8*        pub;         /**< X25519 public, 32 bytes */
  const u8*        cert_seed;   /**< ECDSA P-256 signing scalar, 32 bytes */
  const u8*        scid;        /**< server source connection id */
  u8               scid_len;    /**< scid length in octets, at most 20 */
  const u8*        random;      /**< ServerHello.random, 32 bytes */
  const quic_span* chain;       /**< optional: external chain, leaf first */
  usz              chain_count; /**< entries in chain; 0 = self-signed */
  u64              max_data;    /**< advertised initial_max_data; 0 = default */
  u64 max_streams_bidi; /**< advertised initial_max_streams_bidi; 0 = default */
  u64 max_datagram_frame_size; /**< advertised max_datagram_frame_size
                                * (RFC 9221 3); 0 = not advertised (no
                                * default -- opt in once DATAGRAM delivery is
                                * wired end-to-end) */
  /** RFC 5280 4.2.1.6: 4-byte IPv4 address (network byte order) added to the
   * self-signed certificate's Subject Alternative Name as an iPAddress
   * entry, alongside the fixed dNSName=localhost -- a browser validating a
   * WebTransport connection to a bare IP literal checks this entry (RFC 9110
   * 4.3.5), not just the serverCertificateHashes-pinned hash. 0 to omit
   * (dNSName=localhost only, the pre-existing behavior). Ignored when
   * chain_count > 0 (an external chain's own SAN is used as-is). */
  const u8* san_ipv4;
  /** RFC 5280 4.1.2.5.1: UNIX epoch seconds the self-signed certificate's
   * validity window is anchored to (notBefore = now_secs, notAfter =
   * now_secs + 14 days -- the W3C WebTransport spec's
   * serverCertificateHashes pinning rejects any cert whose validity window
   * exceeds 14 days). Pass quic_clock_epoch_secs() for a real deployment; 0
   * keeps a fixed 2020-2030 window (tests only -- that window is far outside
   * 14 days and will fail serverCertificateHashes validation in a browser).
   * Ignored when chain_count > 0. */
  u64 now_secs;
  /** RFC 9000 7.3 after a Retry: the true original DCID (recovered from the
   * validated Retry token) to advertise as
   * original_destination_connection_id; when set, the accepted Initial's own
   * header DCID (the Retry's SCID) is advertised as
   * retry_source_connection_id. 0/0 on the normal no-Retry path. */
  const u8* retry_odcid;
  /** Bytes at retry_odcid; 0 = no Retry preceded this accept. */
  u8 retry_odcid_len;
  /** RFC 8446 4.6.1: this server's session-ticket encryption key
   * (QUIC_TICKET_KEY_LEN bytes, tls/keys/ticket/ticket.h), or 0 to disable
   * session resumption -- threaded straight to
   * wired_server_init_in.ticket_key, see its doc. */
  const u8* ticket_key;
} wired_srvboot_id;

/** RFC 9000 17.2: 1 if dg is a long-header Initial datagram (a Handshake or
 * short-header packet is the live connection continuing, not a new Initial).
 * @param dg the datagram bytes as received from the socket
 * @param len length of dg in octets
 * @return 1 if dg is a long-header Initial datagram, 0 otherwise */
int wired_srvboot_is_initial(const u8* dg, usz len);

/** RFC 9000 17.2.3: 1 if dg is a long-header 0-RTT datagram. Read before any
 * key exists to open it with -- only the type bits are needed, same scope
 * as wired_srvboot_is_initial's own byte0-vs-version read.
 * @param dg the datagram bytes as received from the socket
 * @param len length of dg in octets
 * @return 1 if dg is a long-header 0-RTT datagram, 0 otherwise */
int wired_srvboot_is_zerortt(const u8* dg, usz len);

/** The server orchestrator and its HTTP/3 loop, freshly cold-started by
 * wired_srvboot_accept and driven together thereafter (wired_srvloop_step
 * takes the same pair). */
typedef struct {
  wired_server*  s; /**< server-side handshake orchestrator */
  wired_srvloop* l; /**< HTTP/3 wire loop driven after the bootstrap */
} wired_srvboot_conn;

/** The fixed server identity to boot with and the client's Initial datagram to
 * recover the ClientHello from. */
typedef struct {
  const wired_srvboot_id* id;    /**< fixed server identity to boot with */
  quic_mspan              dgram; /**< the client's Initial datagram */
} wired_srvboot_in;

/** Most Handshake flight datagrams a bootstrap seals: sized past
 * quic-interop-runner's deliberately inflated 9-cert amplificationlimit
 * chain (~10KB TLS flight, ~10 chunks at the per-datagram CRYPTO chunk
 * size) with headroom. */
#define WIRED_SRVBOOT_FLIGHT_MAX 12

/** The sealed reply datagrams of a bootstrap. The Initial is kept separate
 * because it alone is padded to 1200 bytes (RFC 9000 14.1); a TLS flight too
 * large for one MTU datagram is split into several Handshake packets
 * (RFC 9000 19.6), concatenated in flight and sliced by dgram_len. The caller
 * sends the Initial first, then each flight slice as its own UDP datagram. */
typedef struct {
  quic_obuf* initial; /**< sealed server Initial datagram (>= 1200 bytes) */
  quic_obuf* flight;  /**< all sealed Handshake datagrams, concatenated */
  usz dgram_len[WIRED_SRVBOOT_FLIGHT_MAX]; /**< each flight datagram's length */
  usz dgram_count; /**< flight datagrams sealed (their lengths sum to
                      flight->len) */
  u64 client_pn;   /**< the client Initial's recovered packet number (the one
                      the server Initial acknowledges, RFC 9000 13.2.1) */
} wired_srvboot_out;

/** Recover the ClientHello from the protected Initial datagram, initialize the
 * server and its HTTP/3 loop with in->id, build the server flight, and seal
 * it: a server Initial (ServerHello, acknowledging the client Initial) into
 * out->initial, and the Handshake flight (Certificate/CertificateVerify/
 * Finished) into out->flight as one Handshake packet datagram per CRYPTO
 * chunk (RFC 9000 19.6), recording each datagram's length in out->dgram_len
 * and the count in out->dgram_count. Sets both obufs' len.
 * The caller registers its request handler on conn->l via
 * wired_srvloop_set_handler.
 * @param conn the orchestrator/loop pair to cold-start
 * @param in the fixed server identity and the client's Initial datagram
 * @param out receives the sealed server Initial and Handshake datagrams
 * @return 1 on success, 0 if the datagram is not a valid Initial, the
 *   open/reassembly fails, or the flight cannot be built or does not fit. */
int wired_srvboot_accept(
    const wired_srvboot_conn* conn,
    const wired_srvboot_in*   in,
    wired_srvboot_out*        out);

/** Answer a long-header datagram of an unsupported version with a Version
 * Negotiation packet offering this server's supported versions -- v2 then v1
 * (RFC 9368 5), connection ids swapped (RFC 9000 5.2.2 / RFC 8999 6). No
 * response for: a datagram under 1200 bytes (amplification guard, RFC 9000
 * 6), version 0 (never answer a Version Negotiation packet with another,
 * RFC 9000 6.1), a supported version (v1 or v2), a short header, or an
 * unparseable header.
 * @param dg the received datagram
 * @param out receives the Version Negotiation packet
 * @param cap bytes available at out
 * @return bytes written, or 0 when no response is owed. */
usz wired_srvboot_vneg(quic_span dg, u8* out, usz cap);

/** Datagrams a boot's accumulator holds verbatim while waiting for 0-RTT keys
 * (wired_srvboot_acc.zerortt_dg): comfortably past a real quic-go 0-RTT
 * burst (26 single-packet datagrams observed live). */
#define WIRED_SRVBOOT_ZERORTT_MAX 32
/** Byte capacity of one buffered 0-RTT datagram: past RFC 9000 14.1's
 * 1200-byte Initial floor and a real Ethernet MTU's ~1500-byte payload, the
 * range every 0-RTT datagram observed live falls within. */
#define WIRED_SRVBOOT_ZERORTT_DG_MAX 1500

/** One nascent connection's ClientHello reassembly across Initial datagrams:
 * a ClientHello too big for one Initial (a post-quantum hybrid key share
 * pushes it near 1.7KB) arrives as CRYPTO chunks spread over several packets
 * (RFC 9000 19.6), and the server may not build its flight until the whole
 * message is contiguous. */
typedef struct {
  quic_crecv   cr;  /**< CRYPTO stream reassembly buffer */
  wired_header hdr; /**< the first datagram's header: its DCID is the ODCID
                       the Initial keys derive from (fixed for the whole
                       boot), its SCID the id the server replies to */
  u64 largest_pn;   /**< highest Initial packet number opened so far (the one
                       the boot flight acknowledges, RFC 9000 13.2.1) */
  int any;          /**< 1 once the first datagram bound this accumulator */
  usz opened;       /**< Initial packets successfully opened so far — 0 means
                       nothing authenticated yet and the attempt is
                       abandonable without loss */
  /** Next server Initial packet number for a partial-ClientHello ACK
   * (wired_srvboot_partial_ack). Starts at 2: the accept flight's own
   * server Initial is pn 1, and reusing it would make the peer drop the
   * flight as a duplicate. */
  u64 ack_pn;
  /** An additional DCID admitted alongside the bound one
   * (wired_srvboot_acc_allow): the server's own scid, which the client
   * switches to after the first server packet (RFC 9000 7.2). The Initial
   * keys stay the bound ODCID's either way (RFC 9001 5.2). */
  u8 alt_dcid[WIRED_MAX_CID_LEN];
  /** Length of alt_dcid; 0 while none is allowed. */
  u8 alt_dcid_len;
  /** RFC 9001 4.6.1: 0-RTT datagrams arrive interleaved with the Initials
   * this accumulator is reassembling the ClientHello from, but their own
   * packet-protection keys (quic_sdrv_early_keys) do not exist until the
   * ClientHello is complete and the server has accepted the PSK -- so each
   * whole raw 0-RTT datagram is held here verbatim and only opened once
   * wired_srvboot_accept_acc succeeds (RFC 9000 12.2: never split a
   * datagram's own coalesced packets apart, replay each one exactly as
   * received). A datagram beyond WIRED_SRVBOOT_ZERORTT_MAX is simply dropped
   * (its stream data is resent by the client's own retransmission once
   * 0-RTT keys never confirm it, or is covered once the client re-sends
   * over 1-RTT). */
  u8 zerortt_dg[WIRED_SRVBOOT_ZERORTT_MAX][WIRED_SRVBOOT_ZERORTT_DG_MAX];
  /** Byte length of each held 0-RTT datagram in zerortt_dg. */
  usz zerortt_len[WIRED_SRVBOOT_ZERORTT_MAX];
  /** Number of 0-RTT datagrams currently held. */
  usz zerortt_n;
} wired_srvboot_acc;

/** Empty the accumulator for a fresh connection attempt.
 * @param a the accumulator to reset */
void wired_srvboot_acc_reset(wired_srvboot_acc* a);

/** Absorb one Initial datagram: every coalesced Initial packet in it is
 * opened with the bound ODCID's keys and its CRYPTO chunks land at their
 * stream offsets (duplicates and any arrival order are fine). The first
 * datagram binds the accumulator; later ones must repeat its DCID. RFC 9001
 * 4.6.1: a datagram whose leading packet is 0-RTT instead (no Initial keys
 * exist to open it with yet) is held verbatim in a's zerortt_dg buffer
 * rather than refused, for wired_srvboot_acc_zerortt_take to open once
 * wired_srvboot_accept_acc succeeds.
 * @param a the accumulator
 * @param dg the received datagram (opened in place)
 * @return 1 if at least one Initial packet in the datagram authenticated
 *   and was absorbed, or the datagram was buffered as 0-RTT; 0 if it was
 *   refused outright (unparseable, a foreign DCID, or nothing in it opened
 *   under the bound keys). */
int wired_srvboot_acc_feed(wired_srvboot_acc* a, quic_mspan dg);

/** @param a the accumulator
 * @return the number of whole 0-RTT datagrams buffered in a
 *   (wired_srvboot_acc_zerortt_take indexes 0..this). */
usz wired_srvboot_acc_zerortt_count(const wired_srvboot_acc* a);

/** The i'th buffered 0-RTT datagram, verbatim as received.
 * @param a the accumulator
 * @param i index, 0 <= i < wired_srvboot_acc_zerortt_count(a)
 * @return the datagram's bytes as a view into a's own storage. */
quic_span wired_srvboot_acc_zerortt_take(const wired_srvboot_acc* a, usz i);

/** Admit dcid alongside the bound one: after the server's first packet the
 * client switches its DCID to the server's scid (RFC 9000 7.2), and its
 * remaining ClientHello pieces arrive under that new DCID. Keys stay the
 * bound ODCID's (RFC 9001 5.2).
 * @param a the accumulator
 * @param dcid the additional DCID to admit (the server's own scid) */
void wired_srvboot_acc_allow(wired_srvboot_acc* a, quic_span dcid);

/** Seal an ACK-only server Initial acknowledging the highest Initial opened
 * so far (RFC 9000 13.2.1) — sent while the ClientHello is still
 * incomplete, so a client whose missing piece keeps getting dropped still
 * hears the server is alive instead of timing out. No-op before anything
 * authenticated (nothing may be reflected to an unproven address,
 * RFC 9000 8.1).
 * @param a the accumulator (its ack_pn advances on success)
 * @param scid the server's own connection id for the header
 * @param out receives the sealed datagram
 * @param cap bytes available at out
 * @return bytes written, or 0 when nothing was opened yet or sealing
 *   failed. */
usz wired_srvboot_partial_ack(
    wired_srvboot_acc* a, quic_span scid, u8* out, usz cap);

/** @param a the accumulator
 * @return 1 once the buffered CRYPTO prefix folds a complete ClientHello. */
int wired_srvboot_acc_complete(const wired_srvboot_acc* a);

/** Cold-start the connection from a completed accumulator: initialize the
 * server and loop from the bound header, fold the reassembled ClientHello,
 * and seal the flight, acknowledging the highest Initial packet number
 * received (out fields as in wired_srvboot_accept).
 * @param conn the orchestrator/loop pair to cold-start
 * @param id the fixed server identity
 * @param a a complete accumulator (wired_srvboot_acc_complete)
 * @param out receives the sealed flight and the acknowledged packet number
 * @return 1, or 0 when the accumulator is incomplete or the boot fails. */
int wired_srvboot_accept_acc(
    const wired_srvboot_conn* conn,
    const wired_srvboot_id*   id,
    wired_srvboot_acc*        a,
    wired_srvboot_out*        out);

/** Refuse an authenticated but unservable connection attempt: an Initial
 * CONNECTION_CLOSE acknowledging the highest received packet number so the
 * peer stops retransmitting and fails fast (RFC 9000 10.2).
 * @param a the bound accumulator of the refused attempt
 * @param scid the server connection id to answer with
 * @param error_code RFC 9001 8.2 CRYPTO_ERROR (0x0100 | TLS alert) to report,
 *   e.g. quic_sdrv_last_error's value -- 0 falls back to the generic TLS
 *   handshake_failure code (0x128, RFC 9001 4.8) when the caller has no more
 *   specific cause on hand.
 * @param out receives the sealed Initial datagram
 * @param cap bytes available at out
 * @return bytes written, or 0 on overflow. */
usz wired_srvboot_refusal(
    const wired_srvboot_acc* a,
    quic_span                scid,
    u64                      error_code,
    u8*                      out,
    usz                      cap);

#endif
