#ifndef RAWQ_H
#define RAWQ_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Pure transport-binding helpers that tell a raw-QUIC application
 * connection (an ALPN such as moqt-19, draft-ietf-moq-transport-19 3.1)
 * apart from a WebTransport-over-HTTP/3 one, for the five places the two
 * bindings differ on the wire: stream routing, reset error codes, datagram
 * framing, the first server uni stream id, and the implicit session's
 * identity. Every function takes raw (1 = raw QUIC, 0 = WebTransport) and
 * has no state. */

/** connect_stream_id of the implicit session a raw-QUIC connection gets at
 * handshake confirmation: there is no Extended CONNECT stream, so the
 * identity is a sentinel that is never a valid client bidi id (RFC 9000
 * 2.1) and never reaches the wire (no qsid, capsule, or stream signal is
 * ever built from it on raw). */
#define RAWQ_NO_CONNECT_ID ((u64) - 1)

/** RFC 9000 2.1: first server-initiated uni stream id on raw QUIC. Nothing
 * else claims ids 3/7, so the application's first uni stream is 3. */
#define RAWQ_UNI_FIRST_RAW 3

/** RFC 9114 6.2: first server-initiated uni stream id left for the
 * application on HTTP/3, after the control (3) and QPACK encoder (7)
 * streams. */
#define RAWQ_UNI_FIRST_H3 11

/** Where one client-initiated stream's bytes belong (rawq_route). */
typedef enum {
  RAWQ_ROUTE_REQUEST_H3 = 0, /**< HTTP/3 request stream (WT only) */
  RAWQ_ROUTE_WT_BIDI,        /**< WT bidi stream, leading signal 0x41 */
  RAWQ_ROUTE_WT_UNI,         /**< WT uni stream, leading type 0x54 */
  RAWQ_ROUTE_RAW_BIDI,       /**< raw QUIC bidi: every byte to the session */
  RAWQ_ROUTE_RAW_UNI,        /**< raw QUIC uni: every byte to the session */
  RAWQ_ROUTE_H3_UNI          /**< HTTP/3 control/QPACK/other uni (WT only) */
} rawq_route_kind;

/** Classify a client-initiated stream. On raw QUIC the id's direction bit
 * (RFC 9000 2.1, bit 0x2) alone decides RAW_BIDI/RAW_UNI and first is
 * ignored: a leading 0x41/0x54 carries no signal meaning there
 * (draft-ietf-moq-transport-19 3.3: the uni stream type is the MoQT
 * message/header type itself). On WebTransport the classification is
 * today's srvloop one: a bidi whose offset-0 bytes decode as the varint
 * 0x41 is WT_BIDI, else REQUEST_H3; a uni whose offset-0 bytes decode as
 * the varint 0x54 is WT_UNI, else H3_UNI (draft-ietf-webtrans-http3-15
 * 4.2). Truncated or undecodable leading bytes are not a signal.
 * @param raw 1 for a raw-QUIC connection, 0 for HTTP/3
 * @param stream_id the client-initiated stream id
 * @param first the stream's bytes at offset 0 received so far
 * @return the route */
rawq_route_kind rawq_route(int raw, u64 stream_id, wired_span first);

/** Application error code to put on the wire in RESET_STREAM/STOP_SENDING
 * (RFC 9000 19.4/19.5). Raw QUIC: app itself, the MoQT stream error code
 * verbatim (draft-ietf-moq-transport-19 3.3.4, -22 12.5). WebTransport:
 * wired_wterrmap_to_http3(app) (draft-ietf-webtrans-http3-15 4.4), e.g.
 * 1 -> 0x52e4a40fa8dc.
 * @param raw 1 for a raw-QUIC connection, 0 for HTTP/3
 * @param app the application (MoQT) error code
 * @return the wire error code */
u64 rawq_reset_code_out(int raw, u32 app);

/** Recover the application error code from a received RESET_STREAM/
 * STOP_SENDING wire code. Raw QUIC: mapped when wire fits in u32, *app =
 * wire; a larger code is unmapped and the caller treats it as
 * INTERNAL_ERROR (draft-ietf-moq-transport-22 13: an unknown code never
 * closes the session on its own). WebTransport:
 * wired_wterrmap_from_http3(wire, app).
 * @param raw 1 for a raw-QUIC connection, 0 for HTTP/3
 * @param wire the received wire error code
 * @param app receives the application code when mapped
 * @return 1 mapped, 0 unmapped (*app untouched) */
int rawq_reset_code_in(int raw, u64 wire, u32* app);

/** Bytes that precede the application payload inside one QUIC DATAGRAM
 * (RFC 9221 5). Raw QUIC: 0, one MoQT Object per DATAGRAM as is
 * (draft-ietf-moq-transport-19 11.3, -22 11.2). WebTransport: the length of
 * the RFC 9297 2.1 quarter-stream-id varint (connect_stream_id / 4, RFC
 * 9000 16 encoding).
 * @param raw 1 for a raw-QUIC connection, 0 for HTTP/3
 * @param connect_stream_id the session's CONNECT stream id (WT only)
 * @return the prefix length in bytes */
usz rawq_dgram_prefix_len(int raw, u64 connect_stream_id);

/** First server-initiated uni stream id the application may open:
 * RAWQ_UNI_FIRST_RAW on raw QUIC, RAWQ_UNI_FIRST_H3 on HTTP/3. Later ones
 * follow every 4 (RFC 9000 2.1); skipping ids would implicitly open the
 * skipped ones at the peer (RFC 9000 3.2) and spend its MAX_STREAMS.
 * @param raw 1 for a raw-QUIC connection, 0 for HTTP/3
 * @return the first stream id */
u64 rawq_uni_first_id(int raw);

#endif
