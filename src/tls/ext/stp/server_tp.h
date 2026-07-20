#ifndef QUIC_STP_SERVER_TP_H
#define QUIC_STP_SERVER_TP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 18.2. Build the server's transport parameters into out->p
 * (out->cap bytes). original_dcid is the DCID of the client's first Initial
 * (RFC 9000 7.3); initial_scid is the server's source connection id. On
 * success writes the TLV sequence and sets out->len; returns 1. Returns 0 if
 * it does not fit. */
/** Built-in initial_max_streams_bidi default (a zero quic_stp_limits field
 * falls back to this) -- exposed so callers that track the advertised limit
 * across a connection's life (RFC 9000 4.6/19.11 MAX_STREAMS re-grants) know
 * the true starting value without duplicating the constant. */
#define QUIC_STP_DEFAULT_MAX_STREAMS_BIDI 100
/** RFC 9000 18.2: the operator-tunable integer limits this server
 * advertises; a zero field falls back to the built-in default. */
typedef struct {
  u64 max_data;         /**< initial_max_data (0x04), default 1MiB */
  u64 max_streams_bidi; /**< initial_max_streams_bidi (0x08), default 100 */
  u64 max_datagram_frame_size; /**< max_datagram_frame_size (0x20, RFC 9221 3),
                                * 0 = not advertised (no built-in default: the
                                * caller opts in once DATAGRAM delivery is
                                * wired end-to-end) */
} quic_stp_limits;

int quic_stp_build_server(
    quic_span original_dcid, quic_span initial_scid, quic_obuf* out);

/* As quic_stp_build_server, with the tunable limits overriding defaults
 * (lim = 0 keeps every default). */
/* Same as quic_stp_build_server_lim plus retry_source_connection_id
 * (RFC 9000 7.3): emitted only when rscid is non-empty (a Retry actually
 * preceded the handshake -- the peer treats an unexpected one as a
 * TRANSPORT_PARAMETER_ERROR). */
int quic_stp_build_server_ret(
    quic_span              original_dcid,
    quic_span              initial_scid,
    quic_span              rscid,
    const quic_stp_limits* lim,
    quic_obuf*             out);

int quic_stp_build_server_lim(
    quic_span              original_dcid,
    quic_span              initial_scid,
    const quic_stp_limits* lim,
    quic_obuf*             out);

#endif
