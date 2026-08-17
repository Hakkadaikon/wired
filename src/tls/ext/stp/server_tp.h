#ifndef QUIC_STP_SERVER_TP_H
#define QUIC_STP_SERVER_TP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9000 18.2. Build the server's transport parameters into out->p
 * (out->cap bytes). original_dcid is the DCID of the client's first Initial
 * (RFC 9000 7.3); initial_scid is the server's source connection id. On
 * success writes the TLV sequence and sets out->len; returns 1. Returns 0 if
 * it does not fit. */
/** Built-in initial_max_streams_bidi default (a zero stp_limits field
 * falls back to this) -- exposed so callers that track the advertised limit
 * across a connection's life (RFC 9000 4.6/19.11 MAX_STREAMS re-grants) know
 * the true starting value without duplicating the constant. Like every
 * QUIC_STP_DEFAULT_* below, overridable per build (-D flag). */
#ifndef QUIC_STP_DEFAULT_MAX_STREAMS_BIDI
#define QUIC_STP_DEFAULT_MAX_STREAMS_BIDI 100
#endif
/** Built-in initial_max_data default (RFC 9000 18.2, 0x04) -- 10,000,000 to
 * match the connection-wide default the mainstream stacks ship (quiche's
 * CLI default), so untuned cross-implementation benchmarks start from equal
 * preconditions. Safe above the fixed receive buffers: the per-stream
 * windows below carry the actual buffering promise and bind first. */
#ifndef QUIC_STP_DEFAULT_MAX_DATA
#define QUIC_STP_DEFAULT_MAX_DATA 10000000
#endif
/** Built-in max_idle_timeout default, milliseconds (RFC 9000 18.2, 0x01). */
#ifndef QUIC_STP_DEFAULT_IDLE_TIMEOUT_MS
#define QUIC_STP_DEFAULT_IDLE_TIMEOUT_MS 30000
#endif
/** Built-in initial_max_stream_data_bidi_local / _uni default (RFC 9000
 * 18.2, 0x05/0x07). This is a PROMISE to buffer that many bytes past
 * delivery, and both directions land in srvloop's fixed reassembly windows
 * -- so it must equal WIRED_SRVLOOP_WT_BUF_CAP (srvloop.h; not includable
 * here, the tls layer sits below app, but pinned by server_tp_test.c). A
 * build raising one MUST raise the other in the same breath: advertising
 * more than the buffer holds lets a compliant sender outrun delivery, and
 * the clipped-yet-ACKed overflow becomes an unfillable stream gap that
 * freezes the stream for good (this exact bug killed moqt_chat's voice
 * track 10 s into every call). */
#ifndef QUIC_STP_DEFAULT_STREAM_DATA_LOCAL
#define QUIC_STP_DEFAULT_STREAM_DATA_LOCAL 49152
#endif
/** Built-in initial_max_stream_data_bidi_remote default (RFC 9000 18.2,
 * 0x06): client-initiated request streams. Kept at its historic value (the
 * request path's own buffers predate the local/uni fix above and interop
 * pins the old behavior). */
#ifndef QUIC_STP_DEFAULT_STREAM_DATA_REMOTE
#define QUIC_STP_DEFAULT_STREAM_DATA_REMOTE 262144
#endif
/** Built-in initial_max_streams_uni default (RFC 9000 18.2, 0x09). */
#ifndef QUIC_STP_DEFAULT_MAX_STREAMS_UNI
#define QUIC_STP_DEFAULT_MAX_STREAMS_UNI 100
#endif
/** RFC 9000 18.2: the operator-tunable integer limits this server
 * advertises; a zero field falls back to the built-in default. */
typedef struct {
  u64 max_data;         /**< initial_max_data (0x04), default
                         * QUIC_STP_DEFAULT_MAX_DATA */
  u64 max_streams_bidi; /**< initial_max_streams_bidi (0x08), default 100 */
  /** initial_max_streams_uni (0x09), default 100. A server whose uni-stream
   * reassembly capacity is a fixed slot table should advertise a limit that
   * capacity actually backs (RFC 9000 4.6): a limit above capacity lets a
   * loss-delayed burst of legitimate streams land frames nowhere while
   * their packets still ACK, losing them for good -- the same lockstep rule
   * max_streams_bidi already follows. */
  u64 max_streams_uni;
  u64 max_datagram_frame_size; /**< max_datagram_frame_size (0x20, RFC 9221 3),
                                * 0 = not advertised (no built-in default: the
                                * caller opts in once DATAGRAM delivery is
                                * wired end-to-end) */
} stp_limits;

int stp_build_server(
    wired_span original_dcid, wired_span initial_scid, wired_obuf* out);

/* As stp_build_server, with the tunable limits overriding defaults
 * (lim = 0 keeps every default). */
/* Same as stp_build_server_lim plus retry_source_connection_id
 * (RFC 9000 7.3): emitted only when rscid is non-empty (a Retry actually
 * preceded the handshake -- the peer treats an unexpected one as a
 * TRANSPORT_PARAMETER_ERROR). sreset_token is the 16-byte
 * stateless_reset_token (RFC 9000 10.3.1/18.2) for the handshake SCID;
 * empty omits the TP (a server that never sends resets advertises none). */
int stp_build_server_ret(
    wired_span        original_dcid,
    wired_span        initial_scid,
    wired_span        rscid,
    wired_span        sreset_token,
    const stp_limits* lim,
    wired_obuf*       out);

int stp_build_server_lim(
    wired_span        original_dcid,
    wired_span        initial_scid,
    const stp_limits* lim,
    wired_obuf*       out);

#endif
