#include "srvloop/dispatch.h"
#include "appdata/stream_send.h"
#include "frame/frame.h"
#include "h3srv/respond.h"
#include "pipeline/framewalk.h"
#include "util/bytes.h"
#include "util/dbgdump.h"

/* ponytail: temporary. REQ-STREAMS[id=<n> off=<o> len=<l>] for one gathered
 * STREAM frame. Remove with the rest of the POST-body diagnostics. */
static void dbg_req_stream(const quic_stream_frame *sf)
{
    quic_dbg_str("REQ-STREAMS[id=");
    quic_dbg_u64(sf->stream_id);
    quic_dbg_str(" off=");
    quic_dbg_u64(sf->offset);
    quic_dbg_str(" len=");
    quic_dbg_u64(sf->length);
    quic_dbg_str("]\n");
}

/* RFC 9000 19.8: STREAM frame types occupy 0x08..0x0f. */
static int is_stream(u64 type)
{
    return type >= QUIC_FRAME_STREAM_BASE && type <= QUIC_FRAME_STREAM_BASE + 7;
}

/* RFC 9000 2.1: a STREAM is a client-initiated bidirectional request stream
 * (carrying HTTP/3 HEADERS) iff its low two bits are 0. The 0x2 bit marks a
 * unidirectional stream (HTTP/3 control / QPACK encoder+decoder, RFC 9114 6.2),
 * which curl opens before the request and must NOT be treated as a request. */
static int is_request_stream(u64 stream_id)
{
    return (stream_id & 0x03) == 0;
}

/* 1 if the STREAM frame at `frame` is a client bidi request stream. */
static int stream_is_request(const u8 *frame, usz rem)
{
    quic_stream_frame sf;
    if (quic_frame_get_stream(frame, rem, &sf) == 0) return 0;
    return is_request_stream(sf.stream_id);
}

/* 1 if the walked frame of `type` at `frame` is a client bidi request STREAM. */
static int is_request_frame(u64 type, const u8 *frame, usz rem)
{
    return is_stream(type) && stream_is_request(frame, rem);
}

/* RFC 9114 4.1: hand the (reassembled) request STREAM frame to the HTTP/3
 * request decoder. */
static int dispatch_stream(quic_h3srv_state *h3, const u8 *frame, usz len,
                           u8 *scratch, usz scap,
                           int *got_request, quic_h3reqdrive_req *req)
{
    if (!quic_h3srv_on_request(h3, frame, len, scratch, scap, req))
        return 0;
    *got_request = 1;
    return 1;
}

/* RFC 9000 2.2: append one request STREAM frame's data to buf at *off, OR-ing
 * its FIN into *fin. Frames arrive in offset order on a single stream (curl),
 * so arrival order is the reassembly order. */
static void gather_one(const u8 *frame, usz rem, u8 *buf, usz cap, usz *off,
                       u8 *fin)
{
    quic_stream_frame sf;
    if (!quic_frame_get_stream(frame, rem, &sf))
        return;
    dbg_req_stream(&sf);
    quic_put_bytes(buf, cap, off, sf.data, (usz)sf.length);
    *fin |= sf.fin;
}

/* RFC 9000 2.2 / 12.4, RFC 9114 6.2: concatenate the data of every client bidi
 * (request) STREAM frame in the payload into buf, skipping PADDING/ACK and the
 * unidirectional STREAM frames (control / QPACK) curl sends first. curl may
 * split one request's HEADERS and DATA across two STREAM frames; both are
 * joined here. Returns the joined length (0 if no request stream is present).
 * ponytail: joins only what is in this one datagram; a body fragmented across
 * datagrams is not reassembled — add a per-stream buffer if a client does that. */
static usz gather_request(const u8 *payload, usz len, u8 *buf, usz cap, u8 *fin)
{
    quic_framewalk it;
    u64 type;
    const u8 *frame;
    usz rem, off = 0;
    quic_framewalk_init(&it, payload, len);
    while (quic_framewalk_next(&it, &type, &frame, &rem))
        if (is_request_frame(type, frame, rem))
            gather_one(frame, rem, buf, cap, &off, fin);
    return off;
}

/* RFC 9000 2.2 / RFC 9114 4.1: reassemble the request stream's data, re-wrap it
 * as a single STREAM frame (offset 0) and drive the HTTP/3 request decoder.
 * Returns 1 if a request was found and decoded, 0 otherwise. */
static int reassemble_and_drive(quic_h3srv_state *h3, const u8 *payload,
                                usz len, u8 *scratch, usz scap,
                                int *got_request, quic_h3reqdrive_req *req)
{
    u8 data[1500], wrap[1536];
    usz dlen, wlen = 0;
    u8 fin = 0;
    dlen = gather_request(payload, len, data, sizeof data, &fin);
    if (!dlen)
        return 0;
    quic_dbg_str("REQ-PYLD[");      /* ponytail: temporary POST-body diag */
    quic_dbg_hex(data, dlen);
    quic_dbg_str("]\n");
    if (!quic_appdata_stream_frame(0, 0, data, dlen, fin, wrap, sizeof wrap,
                                   &wlen))
        return 0;
    return dispatch_stream(h3, wrap, wlen, scratch, scap, got_request, req);
}

/* 1 if the payload carries a STREAM frame of any kind (request or uni). Such a
 * 1-RTT payload belongs to the HTTP/3 path and must never re-enter the
 * handshake via quic_server_feed (RFC 9000 12.4). */
static int has_stream(const u8 *payload, usz len)
{
    quic_framewalk it;
    u64 type;
    const u8 *frame;
    usz rem;
    quic_framewalk_init(&it, payload, len);
    while (quic_framewalk_next(&it, &type, &frame, &rem))
        if (is_stream(type)) return 1;
    return 0;
}

/* 1 if the payload carries at least one walkable frame (non-empty, decodes).
 * An empty/undecodable payload drives nothing. */
static int has_frame(const u8 *payload, usz len)
{
    quic_framewalk it;
    u64 type;
    const u8 *frame;
    usz rem;
    quic_framewalk_init(&it, payload, len);
    return quic_framewalk_next(&it, &type, &frame, &rem);
}

/* No request stream found. A payload carrying only unidirectional STREAM frames
 * (curl's control / QPACK, RFC 9114 6.2) is accepted but drives no request; a
 * CRYPTO/handshake payload is handed to quic_server_feed. */
static int feed_or_accept(quic_server *s, const u8 *payload, usz len)
{
    if (has_stream(payload, len)) return 1;
    return quic_server_feed(s, payload, len);
}

static int dispatch_non_request(quic_server *s, const u8 *payload, usz len)
{
    if (!has_frame(payload, len)) return 0;
    return feed_or_accept(s, payload, len);
}

/* RFC 9000 12.4 / 2.1, RFC 9114 6.2: a payload may lead with PADDING/ACK before
 * its CRYPTO or STREAM frame (curl/quiche do this). A client bidi STREAM drives
 * HTTP/3; unidirectional STREAMs are accepted but ignored; anything else is
 * handed whole to quic_server_feed, whose crecv reassembles a split
 * ClientHello/Finished. A STREAM payload never re-enters the handshake. */
int quic_srvloop_dispatch(quic_server *s, quic_h3srv_state *h3,
                          const u8 *payload, usz len,
                          u8 *scratch, usz scap,
                          int *got_request, quic_h3reqdrive_req *req)
{
    if (reassemble_and_drive(h3, payload, len, scratch, scap, got_request, req))
        return 1;
    return dispatch_non_request(s, payload, len);
}
