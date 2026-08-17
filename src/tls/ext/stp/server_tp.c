#include "tls/ext/stp/server_tp.h"

#include "app/datagram/datagram/datagram.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/ext/tparam/tpblob.h"

/* RFC 9000 18.2 integer-valued parameters the server advertises. Every
 * value comes from a QUIC_STP_DEFAULT_* macro (server_tp.h), each
 * overridable per build with a -D flag; the buffer-backing invariant on the
 * two stream-data windows (they must equal WIRED_SRVLOOP_WT_BUF_CAP, and
 * why) is documented on QUIC_STP_DEFAULT_STREAM_DATA_LOCAL and pinned by
 * server_tp_test.c. */
static const struct {
  u64 id, val;
} int_params[] = {
    {QUIC_TP_MAX_IDLE_TIMEOUT, QUIC_STP_DEFAULT_IDLE_TIMEOUT_MS},
    {QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
     QUIC_STP_DEFAULT_STREAM_DATA_LOCAL},
    {QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
     QUIC_STP_DEFAULT_STREAM_DATA_REMOTE},
    {QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, QUIC_STP_DEFAULT_STREAM_DATA_LOCAL},
};

/* Append one integer TP at out->len. Returns 1 on success, 0 if it did not
 * fit. */
static int put_int(wired_obuf* out, u64 id, u64 val) {
  usz        before = out->len;
  wired_obuf tail   = obuf_of(out->p + before, out->cap - before);
  usz        w      = tparam_put_int(&tail, id, val);
  out->len += w;
  return w != 0;
}

/* Append one opaque TP (the two connection ids) at out->len. */
static int put_blob(wired_obuf* out, u64 id, wired_span val) {
  usz        before = out->len;
  wired_obuf tail   = obuf_of(out->p + before, out->cap - before);
  usz        w      = tparam_put_blob(&tail, id, val);
  out->len += w;
  return w != 0;
}

/* Append all integer-valued parameters. Returns 1 if every one fit. */
static int put_int_params(wired_obuf* out) {
  int ok = 1;
  for (usz i = 0; i < sizeof(int_params) / sizeof(int_params[0]); i++)
    ok &= put_int(out, int_params[i].id, int_params[i].val);
  return ok;
}

/* A zero field keeps the built-in default. */
static u64 lim_or(u64 v, u64 dflt) { return v ? v : dflt; }

/* Append an integer TP only when val is non-zero (RFC 9221 3: 0 or absent
 * both mean "not supported", so omitting it is equivalent and cheaper). No
 * built-in default: unlike max_data/max_streams_bidi, absence is the correct
 * out-of-the-box behavior until a caller opts in. Returns 1 if it fit or was
 * skipped, 0 only on an actual encode failure. */
static int put_int_opt(wired_obuf* out, u64 id, u64 val) {
  return val ? put_int(out, id, val) : 1;
}

/* Append the operator-tunable limits (RFC 9000 18.2) plus the opt-in
 * max_datagram_frame_size (RFC 9221 3). */
static int put_tunables(wired_obuf* out, const stp_limits* lim) {
  stp_limits d = {0};
  if (!lim) lim = &d;
  return put_int(
             out, QUIC_TP_INITIAL_MAX_DATA,
             lim_or(lim->max_data, QUIC_STP_DEFAULT_MAX_DATA)) &
         put_int(
             out, QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
             lim_or(lim->max_streams_bidi, QUIC_STP_DEFAULT_MAX_STREAMS_BIDI)) &
         put_int(
             out, QUIC_TP_INITIAL_MAX_STREAMS_UNI,
             lim_or(lim->max_streams_uni, QUIC_STP_DEFAULT_MAX_STREAMS_UNI)) &
         put_int_opt(
             out, QUIC_TP_MAX_DATAGRAM_FRAME_SIZE,
             lim->max_datagram_frame_size);
}

/* reset_stream_at (draft-ietf-quic-reliable-stream-reset 4): advertise
 * support unconditionally via an empty-valued TP -- the codec
 * (reset_stream_at_encode/_decode) is stable, and announcing costs
 * nothing even though no live sender uses it yet (unlike
 * max_datagram_frame_size, whose receive side is not wired). */
static int put_reset_stream_at(wired_obuf* out) {
  return put_blob(out, QUIC_TP_RESET_STREAM_AT, wired_span_of(0, 0));
}

/* retry_source_connection_id only when a Retry actually happened -- an
 * unexpected one is a TRANSPORT_PARAMETER_ERROR at the peer (RFC 9000 7.3).
 */
static int put_rscid(wired_obuf* out, wired_span rscid) {
  if (rscid.n == 0) return 1;
  return put_blob(out, QUIC_TP_RETRY_SOURCE_CONNECTION_ID, rscid);
}

/* stateless_reset_token (RFC 9000 10.3.1/18.2) only when the caller supplied
 * one; the value is exactly 16 bytes by definition, so any other non-zero
 * length is a caller bug and fails the build rather than emitting a TP the
 * peer must reject. */
static int put_sreset_token(wired_obuf* out, wired_span token) {
  if (token.n == 0) return 1;
  return token.n == 16 && put_blob(out, QUIC_TP_STATELESS_RESET_TOKEN, token);
}

int stp_build_server_ret(
    wired_span        original_dcid,
    wired_span        initial_scid,
    wired_span        rscid,
    wired_span        sreset_token,
    const stp_limits* lim,
    wired_obuf*       out) {
  int ok;
  out->len = 0;
  ok =
      put_blob(out, QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, original_dcid) &
      put_int_params(out) & put_tunables(out, lim) & put_reset_stream_at(out) &
      put_rscid(out, rscid) & put_sreset_token(out, sreset_token) &
      put_blob(out, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, initial_scid);
  return ok;
}

int stp_build_server_lim(
    wired_span        original_dcid,
    wired_span        initial_scid,
    const stp_limits* lim,
    wired_obuf*       out) {
  return stp_build_server_ret(
      original_dcid, initial_scid, wired_span_of(0, 0), wired_span_of(0, 0),
      lim, out);
}

int stp_build_server(
    wired_span original_dcid, wired_span initial_scid, wired_obuf* out) {
  return stp_build_server_lim(original_dcid, initial_scid, 0, out);
}
