#include "tls/ext/stp/server_tp.h"

#include "app/datagram/datagram/datagram.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/ext/tparam/tpblob.h"

/* RFC 9000 18.2 integer-valued parameters the server advertises; the two
 * tunable slots hold their defaults and are overridden per build. */
#define STP_DEFAULT_MAX_DATA 1048576
#define STP_DEFAULT_MAX_STREAMS_BIDI 100
static const struct {
  u64 id, val;
} int_params[] = {
    {QUIC_TP_MAX_IDLE_TIMEOUT, 30000},
    {QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 262144},
    {QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 262144},
    {QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 262144},
    {QUIC_TP_INITIAL_MAX_STREAMS_UNI, 100},
};

/* Append one integer TP at out->len. Returns 1 on success, 0 if it did not
 * fit. */
static int put_int(quic_obuf* out, u64 id, u64 val) {
  usz       before = out->len;
  quic_obuf tail   = quic_obuf_of(out->p + before, out->cap - before);
  usz       w      = quic_tparam_put_int(&tail, id, val);
  out->len += w;
  return w != 0;
}

/* Append one opaque TP (the two connection ids) at out->len. */
static int put_blob(quic_obuf* out, u64 id, quic_span val) {
  usz       before = out->len;
  quic_obuf tail   = quic_obuf_of(out->p + before, out->cap - before);
  usz       w      = quic_tparam_put_blob(&tail, id, val);
  out->len += w;
  return w != 0;
}

/* Append all integer-valued parameters. Returns 1 if every one fit. */
static int put_int_params(quic_obuf* out) {
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
static int put_int_opt(quic_obuf* out, u64 id, u64 val) {
  return val ? put_int(out, id, val) : 1;
}

/* Append the operator-tunable limits (RFC 9000 18.2) plus the opt-in
 * max_datagram_frame_size (RFC 9221 3). */
static int put_tunables(quic_obuf* out, const quic_stp_limits* lim) {
  quic_stp_limits d = {0, 0, 0};
  if (!lim) lim = &d;
  return put_int(
             out, QUIC_TP_INITIAL_MAX_DATA,
             lim_or(lim->max_data, STP_DEFAULT_MAX_DATA)) &
         put_int(
             out, QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
             lim_or(lim->max_streams_bidi, STP_DEFAULT_MAX_STREAMS_BIDI)) &
         put_int_opt(
             out, QUIC_TP_MAX_DATAGRAM_FRAME_SIZE,
             lim->max_datagram_frame_size);
}

int quic_stp_build_server_lim(
    quic_span              original_dcid,
    quic_span              initial_scid,
    const quic_stp_limits* lim,
    quic_obuf*             out) {
  int ok;
  out->len = 0;
  ok =
      put_blob(out, QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, original_dcid) &
      put_int_params(out) & put_tunables(out, lim) &
      put_blob(out, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, initial_scid);
  return ok;
}

int quic_stp_build_server(
    quic_span original_dcid, quic_span initial_scid, quic_obuf* out) {
  return quic_stp_build_server_lim(original_dcid, initial_scid, 0, out);
}
