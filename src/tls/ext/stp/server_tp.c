#include "tls/ext/stp/server_tp.h"

#include "tls/ext/tparam/tparam.h"
#include "tls/ext/tparam/tpblob.h"

/* RFC 9000 18.2 integer-valued parameters the server advertises. */
static const struct {
  u64 id, val;
} int_params[] = {
    {QUIC_TP_MAX_IDLE_TIMEOUT, 30000},
    {QUIC_TP_INITIAL_MAX_DATA, 1048576},
    {QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 262144},
    {QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 262144},
    {QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI, 262144},
    {QUIC_TP_INITIAL_MAX_STREAMS_BIDI, 100},
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

int quic_stp_build_server(
    quic_span original_dcid, quic_span initial_scid, quic_obuf* out) {
  int ok;
  out->len = 0;
  ok =
      put_blob(out, QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID, original_dcid) &
      put_int_params(out) &
      put_blob(out, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID, initial_scid);
  return ok;
}
