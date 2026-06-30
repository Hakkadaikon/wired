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

/* Append one integer TP at *off. Returns 1 on success, 0 if it did not fit. */
static int put_int(u8 *out, usz cap, usz *off, u64 id, u64 val) {
  usz w = quic_tparam_put_int(out + *off, cap - *off, id, val);
  *off += w;
  return w != 0;
}

/* Append one opaque TP (the two connection ids) at *off. */
static int put_blob(
    u8 *out, usz cap, usz *off, u64 id, const u8 *val, usz val_len) {
  usz w = quic_tparam_put_blob(out + *off, cap - *off, id, val, val_len);
  *off += w;
  return w != 0;
}

/* Append all integer-valued parameters. Returns 1 if every one fit. */
static int put_int_params(u8 *out, usz cap, usz *off) {
  int ok = 1;
  for (usz i = 0; i < sizeof(int_params) / sizeof(int_params[0]); i++)
    ok &= put_int(out, cap, off, int_params[i].id, int_params[i].val);
  return ok;
}

int quic_stp_build_server(
    const u8 *original_dcid,
    u8        odcid_len,
    const u8 *initial_scid,
    u8        scid_len,
    u8       *out,
    usz       cap,
    usz      *out_len) {
  usz off = 0;
  int ok  = put_blob(
               out, cap, &off, QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID,
               original_dcid, odcid_len) &
           put_int_params(out, cap, &off) &
           put_blob(
               out, cap, &off, QUIC_TP_INITIAL_SOURCE_CONNECTION_ID,
               initial_scid, scid_len);
  if (!ok) return 0;
  *out_len = off;
  return 1;
}
