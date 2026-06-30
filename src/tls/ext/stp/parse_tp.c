#include "tls/ext/stp/parse_tp.h"
#include "tls/ext/tparam/tpblob.h"
#include "common/bytes/varint/varint.h"

/* Decode the value view as a varint into *value_out (0 if not a single one). */
static void emit_int(const u8 *val, usz vlen, u64 *value_out)
{
    u64 v = 0;
    if (!value_out) return;
    quic_varint_decode(val, vlen, &v);
    *value_out = v;
}

/* Fill the caller's out params from a matched (val, vlen) value view. */
static void stp_emit(const u8 *val, usz vlen, u64 *value_out,
                     const u8 **bytes_out, usz *bytes_len)
{
    emit_int(val, vlen, value_out);
    if (bytes_out) *bytes_out = val;
    if (bytes_len) *bytes_len = vlen;
}

/* Read the TLV at *off, advancing *off past it. Returns 1 if it matched
 * param_id (out params filled), 0 if not, -1 if the TLV is malformed. */
static int step_tlv(const u8 *tp, usz len, usz *off, u64 param_id,
                    u64 *value_out, const u8 **bytes_out, usz *bytes_len)
{
    u64 id;
    const u8 *val;
    usz vlen;
    usz r = quic_tparam_get_blob(tp + *off, len - *off, &id, &val, &vlen);
    if (r == 0) return -1;
    *off += r;
    if (id != param_id) return 0;
    stp_emit(val, vlen, value_out, bytes_out, bytes_len);
    return 1;
}

int quic_stp_parse(const u8 *tp, usz len, u64 param_id,
                   u64 *value_out, const u8 **bytes_out, usz *bytes_len)
{
    usz off = 0;
    while (off < len) {
        int s = step_tlv(tp, len, &off, param_id, value_out, bytes_out, bytes_len);
        if (s != 0) return s == 1;
    }
    return 0;
}
