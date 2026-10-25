#include "tls/ext/tparam/tpcheck.h"

#include "common/bytes/varint/varint.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/ext/tparam/tpblob.h"

/* Whether the first n bytes of a and b are equal. */
static int bytes_eq(const u8* a, const u8* b, usz n) {
  for (usz i = 0; i < n; i++) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

int tparam_cid_match(wired_span got, wired_span expected) {
  if (got.n != expected.n) {
    return 0;
  }
  return bytes_eq(got.p, expected.p, got.n);
}

int tparam_check_initial_scid(wired_span got, wired_span observed) {
  return tparam_cid_match(got, observed);
}

int tparam_check_original_dcid(wired_span got, wired_span sent_dcid) {
  return tparam_cid_match(got, sent_dcid);
}

int tparam_check_retry_scid(const tparam_retry_scid_in* in) {
  if (in->did_retry != in->has_param) {
    return 0; /* present iff a Retry was processed */
  }
  if (!in->did_retry) {
    return 1; /* both absent: nothing to match */
  }
  return tparam_cid_match(in->got, in->retry_scid);
}

/* RFC 9000 18.2 range-constrained parameters: id, inclusive minimum,
 * inclusive maximum (U64_MAX means unbounded above). */
typedef struct {
  u64 id, min, max;
} tp_range_row;

static const tp_range_row tp_range[] = {
    {TP_MAX_UDP_PAYLOAD_SIZE, 1200, 0xffffffffffffffffull},
    {TP_ACK_DELAY_EXPONENT, 0, 20},
    {TP_MAX_ACK_DELAY, 0, 16383},
    {TP_ACTIVE_CONNECTION_ID_LIMIT, 2, 0xffffffffffffffffull},
};

/* The range row for id, or 0 if id carries no range constraint. */
static const tp_range_row* range_row(u64 id) {
  for (usz i = 0; i < sizeof(tp_range) / sizeof(tp_range[0]); i++) {
    if (tp_range[i].id == id) {
      return &tp_range[i];
    }
  }
  return 0;
}

int tparam_range_ok(u64 id, u64 value) {
  const tp_range_row* row = range_row(id);
  if (!row) {
    return 1; /* no constraint on this parameter */
  }
  return value >= row->min && value <= row->max;
}

/* A range-constrained parameter's value must be exactly one varint within
 * its range; parameters without a range row are not inspected here. */
static int tp_value_ok(u64 id, wired_span val) {
  u64 v = 0;
  if (!range_row(id)) {
    return 1;
  }
  return varint_decode(val.p, val.n, &v) == val.n && tparam_range_ok(id, v);
}

/* RFC 9000 18.2: original_destination_connection_id, stateless_reset_token,
 * preferred_address and retry_source_connection_id are server-only. */
static int tp_server_only(u64 id) {
  static const u8 ids[] = {
      TP_ORIGINAL_DESTINATION_CONNECTION_ID, TP_STATELESS_RESET_TOKEN,
      TP_PREFERRED_ADDRESS, TP_RETRY_SOURCE_CONNECTION_ID};
  for (usz i = 0; i < sizeof ids; i++) {
    if (ids[i] == id) {
      return 1;
    }
  }
  return 0;
}

static int tp_client_tlv_ok(u64 id, wired_span val) {
  return !tp_server_only(id) && tp_value_ok(id, val);
}

/* The length of the well-formed, acceptable TLV at the head of rest, or 0. */
static usz tp_client_step(wired_span rest) {
  u64        id;
  wired_span val;
  usz        r = tparam_get_blob(rest, &id, &val);
  return r && tp_client_tlv_ok(id, val) ? r : 0;
}

int tparam_client_tp_ok(wired_span tp) {
  usz off = 0;
  while (off < tp.n) {
    usz r = tp_client_step(wired_span_of(tp.p + off, tp.n - off));
    if (!r) {
      return 0;
    }
    off += r;
  }
  return 1;
}
