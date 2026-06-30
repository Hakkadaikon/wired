#include "app/http3/request/h3resp/field_encode.h"

#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpack/static_table.h"

/* Static table index of the first ":status" name entry (RFC 9204 App. A). */
#define QPACK_STATUS_NAME_INDEX 24

/* Render a 3-digit HTTP status into dst[0..2] as decimal ASCII and NUL-
 * terminate at dst[3]. HTTP status codes are exactly three digits
 * (RFC 9110 15). */
static void status_digits(u16 status, u8 *dst) {
  dst[0] = (u8)('0' + (status / 100) % 10);
  dst[1] = (u8)('0' + (status / 10) % 10);
  dst[2] = (u8)('0' + status % 10);
  dst[3] = 0;
}

/* Encode the empty Encoded Field Section Prefix at *off. */
static usz resp_put_prefix(u8 *out, usz cap) {
  quic_qpack_prefix pfx = {0, 0, 0};
  return quic_qpack_prefix_encode(out, cap, &pfx);
}

/* Append the :status field line: Indexed when the value is in the static
 * table, else a Literal referencing the static :status name. */
static usz put_status_line(u16 status, u8 *out, usz cap) {
  u8  digits[4];
  i64 idx;
  status_digits(status, digits);
  idx = quic_qpack_static_find(":status", (const char *)digits);
  if (idx >= 0) return quic_qpack_indexed_encode(out, cap, (u64)idx, 1);
  return quic_qpack_literal_namref_encode(
      out, cap, QPACK_STATUS_NAME_INDEX, 1, 0, digits, 3);
}

/* RFC 9204 4.5 */
int quic_h3resp_encode_status(u16 status, u8 *out, usz cap, usz *out_len) {
  usz off = resp_put_prefix(out, cap);
  usz n;
  if (!off) return 0;
  n = put_status_line(status, out + off, cap - off);
  if (!n) return 0;
  *out_len = off + n;
  return 1;
}
