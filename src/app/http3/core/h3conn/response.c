#include "app/http3/core/h3conn/response.h"

#include "app/http3/request/h3req/respparse.h"
#include "app/http3/request/h3resp/resp_build.h"
#include "app/qpack/qpack/fieldline.h"
#include "app/qpack/qpack/literal.h"
#include "app/qpack/qpack/prefix.h"
#include "app/qpack/qpack/static_table.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9114 4.1 / RFC 9000 19.8 */
int quic_h3conn_send_response(
    u64       stream_id,
    u16       status,
    const u8 *body,
    usz       body_len,
    u8       *out,
    usz       cap,
    usz      *out_len) {
  u8  h3[1500];
  usz h3_len = 0;
  if (!quic_h3resp_build(status, body, body_len, h3, sizeof(h3), &h3_len))
    return 0;
  return quic_appdata_stream_frame(
      stream_id, 0, h3, h3_len, 1, out, cap, out_len);
}

/* RFC 9110 15: three decimal ASCII digits to a status code. */
static u16 digits_to_status(const u8 *d) {
  return (u16)((d[0] - '0') * 100 + (d[1] - '0') * 10 + (d[2] - '0'));
}

/* RFC 9204 4.5.2: Indexed :status -> look up the static entry's value. */
static int status_from_indexed(const u8 *buf, usz n, u16 *status) {
  u64         index     = 0;
  int         is_static = 0;
  const char *name      = 0;
  const char *value     = 0;
  if (!quic_qpack_indexed_decode(buf, n, &index, &is_static)) return 0;
  if (!quic_qpack_static_get((usz)index, &name, &value)) return 0;
  *status = digits_to_status((const u8 *)value);
  return 1;
}

/* RFC 9204 4.5.4: Literal :status with name reference -> its 3-octet value. */
static int status_from_literal(const u8 *buf, usz n, u16 *status) {
  u64 index     = 0;
  int is_static = 0, never = 0;
  u8  val[8];
  usz vlen = 0;
  if (!quic_qpack_literal_namref_decode(
          buf, n, &index, &is_static, &never, val, sizeof(val), &vlen))
    return 0;
  if (vlen != 3) return 0;
  *status = digits_to_status(val);
  return 1;
}

/* RFC 9204 4.5: decode the single :status field line after the section prefix.
 */
static int decode_status(const u8 *fs, usz n, u16 *status) {
  usz off = quic_qpack_prefix_decode(fs, n, &(quic_qpack_prefix){0});
  if (!off) return 0;
  if (status_from_indexed(fs + off, n - off, status)) return 1;
  return status_from_literal(fs + off, n - off, status);
}

/* RFC 9114 4.1 / RFC 9000 19.8 */
int quic_h3conn_recv_response(
    const u8  *stream_data,
    usz        len,
    u16       *status,
    const u8 **body,
    usz       *body_len) {
  quic_stream_frame f;
  const u8         *headers = 0;
  usz               h_len   = 0;
  if (!quic_frame_get_stream(stream_data, len, &f)) return 0;
  if (!quic_h3req_resp_parse(
          f.data, (usz)f.length, &headers, &h_len, body, body_len))
    return 0;
  return decode_status(headers, h_len, status);
}
