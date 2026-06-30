#include "app/http3/core/h3conn/establish.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3run/settings_seq.h"
#include "app/http3/core/h3settings/control_settings.h"
#include "common/bytes/varint/varint.h"

/* RFC 9114 6.2.1: control stream type. */
#define QUIC_H3_CONTROL_STREAM_TYPE 0x00

/* RFC 9114 6.2 / 7.2.4 */
int quic_h3conn_open_control(u8 *out, usz cap, usz *out_len) {
  return quic_h3settings_control_stream(out, cap, out_len);
}

/* RFC 9114 6.2.1: consume the leading control stream type, leaving *off at the
 * first frame. Returns 1 if the type is 0x00, else 0. */
static int skip_control_type(const u8 *s, usz len, usz *off) {
  u64 type = 0;
  usz n    = quic_varint_decode(s, len, &type);
  if (!n || type != QUIC_H3_CONTROL_STREAM_TYPE) return 0;
  *off = n;
  return 1;
}

/* RFC 9114 7.2.4 */
int quic_h3conn_peer_settings_ok(const u8 *control_stream, usz len) {
  quic_h3_settings_state st      = {0};
  usz                    off     = 0;
  u64                    ftype   = 0;
  const u8              *payload = 0;
  u64                    plen    = 0;
  if (!skip_control_type(control_stream, len, &off)) return 0;
  if (!quic_h3_frame_get(
          control_stream + off, len - off, &ftype, &payload, &plen))
    return 0;
  return quic_h3_settings_first(&st, ftype);
}
