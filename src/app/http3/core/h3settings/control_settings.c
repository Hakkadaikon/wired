#include "app/http3/core/h3settings/control_settings.h"

#include "app/http3/core/h3settings/control_open.h"
#include "app/http3/core/h3settings/settings_build.h"

/* RFC 9114 7.2.4.1 default: unlimited field section size is the absence of the
 * setting; we advertise concrete defaults so the peer (e.g. curl) sees them. */
#define DEFAULT_MAX_FIELD_SECTION_SIZE 0x4000 /* 16 KiB */
#define DEFAULT_QPACK_MAX_TABLE_CAP 0
#define DEFAULT_QPACK_BLOCKED_STREAMS 0
/* RFC 9220 3: do not advertise support until a request handler actually
 * validates and processes :protocol (quic_h3_connect_protocol_ok) — false
 * advertising would let a client rely on a capability this server does not
 * yet implement. */
#define DEFAULT_ENABLE_CONNECT_PROTOCOL 0

/* RFC 9114 6.2.1 */
int quic_h3settings_control_stream(u8* out, usz cap, usz* out_len) {
  usz pre = 0;
  if (!quic_h3settings_control_prefix(out, cap, &pre)) return 0;

  quic_h3settings_in in = {
      DEFAULT_MAX_FIELD_SECTION_SIZE, DEFAULT_QPACK_MAX_TABLE_CAP,
      DEFAULT_QPACK_BLOCKED_STREAMS, DEFAULT_ENABLE_CONNECT_PROTOCOL};
  quic_obuf ob = quic_obuf_of(out + pre, cap - pre);
  if (!quic_h3settings_build(&in, &ob)) return 0;

  *out_len = pre + ob.len;
  return 1;
}
