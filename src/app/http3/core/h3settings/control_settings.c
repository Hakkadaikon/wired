#include "app/http3/core/h3settings/control_settings.h"

#include "app/http3/core/h3settings/control_open.h"
#include "app/http3/core/h3settings/settings_build.h"

/* RFC 9114 7.2.4.1 default: unlimited field section size is the absence of the
 * setting; we advertise concrete defaults so the peer (e.g. curl) sees them. */
#define DEFAULT_MAX_FIELD_SECTION_SIZE 0x4000 /* 16 KiB */
#define DEFAULT_QPACK_MAX_TABLE_CAP 0
#define DEFAULT_QPACK_BLOCKED_STREAMS 0
/* RFC 9220 3: srvrun's request path validates :protocol
 * (quic_h3_connect_protocol_ok, wired via srvrun_is_wt_connect) before
 * establishing a WebTransport session, so it is safe to advertise. */
#define DEFAULT_ENABLE_CONNECT_PROTOCOL 1

/* draft-ietf-webtrans-http3 8.2: sessions this server accepts per
 * connection -- srvloop serves one WebTransport session at a time. */
#define DEFAULT_WT_MAX_SESSIONS 1

/* The control-stream SETTINGS values: the defaults, plus the H3-datagram +
 * WebTransport pair when advertise_wt is set. */
static quic_h3settings_in control_settings_in(int advertise_wt) {
  quic_h3settings_in in = {
      DEFAULT_MAX_FIELD_SECTION_SIZE,
      DEFAULT_QPACK_MAX_TABLE_CAP,
      DEFAULT_QPACK_BLOCKED_STREAMS,
      DEFAULT_ENABLE_CONNECT_PROTOCOL,
      0,
      0};
  if (advertise_wt) {
    in.enable_h3_datagram = 1;
    in.wt_max_sessions    = DEFAULT_WT_MAX_SESSIONS;
  }
  return in;
}

/* RFC 9114 6.2.1 */
int quic_h3settings_control_stream(
    int advertise_wt, u8* out, usz cap, usz* out_len) {
  usz                pre = 0;
  quic_h3settings_in in  = control_settings_in(advertise_wt);
  quic_obuf          ob;
  if (!quic_h3settings_control_prefix(out, cap, &pre)) return 0;
  ob = quic_obuf_of(out + pre, cap - pre);
  if (!quic_h3settings_build(&in, &ob)) return 0;
  *out_len = pre + ob.len;
  return 1;
}
