#include "app/http3/core/h3settings/control_settings.h"

#include "app/http3/core/h3settings/control_open.h"
#include "app/http3/core/h3settings/settings_build.h"

/* RFC 9114 7.2.4.1 default: unlimited field section size is the absence of the
 * setting; we advertise concrete defaults so the peer (e.g. curl) sees them. */
#define DEFAULT_MAX_FIELD_SECTION_SIZE 0x4000 /* 16 KiB */
#define DEFAULT_QPACK_MAX_TABLE_CAP 0
#define DEFAULT_QPACK_BLOCKED_STREAMS 0

/* RFC 9114 6.2.1 */
int quic_h3settings_control_stream(u8 *out, usz cap, usz *out_len) {
  usz pre = 0;
  if (!quic_h3settings_control_prefix(out, cap, &pre)) return 0;

  usz body = 0;
  if (!quic_h3settings_build(
          DEFAULT_MAX_FIELD_SECTION_SIZE, DEFAULT_QPACK_MAX_TABLE_CAP,
          DEFAULT_QPACK_BLOCKED_STREAMS, out + pre, cap - pre, &body))
    return 0;

  *out_len = pre + body;
  return 1;
}
