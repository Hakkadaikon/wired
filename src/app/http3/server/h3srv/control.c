#include "app/http3/server/h3srv/control.h"

#include "app/http3/core/h3conn/establish.h"

/* RFC 9114 6.2.1 / 7.2.4 */
int quic_h3srv_open_control(quic_h3srv_state *st, u8 *out, usz cap, usz *len) {
  if (!quic_h3conn_open_control(out, cap, len)) return 0;
  st->settings_sent = 1;
  return 1;
}
