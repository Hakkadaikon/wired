#include "app/http3/server/h3srv/control.h"

#include "app/http3/core/h3conn/establish.h"

/* RFC 9114 6.2.1 / 7.2.4 */
int quic_h3srv_open_control(quic_h3srv_state *st, quic_obuf *out) {
  usz len;
  if (!quic_h3conn_open_control(out->p, out->cap, &len)) return 0;
  out->len          = len;
  st->settings_sent = 1;
  return 1;
}
