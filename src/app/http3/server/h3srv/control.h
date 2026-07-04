#ifndef WIRED_H3SRV_CONTROL_H
#define WIRED_H3SRV_CONTROL_H

#include "app/http3/server/h3srv/state.h"
#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 9114 6.2.1 / 7.2.4. Open the server's single local control stream and
 * emit SETTINGS as its first frame. On success records that the server has
 * sent its own SETTINGS (a precondition of sending any response). Returns 1
 * with out->len set, 0 if out lacks capacity. */
int wired_h3srv_open_control(wired_h3srv_state* st, quic_obuf* out);

#endif
