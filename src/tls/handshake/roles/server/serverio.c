#include "tls/handshake/roles/server/server.h"

/* RFC 8446 E.1.4: tearing the connection down erases the retained secrets
 * (exporter_master_secret among them) along with the socket. */
void wired_server_close(wired_server* s) {
  if (s->fd >= 0) {
    wired_arch_close(s->fd);
  }
  s->fd = -1;
  keysched_wipe(&s->sched);
}
