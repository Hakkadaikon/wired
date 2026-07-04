#include "tls/handshake/roles/server/server.h"

/* RFC 9000 5/7: socket layer for the server orchestrator. Mirrors the client's
 * pump/run loop. Only this file enters the kernel (io/udp).
 * ponytail: pump feeds the raw datagram payload to wired_server_feed as a
 * Handshake CRYPTO payload; real Initial/Handshake AEAD unprotection routes
 * through connio when on-wire protection is wired. */

int wired_server_listen(wired_server* s, u16 port) {
  s->fd = wired_udp_socket();
  if (s->fd < 0) return 0;
  wired_udp_addr(&s->peer, port, (const u8[4]){0, 0, 0, 0});
  return wired_udp_bind(s->fd, &s->peer) == 0;
}

int wired_server_pump(wired_server* s) {
  u8  dg[WIRED_SERVER_DATAGRAM_MAX];
  i64 n = wired_udp_recvfrom(s->fd, quic_mspan_of(dg, sizeof(dg)), &s->peer);
  if (n <= 0) return 0;
  return wired_server_feed(s, dg, (usz)n);
}

int wired_server_run_handshake(wired_server* s, int max_iterations) {
  for (int i = 0; i < max_iterations && !wired_server_is_confirmed(s); i++)
    wired_server_pump(s);
  return wired_server_is_confirmed(s);
}

void wired_server_close(wired_server* s) {
  if (s->fd >= 0) syscall1(SYS_close, s->fd);
  s->fd = -1;
}
