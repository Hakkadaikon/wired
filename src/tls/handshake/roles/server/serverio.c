#include "tls/handshake/roles/server/server.h"

/* RFC 9000 5/7: socket layer for the server orchestrator. Mirrors the client's
 * pump/run loop. Only this file enters the kernel (io/udp).
 * ponytail: pump feeds the raw datagram payload to quic_server_feed as a
 * Handshake CRYPTO payload; real Initial/Handshake AEAD unprotection routes
 * through connio when on-wire protection is wired. */

int quic_server_listen(quic_server *s, u16 port) {
  s->fd = quic_udp_socket();
  if (s->fd < 0) return 0;
  quic_udp_addr(&s->peer, port, 0, 0, 0, 0);
  return quic_udp_bind(s->fd, &s->peer) == 0;
}

int quic_server_pump(quic_server *s) {
  u8  dg[QUIC_SERVER_DATAGRAM_MAX];
  i64 n = quic_udp_recvfrom(s->fd, dg, sizeof(dg), &s->peer);
  if (n <= 0) return 0;
  return quic_server_feed(s, dg, (usz)n);
}

int quic_server_run_handshake(quic_server *s, int max_iterations) {
  for (int i = 0; i < max_iterations && !quic_server_is_confirmed(s); i++)
    quic_server_pump(s);
  return quic_server_is_confirmed(s);
}

void quic_server_close(quic_server *s) {
  if (s->fd >= 0) syscall1(SYS_close, s->fd);
  s->fd = -1;
}
