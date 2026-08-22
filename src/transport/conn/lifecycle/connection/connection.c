#include "transport/conn/lifecycle/connection/connection.h"

#include "transport/packet/frame/pipeline/rxpacket.h"
#include "transport/packet/frame/pipeline/txpacket.h"

/* RFC 9000 17.2: the simplified long-header form the pipeline emits uses a
 * fixed first byte and 8-byte DCID; sender and receiver share one packet
 * number so the AEAD nonce matches. */
#define CONN_BYTE0 0xc3
#define CONN_DCID_LEN 8
#define CONN_PN 0

void connection_init(connection* c, const connection_init_in* in) {
  keyset_init(&c->keys);
  conn_init(&c->conn);
  c->link      = in->link;
  c->is_server = in->is_server;
  for (usz i = 0; i < 8; i++) c->dcid[i] = in->dcid[i];
}

int connection_send(connection* c, int level, wired_span frames) {
  const initial_keys* k;
  aes128              hp;
  u8                  out[MEMLINK_MTU];
  usz                 n;
  if (!keyset_for_level(&c->keys, level, &k)) return 0;
  aes128_init(&hp, k->hp);
  protect_keys pk   = {k, &hp};
  wired_span   none = wired_span_of((const u8*)0, 0);
  tx_desc      t    = {CONN_BYTE0, wired_span_of(c->dcid, CONN_DCID_LEN),
                       none,       1,
                       none,       CONN_PN,
                       frames,     0 /* QUIC v1 */};
  n                 = tx_packet(&pk, &t, wired_mspan_of(out, sizeof(out)));
  if (n == 0) return 0;
  return memlink_send(c->link, out, n);
}

/* Pull and unprotect one level-`k` packet; on success *frames views the
 * plaintext. Returns 1 on success, 0 if nothing valid. c->rxbuf backs the
 * view, so it outlives this call (until c's next recv). */
static int recv_open(connection* c, const initial_keys* k, wired_span* frames) {
  aes128 hp;
  usz    rn = memlink_recv(c->link, c->rxbuf, sizeof(c->rxbuf));
  if (rn == 0) return 0;
  aes128_init(&hp, k->hp);
  protect_keys pk = {k, &hp};
  rx_desc      d  = {wired_mspan_of(c->rxbuf, rn), 1, 0};
  return rx_packet(&pk, &d, frames);
}

int connection_recv(connection* c, int level, framewalk* iter) {
  const initial_keys* k;
  wired_span          frames;
  if (!keyset_for_level(&c->keys, level, &k)) return 0;
  if (!recv_open(c, k, &frames)) return 0;
  framewalk_init(iter, frames.p, frames.n);
  return 1;
}
