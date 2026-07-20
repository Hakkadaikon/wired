#include "transport/conn/lifecycle/connection/connection.h"

#include "transport/packet/frame/pipeline/rxpacket.h"
#include "transport/packet/frame/pipeline/txpacket.h"

/* RFC 9000 17.2: the simplified long-header form the pipeline emits uses a
 * fixed first byte and 8-byte DCID; sender and receiver share one packet
 * number so the AEAD nonce matches. */
#define CONN_BYTE0 0xc3
#define CONN_DCID_LEN 8
#define CONN_PN 0

void quic_connection_init(
    quic_connection* c, const quic_connection_init_in* in) {
  quic_keyset_init(&c->keys);
  quic_conn_init(&c->conn);
  c->link      = in->link;
  c->is_server = in->is_server;
  for (usz i = 0; i < 8; i++) c->dcid[i] = in->dcid[i];
}

int quic_connection_send(quic_connection* c, int level, quic_span frames) {
  const quic_initial_keys* k;
  quic_aes128              hp;
  u8                       out[QUIC_MEMLINK_MTU];
  usz                      n;
  if (!quic_keyset_for_level(&c->keys, level, &k)) return 0;
  quic_aes128_init(&hp, k->hp);
  quic_protect_keys pk   = {k, &hp};
  quic_span         none = quic_span_of((const u8*)0, 0);
  quic_tx_desc      t    = {CONN_BYTE0, quic_span_of(c->dcid, CONN_DCID_LEN),
                            none,       1,
                            none,       CONN_PN,
                            frames,     0 /* QUIC v1 */};
  n = quic_tx_packet(&pk, &t, quic_mspan_of(out, sizeof(out)));
  if (n == 0) return 0;
  return quic_memlink_send(c->link, out, n);
}

/* Pull and unprotect one level-`k` packet; on success *frames views the
 * plaintext. Returns 1 on success, 0 if nothing valid. c->rxbuf backs the
 * view, so it outlives this call (until c's next recv). */
static int recv_open(
    quic_connection* c, const quic_initial_keys* k, quic_span* frames) {
  quic_aes128 hp;
  usz         rn = quic_memlink_recv(c->link, c->rxbuf, sizeof(c->rxbuf));
  if (rn == 0) return 0;
  quic_aes128_init(&hp, k->hp);
  quic_protect_keys pk = {k, &hp};
  quic_rx_desc      d  = {quic_mspan_of(c->rxbuf, rn), 1};
  return quic_rx_packet(&pk, &d, frames);
}

int quic_connection_recv(quic_connection* c, int level, quic_framewalk* iter) {
  const quic_initial_keys* k;
  quic_span                frames;
  if (!quic_keyset_for_level(&c->keys, level, &k)) return 0;
  if (!recv_open(c, k, &frames)) return 0;
  quic_framewalk_init(iter, frames.p, frames.n);
  return 1;
}
