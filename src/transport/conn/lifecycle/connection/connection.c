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
    quic_connection *c, const u8 dcid[8], quic_memlink *link, int is_server) {
  quic_keyset_init(&c->keys);
  quic_conn_init(&c->conn);
  c->link      = link;
  c->is_server = is_server;
  for (usz i = 0; i < 8; i++) c->dcid[i] = dcid[i];
}

int quic_connection_send(
    quic_connection *c, int level, const u8 *frames, usz len) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  u8                       out[QUIC_MEMLINK_MTU];
  usz                      n;
  if (!quic_keyset_for_level(&c->keys, level, &k)) return 0;
  quic_aes128_init(&hp, k->hp);
  n = quic_tx_packet(
      k, &hp, CONN_BYTE0, c->dcid, CONN_DCID_LEN, (const u8 *)0, 0, 1,
      (const u8 *)0, 0, CONN_PN, frames, len, out, sizeof(out));
  if (n == 0) return 0;
  return quic_memlink_send(c->link, out, n);
}

/* Pull and unprotect one level-`k` packet; on success point *frames at the
 * plaintext and set *frames_len. Returns 1 on success, 0 if nothing valid. */
static int recv_open(
    quic_connection         *c,
    const quic_initial_keys *k,
    const u8               **frames,
    usz                     *frames_len) {
  quic_aes128 hp;
  static u8   pkt[QUIC_MEMLINK_MTU]; /* plaintext view outlives this call */
  usz         rn = quic_memlink_recv(c->link, pkt, sizeof(pkt));
  if (rn == 0) return 0;
  quic_aes128_init(&hp, k->hp);
  return quic_rx_packet(k, &hp, pkt, rn, 1, frames, frames_len);
}

int quic_connection_recv(quic_connection *c, int level, quic_framewalk *iter) {
  const quic_initial_keys *k;
  const u8                *frames;
  usz                      frames_len;
  if (!quic_keyset_for_level(&c->keys, level, &k)) return 0;
  if (!recv_open(c, k, &frames, &frames_len)) return 0;
  quic_framewalk_init(iter, frames, frames_len);
  return 1;
}
