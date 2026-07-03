#include "app/http3/server/srvloop/recv.h"

#include "app/http3/server/srvloop/keys.h"
#include "crypto/kdf/keys/keyset.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/build/initpkt/initopen.h"

/* RFC 9001 5.1: open a received Initial under the keys derived from the
 * client's original DCID; the raw frame payload is returned (the dispatcher
 * walks it). in->largest_pn is unused outside the 1-RTT space (the Initial
 * uses a 4-byte PN). */
static int recv_initial(
    quic_server *s, const quic_srvloop_recv_in *in,
    quic_srvloop_recv_out *out) {
  return quic_initpkt_open(
      quic_span_of(s->sdrv.odcid, s->sdrv.odcid_len), in->dgram,
      &out->payload);
}

/* RFC 9001 5.1: open a Handshake packet with the peer-direction CLIENT_HS key.
 * The DCID the client wrote is the server's source id (iscid). */
static int recv_handshake(
    quic_server *s, const quic_srvloop_recv_in *in,
    quic_srvloop_recv_out *out) {
  quic_srvloop_dirkeys dk;
  if (!quic_srvloop_open_keys(s, QUIC_LEVEL_HANDSHAKE, &dk)) return 0;
  quic_protect_keys pk = {dk.keys, &dk.hp};
  return quic_hspkt_open(&pk, in->dgram, &out->payload);
}

/* RFC 9001 5.1 / RFC 9000 A.3: open a 1-RTT packet with the peer-direction
 * CLIENT_AP key, recovering the full packet number from its truncated form
 * relative to in->largest_pn (the largest 1-RTT PN received so far). */
static int recv_onertt(
    quic_server *s, const quic_srvloop_recv_in *in,
    quic_srvloop_recv_out *out) {
  quic_srvloop_dirkeys dk;
  if (!quic_srvloop_open_keys(s, QUIC_LEVEL_ONERTT, &dk)) return 0;
  quic_protect_keys           pk = {dk.keys, &dk.hp};
  quic_hspkt_onertt_open_desc d  = {
      in->dgram, s->sdrv.iscid_len, in->largest_pn};
  return quic_hspkt_onertt_open(&pk, &d, &out->payload);
}

/* RFC 9000 17.2: dispatch the open by level (table keeps CCN low). */
static int recv_at_level(
    quic_server *s, const quic_srvloop_recv_in *in,
    quic_srvloop_recv_out *out) {
  static int (*const open_at[])(
      quic_server *, const quic_srvloop_recv_in *, quic_srvloop_recv_out *) = {
      recv_initial,
      recv_handshake,
      recv_onertt,
  };
  return open_at[out->level](s, in, out);
}

int quic_srvloop_recv(
    quic_server *s, const quic_srvloop_recv_in *in,
    quic_srvloop_recv_out *out) {
  if (in->dgram.n == 0 ||
      !quic_connrunner_packet_level(in->dgram.p[0], &out->level))
    return 0;
  return recv_at_level(s, in, out);
}
