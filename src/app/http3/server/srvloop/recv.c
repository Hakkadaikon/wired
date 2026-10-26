#include "app/http3/server/srvloop/recv.h"

#include "app/http3/server/srvloop/keys.h"
#include "common/bytes/util/bytes.h"
#include "crypto/kdf/keys/keyset.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/version/version/version.h"

/* RFC 9001 5.1: open a received Initial under the keys derived from the
 * client's original DCID and the packet's own version (RFC 9369 3.3.1 /
 * 4.1: after a compatible switch to v2 the client's later Initials arrive
 * v2-keyed, but ones it sent before seeing the v2 flight are still v1 --
 * srvloop_recv_version_ok decided this version may open here); the raw frame
 * payload is returned (the dispatcher walks it). The established loop does
 * not track an Initial-space largest (the space is done after the client's
 * ack of the server flight), so 0 stands in as the recovery baseline. */
static int recv_initial(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  return initpkt_open_ver(
      wired_span_of(s->sdrv.odcid, s->sdrv.odcid_len),
      srvloop_recv_pkt_version(s, in->dgram), in->dgram, 0, &out->payload);
}

/* RFC 9001 5.1: open a Handshake packet with the peer-direction CLIENT_HS key.
 * The DCID the client wrote is the server's source id (iscid). */
static int recv_handshake(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  wired_srvloop_dirkeys dk;
  if (!wired_srvloop_open_keys(s, LEVEL_HANDSHAKE, &dk)) {
    return 0;
  }
  protect_keys pk = {dk.keys, &dk.hp};
  if (!hspkt_open_suite(
          s->sdrv.cipher_suite, &pk, in->dgram, in->hs_largest_pn,
          &out->payload)) {
    return 0;
  }
  s->hs_rx_seen = 1; /* RFC 9369 4.1: original Initial keys retire now */
  return 1;
}

/* RFC 9000 17.2: dispatch the open by level (table keeps CCN low). */
static int recv_at_level(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  static int (*const open_at[])(
      wired_server*, const wired_srvloop_recv_in*, wired_srvloop_recv_out*) = {
      recv_initial,
      recv_handshake,
      srvloop_recv_onertt,
  };
  return open_at[out->level](s, in, out);
}

/* RFC 9000 17.2.3 / RFC 9001 4.6.1: a 0-RTT packet is a long header with no
 * Token field, exactly like Handshake -- hspkt_open_suite already
 * handles that framing. Only tried when this connection actually accepted
 * 0-RTT (sdrv_early_keys). RFC 9000 12.3: 0-RTT and 1-RTT share the App
 * packet number space, so a successfully opened 0-RTT packet is reported as
 * LEVEL_ONERTT -- every downstream consumer (ACK bookkeeping, frame
 * dispatch) already handles that level unmodified. */
static int recv_zerortt(
    wired_server* s, const wired_srvloop_recv_in* in, wired_span* payload) {
  initial_keys keys;
  aes128       hp;
  if (!sdrv_early_keys(&s->sdrv, &keys)) {
    return 0;
  }
  aes128_init(&hp, keys.hp);
  {
    protect_keys pk = {&keys, &hp};
    return hspkt_open_suite(
        s->sdrv.cipher_suite, &pk, in->dgram, in->largest_pn, payload);
  }
}

/* Version already admitted; picks the 0-RTT path or the normal
 * Initial/Handshake/1-RTT level dispatch, reading type bits under the
 * packet's own version (RFC 9369 3.2). */
static int recv_by_type(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out,
    u32                          ver,
    int                          type) {
  if (type == PT_0RTT) {
    out->level = LEVEL_ONERTT;
    return recv_zerortt(s, in, &out->payload);
  }
  if (!connrunner_packet_level(in->dgram.p[0], ver, &out->level)) {
    return 0;
  }
  return recv_at_level(s, in, out);
}

/* byte0 already known non-empty: decode the long header by its own
 * Version field (RFC 9369 4.1), drop a version this connection may not
 * receive at that type, then dispatch. Split out of wired_srvloop_recv to
 * keep its own branch count at the gate. */
static int recv_dispatch(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  u32 ver  = srvloop_recv_pkt_version(s, in->dgram);
  int type = packet_long_type(in->dgram.p[0], ver);
  if (!srvloop_recv_version_ok(s, ver, type)) {
    return 0;
  }
  return recv_by_type(s, in, out, ver, type);
}

int wired_srvloop_recv(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  if (in->dgram.n == 0) {
    return 0;
  }
  return recv_dispatch(s, in, out);
}
