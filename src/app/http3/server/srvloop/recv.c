#include "app/http3/server/srvloop/recv.h"

#include "app/http3/server/srvloop/keys.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "common/diag/error/error.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/keyupdate/keyphase.h"
#include "tls/keys/keyupdate/pncheck.h"
#include "tls/keys/kuswitch/derive.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/header/packet/pnum.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hpapply.h"
#include "transport/packet/protect/hp/hpsample.h"
#include "transport/packet/protect/protect_suite/hp_suite.h"
#include "transport/version/version/version.h"

/* RFC 9001 5.1: open a received Initial under the keys derived from the
 * client's original DCID and the connection's negotiated version (RFC 9369
 * 3.3.1: after a compatible switch to v2 the client's later Initials --
 * e.g. its ACK of the server Initial -- arrive v2-keyed); the raw frame
 * payload is returned (the dispatcher walks it). The established loop does
 * not track an Initial-space largest (the space is done after the client's
 * ack of the server flight), so 0 stands in as the recovery baseline. */
static int recv_initial(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  return initpkt_open_ver(
      wired_span_of(s->sdrv.odcid, s->sdrv.odcid_len),
      sdrv_wire_version(&s->sdrv), in->dgram, 0, &out->payload);
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
  return hspkt_open_suite(
      s->sdrv.cipher_suite, &pk, in->dgram, in->hs_largest_pn, &out->payload);
}

/* RFC 9001 6.3/6.5: the receive key generation a 1-RTT packet is opened
 * under -- exactly one AEAD attempt per packet. */
enum { KU_PICK_CUR, KU_PICK_OLD, KU_PICK_NEXT };

/* The Key Phase bit and full packet number of a protected short-header
 * packet, read through header protection on a copy (the header-protection
 * key is the same in every generation, RFC 9001 6.1). */
typedef struct {
  int phase;
  u64 pn;
} onertt_hdr;

static int onertt_peek(
    const wired_server* s, const wired_srvloop_recv_in* in, onertt_hdr* h) {
  usz pn_off = 1u + (usz)s->sdrv.iscid_len;
  u8  mask[5], pnb[4], b0;
  if (!hp_sample_ok(in->dgram.n, hp_sample_offset(pn_off))) {
    return 0;
  }
  if (!hp_suite_mask(
          s->sdrv.cipher_suite, s->ku.cur.hp,
          in->dgram.p + hp_sample_offset(pn_off), mask)) {
    return 0;
  }
  b0 = (u8)(in->dgram.p[0] ^ (mask[0] & HP_SHORT_MASK));
  bytes_memcpy(pnb, in->dgram.p + pn_off, 4);
  hp_protect_pn(pnb, (b0 & 0x03u) + 1u, mask);
  h->phase = keyphase_get(b0);
  h->pn    = pnum_decode(pnb, (b0 & 0x03u) + 1u, in->largest_pn);
  return 1;
}

/* RFC 9001 6.5: an old-phase packet numbered above everything opened under
 * the current keys is a Key Update (next keys); one below or among them is
 * a delayed packet (old keys) -- or, without old keys retained, an update. */
static int onertt_pick_other(const wired_server* s, u64 pn) {
  if (!s->ku.have_old || pn > s->ku_cur_hi) {
    return KU_PICK_NEXT;
  }
  return KU_PICK_OLD;
}

static int onertt_pick(const wired_server* s, const onertt_hdr* h) {
  if (h->phase == (int)keyphase_bit(s->ku.generation)) {
    return KU_PICK_CUR;
  }
  return onertt_pick_other(s, h->pn);
}

static const initial_keys* onertt_keys(const wired_server* s, int pick) {
  const initial_keys* keys[] = {&s->ku.cur, &s->ku.old, &s->ku_next};
  return keys[pick];
}

static int onertt_open(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    const initial_keys*          keys,
    wired_srvloop_recv_out*      out) {
  aes128 hp;
  aes128_init(&hp, keys->hp);
  {
    protect_keys           pk = {keys, &hp};
    hspkt_onertt_open_desc d  = {in->dgram, s->sdrv.iscid_len, in->largest_pn};
    return hspkt_onertt_open_suite(
        s->sdrv.cipher_suite, &pk, &d, &out->payload);
  }
}

void srvloop_ku_rotate_send(wired_server* s) {
  initial_keys send_next;
  u8           send_next_secret[TLS_HASH_MAX];
  kuswitch_next_keys_suite(
      s->sdrv.cipher_suite, s->ku_send_secret, &send_next, send_next_secret);
  bytes_memcpy(send_next.hp, s->ku_send.cur.hp, AEAD_KEY_MAX);
  kuswitch_rotate(&s->ku_send, &send_next);
  bytes_memcpy(s->ku_send_secret, send_next_secret, TLS_HASH_MAX);
  s->ku_send_count = 0; /* RFC 9001 6.6: the limit is per key */
}

/* A packet opened under the current keys widens their pn range. */
static int onertt_took_cur(wired_server* s, u64 pn) {
  s->ku_cur_lo = u64_min(s->ku_cur_lo, pn);
  s->ku_cur_hi = u64_max(s->ku_cur_hi, pn);
  return 1;
}

/* RFC 9001 6.4: old keys opening a packet numbered above one the newer
 * keys already protected is a KEY_UPDATE_ERROR; the packet is dropped. */
static int onertt_took_old(wired_server* s, u64 pn) {
  if (!keyupdate_pn_violates(s->ku_cur_lo, pn)) {
    return 1;
  }
  s->ku_error = ERR_KEY_UPDATE_ERROR;
  return 0;
}

/* RFC 9001 6.3: the next keys opened it -- the peer's update is confirmed.
 * Rotate (current becomes the retained old), adopt the secret, derive the
 * generation after it right away, and (RFC 9001 6.2) bring the send side
 * along unless it already went ahead (a self-initiated update, 6.1). */
static int onertt_took_next(wired_server* s, u64 pn) {
  initial_keys next = s->ku_next;
  kuswitch_rotate(&s->ku, &next);
  bytes_memcpy(s->ku_secret, s->ku_next_secret, TLS_HASH_MAX);
  server_ku_derive_next(s);
  if (s->ku_send.generation < s->ku.generation) {
    srvloop_ku_rotate_send(s);
  }
  return onertt_took_cur(s, pn);
}

static int onertt_took(wired_server* s, int pick, u64 pn) {
  static int (*const took[])(wired_server*, u64) = {
      onertt_took_cur, onertt_took_old, onertt_took_next};
  return took[pick](s, pn);
}

/* RFC 9001 6.3: pick the generation from the Key Phase bit and packet
 * number, then open once -- no on-demand key derivation, so an invalid
 * Key Phase bit costs the same as a valid one. */
static int onertt_open_picked(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  onertt_hdr h;
  int        pick;
  if (!onertt_peek(s, in, &h)) {
    return 0;
  }
  pick = onertt_pick(s, &h);
  if (!onertt_open(s, in, onertt_keys(s, pick), out)) {
    s->ku_auth_fail++; /* RFC 9001 6.6 integrity limit */
    return 0;
  }
  return onertt_took(s, pick, h.pn);
}

/* RFC 9001 6 depends on generation-0 keys already being seeded (srvfin's
 * confirm, server.c srv_seed_kuswitch) -- before that, s->ku.cur is not real
 * key material, so failing closed here is a structural guarantee, not an
 * incidental AEAD-failure side effect. */
static int recv_onertt(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  if (!s->ku_seeded) {
    return 0;
  }
  return onertt_open_picked(s, in, out);
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
      recv_onertt,
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

/* 1 if byte0 wears a 0-RTT long header under the connection's negotiated
 * version (RFC 9000 17.2.3 / RFC 9369 3.2) -- read before header
 * protection removal, so only the form/type bits are trustworthy yet. */
static int recv_is_zerortt(u8 byte0, u32 version) {
  return packet_long_type(byte0, version) == PT_0RTT;
}

/* byte0 already known non-empty; picks the 0-RTT path or the normal
 * Initial/Handshake/1-RTT level dispatch, reading type bits under the
 * connection's negotiated version (RFC 9369 3.2). Split out of
 * wired_srvloop_recv to keep its own branch count at the gate. */
static int recv_dispatch(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  u32 version = sdrv_wire_version(&s->sdrv);
  if (recv_is_zerortt(in->dgram.p[0], version)) {
    out->level = LEVEL_ONERTT;
    return recv_zerortt(s, in, &out->payload);
  }
  if (!connrunner_packet_level(in->dgram.p[0], version, &out->level)) {
    return 0;
  }
  return recv_at_level(s, in, out);
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
