#include "app/http3/server/srvloop/recv.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "common/diag/error/error.h"
#include "tls/keys/keyupdate/keyphase.h"
#include "tls/keys/keyupdate/pncheck.h"
#include "tls/keys/kuswitch/derive.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/header/packet/pnum.h"
#include "transport/packet/protect/hp/hp.h"
#include "transport/packet/protect/hp/hpapply.h"
#include "transport/packet/protect/hp/hpsample.h"
#include "transport/packet/protect/protect_suite/hp_suite.h"

/* RFC 9001 6: the 1-RTT receive path -- Key Phase bit and packet number
 * pick one key generation (RFC 9001 6.3-6.5). */

/* RFC 9001 6.3/6.5: the receive key generation a 1-RTT packet is opened
 * under -- exactly one AEAD attempt per packet. */
enum { KURX_CUR, KURX_OLD, KURX_NEXT };

/* The Key Phase bit and full packet number of a protected short-header
 * packet, read through header protection on a copy (the header-protection
 * key is the same in every generation, RFC 9001 6.1). */
typedef struct {
  int phase;
  u64 pn;
} kurx_hdr;

static int kurx_peek(
    const wired_server* s, const wired_srvloop_recv_in* in, kurx_hdr* h) {
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
static int kurx_pick_other(const wired_server* s, u64 pn) {
  if (!s->ku.have_old || pn > s->ku_cur_hi) {
    return KURX_NEXT;
  }
  return KURX_OLD;
}

static int kurx_pick(const wired_server* s, const kurx_hdr* h) {
  if (h->phase == (int)keyphase_bit(s->ku.generation)) {
    return KURX_CUR;
  }
  return kurx_pick_other(s, h->pn);
}

static const initial_keys* kurx_keys(const wired_server* s, int pick) {
  const initial_keys* keys[] = {&s->ku.cur, &s->ku.old, &s->ku_next};
  return keys[pick];
}

static int kurx_open(
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
static int kurx_took_cur(wired_server* s, u64 pn) {
  s->ku_cur_lo = u64_min(s->ku_cur_lo, pn);
  s->ku_cur_hi = u64_max(s->ku_cur_hi, pn);
  return 1;
}

/* RFC 9001 6.4: old keys opening a packet numbered above one the newer
 * keys already protected is a KEY_UPDATE_ERROR; the packet is dropped. */
static int kurx_took_old(wired_server* s, u64 pn) {
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
static int kurx_took_next(wired_server* s, u64 pn) {
  initial_keys next = s->ku_next;
  kuswitch_rotate(&s->ku, &next);
  bytes_memcpy(s->ku_secret, s->ku_next_secret, TLS_HASH_MAX);
  server_ku_derive_next(s);
  if (s->ku_send.generation < s->ku.generation) {
    srvloop_ku_rotate_send(s);
  }
  return kurx_took_cur(s, pn);
}

static int kurx_took(wired_server* s, int pick, u64 pn) {
  static int (*const took[])(wired_server*, u64) = {
      kurx_took_cur, kurx_took_old, kurx_took_next};
  return took[pick](s, pn);
}

/* RFC 9001 6.3: pick the generation from the Key Phase bit and packet
 * number, then open once -- no on-demand key derivation, so an invalid
 * Key Phase bit costs the same as a valid one. */
static int kurx_open_picked(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  kurx_hdr h;
  int      pick;
  if (!kurx_peek(s, in, &h)) {
    return 0;
  }
  pick = kurx_pick(s, &h);
  if (!kurx_open(s, in, kurx_keys(s, pick), out)) {
    s->ku_auth_fail++; /* RFC 9001 6.6 integrity limit */
    return 0;
  }
  return kurx_took(s, pick, h.pn);
}

/* RFC 9001 6 depends on generation-0 keys already being seeded (srvfin's
 * confirm, server.c srv_seed_kuswitch) -- before that, s->ku.cur is not real
 * key material, so failing closed here is a structural guarantee, not an
 * incidental AEAD-failure side effect. */
int srvloop_recv_onertt(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  if (!s->ku_seeded) {
    return 0;
  }
  return kurx_open_picked(s, in, out);
}
