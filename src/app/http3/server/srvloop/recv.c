#include "app/http3/server/srvloop/recv.h"

#include "app/http3/server/srvloop/keys.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/kuswitch/derive.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/version/version/version.h"

/* RFC 8999 5.1: the Version field of a long header. A short header carries
 * none -- 1-RTT is always in the connection's negotiated version. */
static u32 recv_pkt_version(const wired_server* s, wired_mspan dg) {
  if (dg.n < 5 || !packet_is_long(dg.p[0])) {
    return sdrv_wire_version(&s->sdrv);
  }
  return be_get_be32(dg.p + 1);
}

/* RFC 9001 5.1: open a received Initial under the keys derived from the
 * client's original DCID and the packet's own version (RFC 9369 3.3.1 /
 * 4.1: after a compatible switch to v2 the client's later Initials arrive
 * v2-keyed, but ones it sent before seeing the v2 flight are still v1 --
 * recv_version_ok decided this version may open here); the raw frame
 * payload is returned (the dispatcher walks it). The established loop does
 * not track an Initial-space largest (the space is done after the client's
 * ack of the server flight), so 0 stands in as the recovery baseline. */
static int recv_initial(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  return initpkt_open_ver(
      wired_span_of(s->sdrv.odcid, s->sdrv.odcid_len),
      recv_pkt_version(s, in->dgram), in->dgram, 0, &out->payload);
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

/* hspkt_onertt_open mutates byte0 and the pn bytes in place (header
 * protection removal, RFC 9001 5.4.1) even on an AEAD failure -- a failed
 * attempt against one key generation must not corrupt the bytes a retry
 * against another generation needs. Cap: pn_off + a 4-byte pn (the longest
 * possible), the same bound hspkt_unprotect itself uses. */
#define RECV_ONERTT_HDR_MAX 24

static usz onertt_hdr_len(u8 dcid_len) { return 1u + (usz)dcid_len + 4u; }

static void onertt_backup(
    wired_mspan pkt, u8 dcid_len, u8 save[RECV_ONERTT_HDR_MAX]) {
  usz n = onertt_hdr_len(dcid_len);
  for (usz i = 0; i < n && i < pkt.n; i++) {
    save[i] = pkt.p[i];
  }
}

static void onertt_restore(
    wired_mspan pkt, u8 dcid_len, const u8 save[RECV_ONERTT_HDR_MAX]) {
  usz n = onertt_hdr_len(dcid_len);
  for (usz i = 0; i < n && i < pkt.n; i++) {
    pkt.p[i] = save[i];
  }
}

/* Try opening with one key candidate; restores the header bytes first so a
 * prior failed attempt against a different generation left no residue
 * (hspkt_onertt_open mutates the datagram's own bytes in place through
 * its pkt view, regardless of how many wired_mspan copies wrap it). */
static int onertt_try(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    const initial_keys*          keys,
    const u8                     save[RECV_ONERTT_HDR_MAX],
    wired_srvloop_recv_out*      out) {
  aes128 hp;
  aes128_init(&hp, keys->hp);
  {
    protect_keys           pk = {keys, &hp};
    hspkt_onertt_open_desc d  = {in->dgram, s->sdrv.iscid_len, in->largest_pn};
    onertt_restore(in->dgram, s->sdrv.iscid_len, save);
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

/* RFC 9001 6.3: a next-generation candidate that actually decrypts confirms
 * the peer's update -- rotate so current becomes old (retained) and the
 * derived generation becomes current, and adopt its secret for the update
 * after this one. Only called once a probe has already succeeded. RFC 9001
 * 6.2 requires the send side to follow in the same step (before this
 * packet's ACK goes out, which srvloop's caller does right after opening)
 * -- unless the send side already went ahead (a self-initiated update the
 * peer is now following, RFC 9001 6.1), in which case it stays put. */
static void onertt_rotate_to(
    wired_server* s, const initial_keys* next, const u8* next_secret) {
  kuswitch_rotate(&s->ku, next);
  bytes_memcpy(s->ku_secret, next_secret, TLS_HASH_MAX);
  if (s->ku_send.generation < s->ku.generation) {
    srvloop_ku_rotate_send(s);
  }
}

/* RFC 9001 6.3: current generation first (the common case, every packet
 * until the peer's next update), else retry with old (retained prior
 * generation) so a reordered pre-update packet still decrypts. */
static int onertt_try_known(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    const u8                     save[RECV_ONERTT_HDR_MAX],
    wired_srvloop_recv_out*      out) {
  if (onertt_try(s, in, &s->ku.cur, save, out)) {
    return 1;
  }
  return s->ku.have_old && onertt_try(s, in, &s->ku.old, save, out);
}

/* Neither retained generation decrypted it -- the peer's phase bit may name
 * a generation this endpoint has not adopted yet. Derive it once and retry
 * as a probe, rotating only if that probe actually decrypts (RFC 9001:
 * confirm on a successful unprotect, not on the bit alone). */
static int onertt_try_next_gen(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    const u8                     save[RECV_ONERTT_HDR_MAX],
    wired_srvloop_recv_out*      out) {
  initial_keys next;
  u8           next_secret[TLS_HASH_MAX];
  kuswitch_next_keys_suite(
      s->sdrv.cipher_suite, s->ku_secret, &next, next_secret);
  /* RFC 9001 6.1: hp is unchanged across an update. */
  bytes_memcpy(next.hp, s->ku.cur.hp, AEAD_KEY_MAX);
  if (!onertt_try(s, in, &next, save, out)) {
    return 0;
  }
  onertt_rotate_to(s, &next, next_secret);
  return 1;
}

/* RFC 9001 6.3: every generation this endpoint holds or can derive one step
 * ahead -- current, retained old, then the next-generation probe. */
static int onertt_try_any(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    const u8                     save[RECV_ONERTT_HDR_MAX],
    wired_srvloop_recv_out*      out) {
  return onertt_try_known(s, in, save, out) ||
         onertt_try_next_gen(s, in, save, out);
}

/* RFC 9001 6 depends on generation-0 keys already being seeded (srvfin's
 * confirm, server.c srv_seed_kuswitch) -- before that, s->ku.cur is not real
 * key material, so failing closed here is a structural guarantee, not an
 * incidental AEAD-failure side effect. A seeded packet that opens under no
 * generation counts toward the AEAD integrity limit (RFC 9001 6.6). */
static int recv_onertt(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  u8 save[RECV_ONERTT_HDR_MAX];
  if (!s->ku_seeded) {
    return 0;
  }
  onertt_backup(in->dgram, s->sdrv.iscid_len, save);
  if (onertt_try_any(s, in, save, out)) {
    return 1;
  }
  s->ku_auth_fail++;
  return 0;
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

/* The client's original version: its first Initial's (RFC 9368 2.2). */
static u32 recv_orig_version(const wired_server* s) {
  return s->sdrv.client_version ? s->sdrv.client_version : VERSION_1;
}

/* RFC 9369 4.1: the original version still carries 0-RTT (a client never
 * sends 0-RTT in the negotiated version) and Initials until a Handshake
 * packet -- necessarily in the negotiated version -- has been processed. */
static int recv_orig_type_ok(const wired_server* s, int type) {
  return type == PT_0RTT || (type == PT_INITIAL && !s->hs_rx_seen);
}

static int recv_orig_ok(const wired_server* s, u32 ver, int type) {
  return ver == recv_orig_version(s) && recv_orig_type_ok(s, type);
}

/* RFC 9369 4.1: Initial, Handshake and 1-RTT packets in the negotiated
 * version; 0-RTT never is (recv_orig_ok's alone). */
static int recv_wire_ok(const wired_server* s, u32 ver, int type) {
  return type != PT_0RTT && ver == sdrv_wire_version(&s->sdrv);
}

/* RFC 9369 4.1: "An endpoint MUST drop packets using any other version." */
static int recv_version_ok(const wired_server* s, u32 ver, int type) {
  return recv_orig_ok(s, ver, type) || recv_wire_ok(s, ver, type);
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
  u32 ver  = recv_pkt_version(s, in->dgram);
  int type = packet_long_type(in->dgram.p[0], ver);
  if (!recv_version_ok(s, ver, type)) {
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
