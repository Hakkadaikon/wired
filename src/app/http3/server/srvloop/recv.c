#include "app/http3/server/srvloop/recv.h"

#include "app/http3/server/srvloop/keys.h"
#include "common/bytes/util/bytes.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/kuswitch/derive.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/packet/build/hspkt/hspkt_open.h"
#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/build/initpkt/initopen.h"
#include "transport/packet/header/packet/ptype.h"
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
  if (!wired_srvloop_open_keys(s, LEVEL_HANDSHAKE, &dk)) return 0;
  protect_keys pk = {dk.keys, &dk.hp};
  return hspkt_open_suite(
      s->sdrv.cipher_suite, &pk, in->dgram, in->hs_largest_pn, &out->payload);
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
  for (usz i = 0; i < n && i < pkt.n; i++) save[i] = pkt.p[i];
}

static void onertt_restore(
    wired_mspan pkt, u8 dcid_len, const u8 save[RECV_ONERTT_HDR_MAX]) {
  usz n = onertt_hdr_len(dcid_len);
  for (usz i = 0; i < n && i < pkt.n; i++) pkt.p[i] = save[i];
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

/* RFC 9001 6.2: this endpoint's own send keys MUST follow a confirmed peer
 * update, in the same generation. Derives independently (server_ap_secret
 * is a different HKDF chain than client_ap_secret) but advances in
 * lockstep with the recv side's rotate. */
static void onertt_rotate_send(wired_server* s) {
  initial_keys send_next;
  u8           send_next_secret[HKDF_PRK];
  kuswitch_next_keys_suite(
      s->sdrv.cipher_suite, s->ku_send_secret, &send_next, send_next_secret);
  bytes_memcpy(send_next.hp, s->ku_send.cur.hp, AEAD_KEY_MAX);
  kuswitch_rotate(&s->ku_send, &send_next);
  bytes_memcpy(s->ku_send_secret, send_next_secret, HKDF_PRK);
}

/* RFC 9001 6.3: a next-generation candidate that actually decrypts confirms
 * the peer's update -- rotate so current becomes old (retained) and the
 * derived generation becomes current, and adopt its secret for the update
 * after this one. Only called once a probe has already succeeded. RFC 9001
 * 6.2 requires the send side to follow in the same step (before this
 * packet's ACK goes out, which srvloop's caller does right after opening). */
static void onertt_rotate_to(
    wired_server* s, const initial_keys* next, const u8* next_secret) {
  kuswitch_rotate(&s->ku, next);
  bytes_memcpy(s->ku_secret, next_secret, HKDF_PRK);
  onertt_rotate_send(s);
}

/* RFC 9001 6.3: current generation first (the common case, every packet
 * until the peer's next update), else retry with old (retained prior
 * generation) so a reordered pre-update packet still decrypts. */
static int onertt_try_known(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    const u8                     save[RECV_ONERTT_HDR_MAX],
    wired_srvloop_recv_out*      out) {
  if (onertt_try(s, in, &s->ku.cur, save, out)) return 1;
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
  u8           next_secret[HKDF_PRK];
  kuswitch_next_keys_suite(
      s->sdrv.cipher_suite, s->ku_secret, &next, next_secret);
  /* RFC 9001 6.1: hp is unchanged across an update. */
  bytes_memcpy(next.hp, s->ku.cur.hp, AEAD_KEY_MAX);
  if (!onertt_try(s, in, &next, save, out)) return 0;
  onertt_rotate_to(s, &next, next_secret);
  return 1;
}

/* RFC 9001 6 depends on generation-0 keys already being seeded (srvfin's
 * confirm, server.c srv_seed_kuswitch) -- before that, s->ku.cur is not real
 * key material, so failing closed here is a structural guarantee, not an
 * incidental AEAD-failure side effect. */
static int recv_onertt(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  u8 save[RECV_ONERTT_HDR_MAX];
  if (!s->ku_seeded) return 0;
  onertt_backup(in->dgram, s->sdrv.iscid_len, save);
  if (onertt_try_known(s, in, save, out)) return 1;
  return onertt_try_next_gen(s, in, save, out);
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
  if (!sdrv_early_keys(&s->sdrv, &keys)) return 0;
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
  if (!connrunner_packet_level(in->dgram.p[0], version, &out->level)) return 0;
  return recv_at_level(s, in, out);
}

int wired_srvloop_recv(
    wired_server*                s,
    const wired_srvloop_recv_in* in,
    wired_srvloop_recv_out*      out) {
  if (in->dgram.n == 0) return 0;
  return recv_dispatch(s, in, out);
}
