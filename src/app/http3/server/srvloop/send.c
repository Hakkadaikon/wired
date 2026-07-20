#include "app/http3/server/srvloop/send.h"

#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvwire/wire.h"
#include "crypto/kdf/keys/keyset.h"
#include "tls/keys/keyupdate/keyphase.h"
#include "transport/packet/build/hspkt/onertt.h"

/* RFC 9001 5.2: the server Initial is protected with the keys derived from
 * the client's original DCID (odcid), the same value the client opens with --
 * but it is ADDRESSED to in->cli_scid, the client's own SCID (RFC 9000 7.2;
 * possibly zero-length). Writing the odcid into the header instead makes the
 * client discard the reply unread (RFC 9000 5.1) and PTO-retransmit its
 * Initial until it idles out. */
int wired_srvloop_send_initial_ver(
    u32                          version,
    const wired_server*          s,
    const wired_srvloop_send_in* in,
    quic_obuf*                   out) {
  quic_srvwire_seal_in wi = {
      quic_span_of(s->sdrv.odcid, s->sdrv.odcid_len),
      in->cli_scid,
      quic_span_of(s->sdrv.iscid, s->sdrv.iscid_len),
      in->pn,
      in->ack_pn,
      in->payload,
      0};
  return quic_srvwire_seal_initial_ver(version, &wi, out);
}

int wired_srvloop_send_initial(
    const wired_server* s, const wired_srvloop_send_in* in, quic_obuf* out) {
  return wired_srvloop_send_initial_ver(QUIC_VERSION_1, s, in, out);
}

/* RFC 9001 5 / 5.1: Handshake flight sealed with the own-direction SERVER_HS,
 * addressed to the client's SCID (RFC 9000 7.2). The key-derivation dcid slot
 * is unused at this level (keys come from the schedule). */
int wired_srvloop_send_handshake(
    const wired_server* s, const wired_srvloop_send_in* in, quic_obuf* out) {
  wired_srvloop_dirkeys dk;
  quic_srvwire_seal_in  wi = {
      quic_span_of((const u8*)0, 0),
      in->cli_scid,
      quic_span_of(s->sdrv.iscid, s->sdrv.iscid_len),
      in->pn,
      in->ack_pn,
      in->payload,
      in->crypto_off};
  quic_protect_keys k;
  if (!wired_srvloop_seal_keys(s, QUIC_LEVEL_HANDSHAKE, &dk)) return 0;
  k = (quic_protect_keys){dk.keys, &dk.hp};
  return quic_srvwire_seal_handshake_suite(s->sdrv.cipher_suite, &k, &wi, out);
}

/* RFC 9001 6.2: this endpoint's send-side generation (s->ku_send.cur,
 * advanced by onertt_rotate_send once a peer Key Update is confirmed --
 * RFC 9001 "MUST update its send keys to the corresponding key phase in
 * response"). Falls back to the schedule's fixed generation-0 SERVER_AP only
 * if seeding kuswitch itself failed (should not happen once confirmed; a
 * missing key still fails closed). Owns hp's storage via the caller's out
 * param so the returned quic_protect_keys stays valid. */
static int send_onertt_keys(
    const wired_server* s, quic_aes128* hp, quic_protect_keys* out) {
  wired_srvloop_dirkeys dk;
  if (s->ku_seeded) {
    quic_aes128_init(hp, s->ku_send.cur.hp);
    *out = (quic_protect_keys){&s->ku_send.cur, hp};
    return 1;
  }
  if (!wired_srvloop_seal_keys(s, QUIC_LEVEL_ONERTT, &dk)) return 0;
  *out = (quic_protect_keys){dk.keys, &dk.hp};
  return 1;
}

/* RFC 9001 5 / 5.1 / 6: 1-RTT payload sealed with the own-direction
 * SERVER_AP, its Key Phase bit set to this endpoint's current send-side
 * generation (quic_hspkt_onertt_build's byte0 has no way to infer the
 * phase from the keys alone -- the wire bit is the only signal a peer
 * uses to detect an update, RFC 9001 6.3). 0 (generation 0's phase) before
 * kuswitch is seeded, matching send_onertt_keys's own fallback. */
int wired_srvloop_send_onertt(
    const wired_server* s, const wired_srvloop_send_in* in, quic_obuf* out) {
  quic_aes128       hp;
  quic_protect_keys pk;
  int phase = s->ku_seeded ? quic_keyphase_bit(s->ku_send.generation) : 0;
  quic_hspkt_onertt_desc d = {in->cli_scid, in->pn, in->payload, phase};
  if (!send_onertt_keys(s, &hp, &pk)) return 0;
  return quic_hspkt_onertt_build_suite(s->sdrv.cipher_suite, &pk, &d, out);
}
