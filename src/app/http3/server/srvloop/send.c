#include "app/http3/server/srvloop/send.h"

#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvwire/wire.h"
#include "crypto/kdf/keys/keyset.h"
#include "transport/packet/build/hspkt/onertt.h"

/* RFC 9001 5.2: the server Initial is protected with the keys derived from the
 * client's original DCID (odcid), the same value the client opens with. */
int wired_srvloop_send_initial(
    const wired_server* s, const wired_srvloop_send_in* in, quic_obuf* out) {
  quic_srvwire_seal_in wi = {
      quic_span_of(s->sdrv.odcid, s->sdrv.odcid_len),
      quic_span_of(s->sdrv.iscid, s->sdrv.iscid_len),
      in->pn,
      in->ack_pn,
      in->payload,
      0};
  return quic_srvwire_seal_initial(&wi, out);
}

/* RFC 9001 5 / 5.1: Handshake flight sealed with the own-direction SERVER_HS.
 */
int wired_srvloop_send_handshake(
    const wired_server* s, const wired_srvloop_send_in* in, quic_obuf* out) {
  wired_srvloop_dirkeys dk;
  quic_srvwire_seal_in  wi = {
      in->cli_scid, quic_span_of(s->sdrv.iscid, s->sdrv.iscid_len),
      in->pn,       in->ack_pn,
      in->payload,  in->crypto_off};
  quic_protect_keys k;
  if (!wired_srvloop_seal_keys(s, QUIC_LEVEL_HANDSHAKE, &dk)) return 0;
  k = (quic_protect_keys){dk.keys, &dk.hp};
  return quic_srvwire_seal_handshake(&k, &wi, out);
}

/* RFC 9001 5 / 5.1: 1-RTT payload sealed with the own-direction SERVER_AP. */
int wired_srvloop_send_onertt(
    const wired_server* s, const wired_srvloop_send_in* in, quic_obuf* out) {
  wired_srvloop_dirkeys dk;
  if (!wired_srvloop_seal_keys(s, QUIC_LEVEL_ONERTT, &dk)) return 0;
  quic_protect_keys      pk = {dk.keys, &dk.hp};
  quic_hspkt_onertt_desc d  = {in->cli_scid, in->pn, in->payload};
  if (!quic_hspkt_onertt_build(&pk, &d, out)) return 0;
  return 1;
}
