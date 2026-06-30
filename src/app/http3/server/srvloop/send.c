#include "app/http3/server/srvloop/send.h"

#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvwire/wire.h"
#include "crypto/kdf/keys/keyset.h"
#include "transport/packet/build/hspkt/onertt.h"

/* RFC 9001 5.2: the server Initial is protected with the keys derived from the
 * client's original DCID (odcid), the same value the client opens with. */
int quic_srvloop_send_initial(
    const quic_server *s,
    const u8          *cli_scid,
    u8                 cli_scid_len,
    u64                pn,
    i64                ack_pn,
    const u8          *tls,
    usz                tls_len,
    u8                *out,
    usz                cap,
    usz               *out_len) {
  (void)cli_scid;
  (void)cli_scid_len;
  return quic_srvwire_seal_initial(
      s->sdrv.odcid, s->sdrv.odcid_len, s->sdrv.iscid, s->sdrv.iscid_len, pn,
      ack_pn, tls, tls_len, out, cap, out_len);
}

/* RFC 9001 5 / 5.1: Handshake flight sealed with the own-direction SERVER_HS.
 */
int quic_srvloop_send_handshake(
    const quic_server *s,
    const u8          *cli_scid,
    u8                 cli_scid_len,
    u64                pn,
    i64                ack_pn,
    const u8          *tls,
    usz                tls_len,
    u8                *out,
    usz                cap,
    usz               *out_len) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  if (!quic_srvloop_seal_keys(s, QUIC_LEVEL_HANDSHAKE, &k, &hp)) return 0;
  return quic_srvwire_seal_handshake(
      k, &hp, cli_scid, cli_scid_len, s->sdrv.iscid, s->sdrv.iscid_len, pn,
      ack_pn, tls, tls_len, out, cap, out_len);
}

/* RFC 9001 5 / 5.1: 1-RTT payload sealed with the own-direction SERVER_AP. */
int quic_srvloop_send_onertt(
    const quic_server *s,
    const u8          *cli_scid,
    u8                 cli_scid_len,
    u64                pn,
    const u8          *payload,
    usz                payload_len,
    u8                *out,
    usz                cap,
    usz               *out_len) {
  const quic_initial_keys *k;
  quic_aes128              hp;
  if (!quic_srvloop_seal_keys(s, QUIC_LEVEL_ONERTT, &k, &hp)) return 0;
  return quic_hspkt_onertt_build(
      k, &hp, cli_scid, cli_scid_len, pn, payload, payload_len, out, cap,
      out_len);
}
