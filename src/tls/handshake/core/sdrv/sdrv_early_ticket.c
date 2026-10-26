#include "app/http3/core/h3settings/control_settings.h"
#include "tls/handshake/core/sdrv/sdrv_impl.h"

/* RFC 9000 7.4.1 / RFC 9001 4.6.3: a 0-RTT client applies the limits the
 * ticket's connection advertised, so none may be lower now; RFC 9221 3:
 * nor max_datagram_frame_size. Otherwise 0-RTT is declined (the PSK still
 * resumes as 1-RTT). */
int sdrv_early_limits_ok(const sdrv* s, const ticket* t) {
  u64 cur[STP_REMEMBERED_N];
  int ok = 1;
  stp_remembered(&s->limits, cur);
  for (usz i = 0; i < STP_REMEMBERED_DGRAM; i++) {
    ok &= zerortt_param_ok(t->tp[i], cur[i]);
  }
  ok &= datagram_0rtt_accept_ok(
      t->tp[STP_REMEMBERED_DGRAM], cur[STP_REMEMBERED_DGRAM]);
  /* RFC 9114 7.2.4.2: and the HTTP/3 SETTINGS remembered with them */
  return ok & h3settings_zerortt_remembered_ok(
                  t->tp[STP_REMEMBERED_DGRAM], cur[STP_REMEMBERED_DGRAM]);
}

/* RFC 8446 4.6.1: a ticket is valid only for ticket_lifetime seconds from
 * issuance, for 1-RTT resumption as much as for 0-RTT -- past it the
 * keying material it carries is no longer usable. */
int sdrv_ticket_live(const ticket* t) {
  return wired_clock_epoch_secs() < t->issued_at + t->lifetime_secs;
}

/* RFC 6066 3: issued under this server_name (or none); RFC 9369 5: from
 * this connection's QUIC version. */
int sdrv_ticket_bound(const sdrv* s, const ticket* t) {
  return ct_diffn(t->sni, s->sni_digest, TICKET_SNI_LEN) == 0 &&
         ticket_version_ok(t->version, sdrv_wire_version(s));
}
