#include "tls/handshake/flight/resume/resume.h"

#include "common/bytes/util/bytes.h"

/* RFC 8446 4.6.1 */
int quic_resume_store(
    quic_resume* r, quic_span ticket, const quic_resume_store_in* in) {
  usz off = 0;
  if (!quic_put_bytes(
          quic_mspan_of(r->ticket, QUIC_RESUME_TICKET_MAX), &off, ticket))
    return 0;
  r->ticket_len  = ticket.n;
  r->issued_at   = in->issued_at;
  r->lifetime    = in->lifetime;
  r->max_data    = in->max_data;
  r->have_ticket = 1;
  return 1;
}

/* RFC 8446 4.6.1: usable while now < issued_at + lifetime. */
int quic_resume_valid(const quic_resume* r, u64 now) {
  return r->have_ticket && now < r->issued_at + r->lifetime;
}

/* RFC 9001 4.6 / RFC 9000 7.4.1 */
int quic_resume_tp_compatible(u64 remembered_max_data, u64 new_max_data) {
  return remembered_max_data <= new_max_data;
}

/* RFC 9001 4.6 */
int quic_resume_can_0rtt(
    const quic_resume* r, int ticket_valid, int tp_compatible) {
  return r->have_ticket && ticket_valid && tp_compatible;
}

/* RFC 9000 8.1 / 17.2.5: a Retry never invalidates resumption. */
int quic_resume_after_retry(const quic_resume* r, int retry_received) {
  (void)retry_received;
  return r->have_ticket;
}
