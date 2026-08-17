#include "tls/handshake/flight/resume/resume.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"

/* RFC 8446 4.6.1 */
/* Copy the captured resumption PSK, when the caller has one. */
static void resume_take_psk(quic_resume* r, const u8* psk) {
  r->have_psk = psk != 0;
  if (!psk) return;
  for (usz i = 0; i < 32; i++) r->psk[i] = psk[i];
}

/* RFC 6066 3: remember the server_name this session was established under,
 * truncated to QUIC_RESUME_SNI_MAX (RFC 1035 3.1's 255-octet name bound). */
static void resume_take_sni(quic_resume* r, wired_span sni) {
  r->sni_len = quic_u64_min(sni.n, QUIC_RESUME_SNI_MAX);
  for (usz i = 0; i < r->sni_len; i++) r->sni[i] = sni.p[i];
}

int quic_resume_store(
    quic_resume* r, wired_span ticket, const quic_resume_store_in* in) {
  usz off = 0;
  if (!quic_put_bytes(
          wired_mspan_of(r->ticket, QUIC_RESUME_TICKET_MAX), &off, ticket))
    return 0;
  r->ticket_len  = ticket.n;
  r->issued_at   = in->issued_at;
  r->lifetime    = in->lifetime;
  r->max_data    = in->max_data;
  r->have_ticket = 1;
  resume_take_psk(r, in->psk);
  resume_take_sni(r, in->sni);
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

/* RFC 6066 3: an omitted server_name on resumption, or no remembered one, is
 * always compatible; otherwise the two names must match exactly. */
int quic_resume_sni_compatible(const quic_resume* r, wired_span new_sni) {
  if (new_sni.n == 0 || r->sni_len == 0) return 1;
  return quic_ascii_dns_eq(wired_span_of(r->sni, r->sni_len), new_sni);
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

/* Blob layout: issued_at be64 | lifetime be32 | max_data be64 | psk 32 |
 * ticket_len be16 | ticket bytes. */
#define RESUME_BLOB_HDR (8 + 4 + 8 + 32 + 2)

usz quic_resume_session(const quic_resume* r, u8* out, usz cap) {
  usz off = 0;
  if (!r->have_ticket || RESUME_BLOB_HDR + r->ticket_len > cap) return 0;
  quic_put_be64(out, r->issued_at);
  quic_put_be32(out + 8, r->lifetime);
  quic_put_be64(out + 12, r->max_data);
  off = 20;
  quic_put_bytes(wired_mspan_of(out, cap), &off, wired_span_of(r->psk, 32));
  quic_put_be16(out + 52, (u16)r->ticket_len);
  off = RESUME_BLOB_HDR;
  quic_put_bytes(
      wired_mspan_of(out, cap), &off, wired_span_of(r->ticket, r->ticket_len));
  return off;
}

/* The declared ticket length, if the blob is big enough to hold it. */
static int resume_blob_len_ok(wired_span blob, usz* tlen) {
  if (blob.n < RESUME_BLOB_HDR) return 0;
  *tlen = quic_get_be16(blob.p + 52);
  return *tlen <= QUIC_RESUME_TICKET_MAX && blob.n == RESUME_BLOB_HDR + *tlen;
}

int quic_resume_set_session(quic_resume* r, wired_span blob) {
  usz tlen;
  usz off = 0;
  if (!resume_blob_len_ok(blob, &tlen)) return 0;
  r->issued_at = quic_get_be64(blob.p);
  r->lifetime  = quic_get_be32(blob.p + 8);
  r->max_data  = quic_get_be64(blob.p + 12);
  quic_take_bytes(
      wired_span_of(blob.p + 20, 32), &off, wired_mspan_of(r->psk, 32));
  for (usz i = 0; i < tlen; i++) r->ticket[i] = blob.p[RESUME_BLOB_HDR + i];
  r->ticket_len  = tlen;
  r->have_ticket = 1;
  r->have_psk    = 1;
  return 1;
}

int quic_resume_early_keys(
    const quic_resume* r, const u8* ch, usz ch_len, quic_initial_keys* out) {
  if (!r->have_psk) return 0;
  quic_tls_early_keys(r->psk, ch, ch_len, out);
  return 1;
}
