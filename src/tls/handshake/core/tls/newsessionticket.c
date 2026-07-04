#include "tls/handshake/core/tls/newsessionticket.h"

#include "common/bytes/util/be.h"
#include "tls/handshake/core/tls/handshake.h"

/* body: ticket_lifetime(4) ticket_age_add(4) ticket_nonce_len(1)=0
 * ticket_len(2) ticket(sealed) extensions_len(2)=0 */
#define QUIC_NST_BODY_LEN (4 + 4 + 1 + 2 + QUIC_TICKET_SEALED_LEN + 2)

static void put_nst_body(u8 *body, const quic_ticket *t, const u8 *sealed) {
  usz i;
  quic_put_be32(body, t->lifetime_secs);
  quic_put_be32(body + 4, 0); /* ticket_age_add, ponytail: see header */
  body[8] = 0;                /* ticket_nonce_len */
  quic_put_be16(body + 9, QUIC_TICKET_SEALED_LEN);
  for (i = 0; i < QUIC_TICKET_SEALED_LEN; i++) body[11 + i] = sealed[i];
  quic_put_be16(body + 11 + QUIC_TICKET_SEALED_LEN, 0); /* extensions_len */
}

usz quic_tls_new_session_ticket_encode(
    u8 *out, usz cap, const quic_ticket *t, const u8 key[QUIC_TICKET_KEY_LEN]) {
  u8  sealed[QUIC_TICKET_SEALED_LEN];
  usz off = quic_hs_begin(out, cap, QUIC_HS_NEW_SESSION_TICKET);
  if (off == 0 || cap - off < QUIC_NST_BODY_LEN) return 0;
  quic_ticket_seal(t, key, sealed);
  put_nst_body(out + off, t, sealed);
  off += QUIC_NST_BODY_LEN;
  quic_hs_finish(out, off);
  return off;
}

/* be16 read; the shared util only has the 32/64-bit loads (util/be.h). */
static u16 get_be16(const u8 *p) { return (u16)(((u16)p[0] << 8) | p[1]); }

/* Whether type/body_len are a well-formed NewSessionTicket header carrying at
 * least the fixed 11-byte prefix before the ticket bytes. */
static int nst_header_ok(u8 type, usz body_len) {
  return type == QUIC_HS_NEW_SESSION_TICKET && body_len >= 11;
}

/* Whether body_len legitimately carries a QUIC_TICKET_SEALED_LEN ticket
 * starting right after the fixed 11-byte prefix. */
static int nst_ticket_fits(usz body_len, usz ticket_len) {
  return ticket_len == QUIC_TICKET_SEALED_LEN && body_len >= 11 + ticket_len;
}

/* Body-level check + the sealed-ticket view, once the header parsed and
 * passed nst_header_ok. */
static int nst_take_ticket(
    quic_span msg, usz body_len, quic_span *sealed) {
  usz ticket_len = get_be16(msg.p + 4 + 9);
  if (!nst_ticket_fits(body_len, ticket_len)) return 0;
  *sealed = quic_span_of(msg.p + 4 + 11, ticket_len);
  return 1;
}

int quic_tls_new_session_ticket_parse(quic_span msg, quic_span *sealed) {
  u8  type;
  usz body_len;
  if (quic_hs_parse(msg, &type, &body_len) == 0) return 0;
  if (!nst_header_ok(type, body_len)) return 0;
  return nst_take_ticket(msg, body_len, sealed);
}
