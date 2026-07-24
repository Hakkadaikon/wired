#include "tls/handshake/core/tls/newsessionticket.h"

#include "common/bytes/util/be.h"
#include "common/platform/rng/rng.h"
#include "tls/ext/tlsext/earlydata.h"
#include "tls/handshake/core/tls/handshake.h"

/* fixed prefix: ticket_lifetime(4) ticket_age_add(4) ticket_nonce_len(1)=0
 * ticket_len(2) ticket(sealed) -- extensions_len(2) plus any extensions
 * follow (put_nst_exts below). */
#define QUIC_NST_PREFIX_LEN (4 + 4 + 1 + 2 + QUIC_TICKET_SEALED_LEN)

/* RFC 8446 4.6.1: ticket_age_add MUST be a fresh random value per ticket, so
 * an observer cannot correlate ticket_age across issuances. */
static u32 nst_random_age_add(void) {
  u8 b[4];
  quic_rng_bytes(b, 4);
  return quic_get_be32(b);
}

static void put_nst_prefix(
    u8* body, const quic_ticket* t, u32 age_add, const u8* sealed) {
  usz i;
  quic_put_be32(body, t->lifetime_secs);
  quic_put_be32(body + 4, age_add);
  body[8] = 0; /* ticket_nonce_len */
  quic_put_be16(body + 9, QUIC_TICKET_SEALED_LEN);
  for (i = 0; i < QUIC_TICKET_SEALED_LEN; i++) body[11 + i] = sealed[i];
}

/* RFC 8446 4.2.10: extensions_len(2) followed by early_data(4+4) when
 * max_early_data_size is nonzero, or extensions_len(2)=0 alone otherwise.
 * Returns the bytes written (2 or 10). */
static usz put_nst_exts(u8* p, usz cap, u32 max_early_data_size) {
  quic_obuf eob;
  if (max_early_data_size == 0 || cap < 10) {
    quic_put_be16(p, 0);
    return 2;
  }
  eob = quic_obuf_of(p + 2, cap - 2);
  quic_tlsext_early_data_nst(max_early_data_size, &eob);
  quic_put_be16(p, (u16)eob.len);
  return 2 + eob.len;
}

usz quic_tls_new_session_ticket_encode(
    u8*                out,
    usz                cap,
    const quic_ticket* t,
    const u8           key[QUIC_TICKET_KEY_LEN],
    u32                max_early_data_size) {
  u8          sealed[QUIC_TICKET_SEALED_LEN];
  quic_ticket sealed_t = *t;
  usz         off      = quic_hs_begin(out, cap, QUIC_HS_NEW_SESSION_TICKET);
  if (off == 0 || cap - off < QUIC_NST_PREFIX_LEN + 2) return 0;
  sealed_t.age_add = nst_random_age_add();
  quic_ticket_seal(&sealed_t, key, sealed);
  put_nst_prefix(out + off, t, sealed_t.age_add, sealed);
  off += QUIC_NST_PREFIX_LEN;
  off += put_nst_exts(out + off, cap - off, max_early_data_size);
  quic_hs_finish(out, off);
  return off;
}

/* be16 read; the shared util only has the 32/64-bit loads (util/be.h). */
static u16 get_be16(const u8* p) { return (u16)(((u16)p[0] << 8) | p[1]); }

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
static int nst_take_ticket(quic_span msg, usz body_len, quic_span* sealed) {
  usz ticket_len = get_be16(msg.p + 4 + 9);
  if (!nst_ticket_fits(body_len, ticket_len)) return 0;
  *sealed = quic_span_of(msg.p + 4 + 11, ticket_len);
  return 1;
}

int quic_tls_new_session_ticket_parse(quic_span msg, quic_span* sealed) {
  u8  type;
  usz body_len;
  if (quic_hs_parse(msg, &type, &body_len) == 0) return 0;
  if (!nst_header_ok(type, body_len)) return 0;
  return nst_take_ticket(msg, body_len, sealed);
}
