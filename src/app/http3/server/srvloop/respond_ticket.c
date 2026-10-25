#include "app/http3/server/srvloop/respond_impl.h"
#include "common/bytes/util/num.h"

static u32 ticket_max_early_data(const wired_server* s);
static u64 ticket_origin(const wired_server* s, u64 now);
static u64 resumption_left(u64 origin, u64 now);
static int tickets_owed(const wired_server* s, u64 left);
static int ticket_fill(const wired_server* s, u64 now, u64 left, ticket* t);
static int encode_tickets(const wired_server* s, ticket* t, wired_obuf* msg);
static int build_tickets(const wired_server* s, wired_obuf* msg);
static int put_crypto0(wired_obuf* out, wired_span data);

static u32 ticket_max_early_data(const wired_server* s) {
  return sdrv_early_allowed(&s->sdrv) ? WIRED_SRVLOOP_MAX_EARLY_DATA_SIZE : 0;
}

/* RFC 8446 4.6.1: when the keying material this connection hands on was
 * first established -- the resumed ticket's origin, or now for a full
 * handshake. */
static u64 ticket_origin(const wired_server* s, u64 now) {
  return s->sdrv.psk_accepted ? s->sdrv.psk_origin_at : now;
}

/* Seconds of SRVLOOP_RESUMPTION_MAX_SECS still left at now; 0 once spent.
 * A clock stepped back below origin counts as age 0. */
static u64 resumption_left(u64 origin, u64 now) {
  u64 age = now > origin ? now - origin : 0;
  return SRVLOOP_RESUMPTION_MAX_SECS -
         u64_min(age, SRVLOOP_RESUMPTION_MAX_SECS);
}

/* A ticket is owed only to a client that can resume with it (RFC 8446
 * 4.2.9: it offered psk_dhe_ke) while the resumption cap is not spent
 * (RFC 8446 4.6.1). */
static int tickets_owed(const wired_server* s, u64 left) {
  return s->sdrv.psk_dhe_ke && left > 0;
}

/* The fields this connection's tickets share: RFC 8446 4.2.10 alpn, the
 * suite, the origin, and a lifetime cut to what the cap leaves. */
static int ticket_fill(const wired_server* s, u64 now, u64 left, ticket* t) {
  *t = (ticket){
      {0},
      now,
      (u32)u64_min(SRVLOOP_TICKET_LIFETIME_SECS, left),
      0,
      (u8)s->sdrv.alpn,
      0,
      s->sdrv.cipher_suite,
      ticket_origin(s, now)};
  return srvkeys_ready() && wired_server_resumption_secret(s, t->secret);
}

/* SRVLOOP_TICKET_COUNT NewSessionTickets back to back, ticket_nonce 0..N-1:
 * unique across this connection's tickets, so each derives its own PSK
 * (RFC 8446 4.6.1). */
static int encode_tickets(const wired_server* s, ticket* t, wired_obuf* msg) {
  u8  key[KEYRING_KEY];
  usz w;
  keyring_key(srvkeys_ticket(), t->issued_at, 0, key);
  for (t->ticket_nonce = 0; t->ticket_nonce < SRVLOOP_TICKET_COUNT;
       t->ticket_nonce++) {
    w = tls_new_session_ticket_encode(
        msg->p + msg->len, msg->cap - msg->len, t, key,
        ticket_max_early_data(s));
    if (w == 0) {
      return 0;
    }
    msg->len += w;
  }
  return 1;
}

/* This confirmation's tickets into msg: 1 with msg->len 0 when none is owed,
 * 0 when they cannot be built. */
static int build_tickets(const wired_server* s, wired_obuf* msg) {
  u64    now  = wired_clock_epoch_secs();
  u64    left = resumption_left(ticket_origin(s, now), now);
  ticket t;
  if (!tickets_owed(s, left)) {
    return 1;
  }
  if (!ticket_fill(s, now, left, &t)) {
    return 0;
  }
  return encode_tickets(s, &t, msg);
}

/* data as a CRYPTO frame at offset 0 (RFC 9000 19.6) appended to out. */
static int put_crypto0(wired_obuf* out, wired_span data) {
  crypto_frame cf = {0, data.n, data.p};
  usz written = frame_put_crypto(out->p + out->len, out->cap - out->len, &cf);
  if (written == 0) {
    return 0;
  }
  out->len += written;
  return 1;
}

int srvloop_append_tickets(const wired_server* s, wired_obuf* out) {
  u8         msg[SRVLOOP_TICKET_COUNT * SRVLOOP_TICKET_MSG_MAX];
  wired_obuf mb = obuf_of(msg, sizeof msg);
  if (!build_tickets(s, &mb)) {
    return 0;
  }
  if (mb.len == 0) {
    return 1;
  }
  return put_crypto0(out, wired_span_of(msg, mb.len));
}
