#include "tls/handshake/core/sdrv/sdrv_impl.h"

static int find_client_early_data_ext(
    const u8* ch, usz ch_len, wired_span* ext);
static zerortt_seen* sdrv_zerortt_seen(void);
static int           sdrv_early_data_eligible(
    const ticket* t, const tlsext_psk_offer* off);
static int sdrv_early_data_wanted(
    const u8* ch_msg, usz ch_len, const ticket* t, const tlsext_psk_offer* off);
static void sdrv_take_early_keys(sdrv* s, const u8* ch_msg, usz ch_len);
static int  sdrv_ticket_alpn_matches(const sdrv* s, const ticket* t);
static int  sdrv_early_alpn_ok(const sdrv* s, const ticket* t);
static int  sdrv_early_permitted(const sdrv* s, const ticket* t);
static void sdrv_psk_accept_opened(
    sdrv*                   s,
    const ticket*           t,
    const u8*               ch_msg,
    usz                     ch_len,
    const tlsext_psk_offer* off);
static int sdrv_psk_open_usable(
    const sdrv* s, const tlsext_psk_offer* off, ticket* t);
static int sdrv_psk_try_offer(
    sdrv*                   s,
    const u8*               ch_msg,
    usz                     ch_len,
    wired_span              psk_ext,
    const tlsext_psk_offer* off);
static int sdrv_find_psk_offer(
    const sdrv*       s,
    const u8*         ch_msg,
    usz               ch_len,
    wired_span*       psk_ext,
    tlsext_psk_offer* off);

static int find_client_early_data_ext(
    const u8* ch, usz ch_len, wired_span* ext) {
  usz body, start, end;
  if (!sdrv_is_client_hello(ch, ch_len, &body)) {
    return 0;
  }
  if (!sdrv_ch_exts_span(ch + 4, body, &start, &end)) {
    return 0;
  }
  return sdrv_ch_find_ext(ch + 4, start, end, SDRV_EARLY_DATA_EXT_TYPE, ext);
}

/* RFC 8446 8.1 / RFC 9001 9.2: single-use ticket enforcement, shared by
 * every sdrv instance in this process (0-RTT replay must be caught
 * across connections, not just within one). Reused verbatim across tests in
 * this binary: a ticket identity is process-unique sealed-ciphertext bytes
 * (a fresh random nonce per ticket_seal call), so unrelated tests never
 * collide on it. */
/* Zero-initialized static storage is already an empty, unlocked tracker
 * (zerortt_seen_init's own state), so no lazy init -- a lazy init flag
 * would itself race between threads. */
static zerortt_seen g_sdrv_zerortt_seen;

static zerortt_seen* g_sdrv_zerortt_tab = &g_sdrv_zerortt_seen;

static zerortt_seen* sdrv_zerortt_seen(void) { return g_sdrv_zerortt_tab; }

int sdrv_zerortt_share(void) {
  i64 p;
  if (g_sdrv_zerortt_tab != &g_sdrv_zerortt_seen) {
    return 1;
  }
  p = wired_arch_mmap(
      0, sizeof(zerortt_seen), SDRV_PROT_RW, SDRV_MAP_SHARED_ANON, -1, 0);
  if (p < 0) {
    return 0;
  }
  bytes_memcpy((void*)p, &g_sdrv_zerortt_seen, sizeof(zerortt_seen));
  g_sdrv_zerortt_tab = (zerortt_seen*)p;
  return 1;
}

/* RFC 8446 4.2.11.1 / 8.3: the ticket is on its first use (RFC 8446 8.1) and
 * the client's claimed ticket age is still fresh relative to the server's
 * own record of issuance (ticket_freshness_ok) -- the two conditions
 * zerortt_replay_ok's ticket_first_use argument and the freshness gate
 * this SDK adds on top of it. A stale/manipulated age is treated exactly
 * like a policy-unsafe request: 0-RTT is declined, the handshake itself
 * proceeds as 1-RTT (RFC 8446 4.2.10). */
static int sdrv_early_data_eligible(
    const ticket* t, const tlsext_psk_offer* off) {
  int first_use = zerortt_seen_check(
      sdrv_zerortt_seen(), wired_span_of(off->identity, off->id_len));
  if (!zerortt_replay_ok(1, first_use)) {
    return 0;
  }
  return ticket_freshness_ok(t, off->ticket_age, wired_clock_epoch_secs());
}

/* RFC 8446 4.2.10: the ClientHello asked for 0-RTT (an early_data extension
 * is present) and the presented ticket is eligible (see
 * sdrv_early_data_eligible's doc). */
static int sdrv_early_data_wanted(
    const u8*               ch_msg,
    usz                     ch_len,
    const ticket*           t,
    const tlsext_psk_offer* off) {
  wired_span ed_ext;
  if (!find_client_early_data_ext(ch_msg, ch_len, &ed_ext)) {
    return 0;
  }
  return sdrv_early_data_eligible(t, off);
}

/* RFC 8446 4.2.10 / RFC 9001 4.6.1: derive and cache the 0-RTT key/iv/hp
 * (client_early_traffic_secret) over the accepted PSK and the raw
 * ClientHello bytes -- the same inputs a peer's own 0-RTT sender used. */
static void sdrv_take_early_keys(sdrv* s, const u8* ch_msg, usz ch_len) {
  tls_early_keys_suite(
      s->cipher_suite, s->psk_secret, ch_msg, ch_len, &s->early_keys);
  s->early_data_accepted = 1;
}

/* RFC 8446 4.2.10: the ticket's recorded ALPN (0 = not recorded) is the
 * one negotiated now. */
static int sdrv_ticket_alpn_matches(const sdrv* s, const ticket* t) {
  return t->alpn == SALPN_NONE || t->alpn == s->alpn;
}

int sdrv_early_allowed(const sdrv* s) { return s->alpn != SALPN_RAW; }

/* 0-RTT may be accepted under this ALPN (sdrv_early_allowed), and only
 * with a ticket issued under the same ALPN (RFC 8446 4.2.10). */
static int sdrv_early_alpn_ok(const sdrv* s, const ticket* t) {
  return sdrv_early_allowed(s) && t->suite == s->cipher_suite &&
         sdrv_ticket_alpn_matches(s, t);
}

/* RFC 8446 4.1.2: "Early data is not permitted after a HelloRetryRequest"
 * -- a ClientHello2 that keeps early_data still resumes, as 1-RTT. */
static int sdrv_early_permitted(const sdrv* s, const ticket* t) {
  return !s->hrr_sent && sdrv_early_alpn_ok(s, t);
}

/* A ticket that opened AND whose binder verified: record psk_accepted/
 * psk_secret and derive 0-RTT keys when the ClientHello asked for them and
 * the ticket is not a replay. */
static void sdrv_psk_accept_opened(
    sdrv*                   s,
    const ticket*           t,
    const u8*               ch_msg,
    usz                     ch_len,
    const tlsext_psk_offer* off) {
  s->psk_accepted = 1;
  /* s->psk_secret feeds RFC 8446 7.1's Early Secret = HKDF-Extract(0, PSK)
   * -- the actual PSK (see sdrv_psk_from_ticket_secret's doc), not the raw
   * ticket-stored resumption_master_secret. */
  sdrv_psk_from_ticket_secret(t, s->psk_secret);
  if (sdrv_early_permitted(s, t) &&
      sdrv_early_data_wanted(ch_msg, ch_len, t, off)) {
    sdrv_take_early_keys(s, ch_msg, ch_len);
  }
}

/* RFC 8446 4.2.11: the ticket opens AND its hash is the negotiated suite's
 * -- a PSK of another hash is unusable here, so it is ignored like an
 * unknown identity (full handshake), never keyed under the wrong hash. */
static int sdrv_psk_open_usable(
    const sdrv* s, const tlsext_psk_offer* off, ticket* t) {
  return sdrv_psk_open_ticket(s, off, t) &&
         tls_hash_of(t->suite)->len == tls_hash_of(s->cipher_suite)->len;
}

/* A parsed pre_shared_key offer: open its ticket and verify the binder.
 * RFC 8446 4.2.11: an identity that does not open (unknown, forged, or
 * sealed under a retired ticket key) is ignored and the handshake
 * continues as a full handshake. The binder check still runs (over a
 * zero ticket) so both paths cost the same work. A recognized identity
 * whose binder fails aborts with decrypt_error (RFC 8446 4.2.11.2). */
static int sdrv_psk_try_offer(
    sdrv*                   s,
    const u8*               ch_msg,
    usz                     ch_len,
    wired_span              psk_ext,
    const tlsext_psk_offer* off) {
  ticket t      = {{0}, 0, 0, 0, 0, 0, 0};
  int    opened = sdrv_psk_open_usable(s, off, &t);
  int    bound  = sdrv_psk_binder_ok(s, &t, ch_msg, psk_ext, off);
  if (!opened) {
    return 1;
  }
  if (!bound) {
    s->last_error = err_crypto(51); /* decrypt_error, RFC 8446 4.2.11.2 */
    return 0;
  }
  sdrv_psk_accept_opened(s, &t, ch_msg, ch_len, off);
  return 1;
}

/* Locate and parse a pre_shared_key offer in the ClientHello, if resumption
 * is enabled and one is present. Returns 1 and fills *psk_ext and *off only
 * when both are found and well-formed; 0 otherwise (disabled, absent, or
 * malformed extension -- all "nothing to try", not an error). */
static int sdrv_find_psk_offer(
    const sdrv*       s,
    const u8*         ch_msg,
    usz               ch_len,
    wired_span*       psk_ext,
    tlsext_psk_offer* off) {
  if (!s->has_ticket_key) {
    return 0;
  }
  if (!sdrv_find_client_psk_ext(ch_msg, ch_len, psk_ext)) {
    return 0;
  }
  return tlsext_pre_shared_key_parse(psk_ext->p, psk_ext->n, off);
}

/* RFC 8446 4.2.11: if resumption is enabled and the ClientHello carries a
 * well-formed pre_shared_key extension, try to accept it (see
 * sdrv_recv_client_hello's doc for the full absent/open-fail/binder-
 * fail state table). Absent/disabled/malformed: no-op success, matching
 * today's full-handshake behavior exactly. */
int sdrv_ch_take_psk(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span       psk_ext;
  tlsext_psk_offer off;
  if (!sdrv_find_psk_offer(s, ch_msg, ch_len, &psk_ext, &off)) {
    return 1;
  }
  return sdrv_psk_try_offer(s, ch_msg, ch_len, psk_ext, &off);
}
