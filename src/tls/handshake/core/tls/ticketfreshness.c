#include "tls/handshake/core/tls/ticketfreshness.h"

u32 quic_ticket_real_age_ms(u32 obfuscated_age, u32 age_add) {
  return obfuscated_age - age_add; /* RFC 8446 4.2.11.1: mod 2^32 */
}

/* now_secs - issued_at, clamped to 0 (a claim from before issuance is never
 * negative skew -- the lifetime check below rejects a stale ticket, and this
 * keeps the subtraction well-defined without a signed type). */
static u64 freshness_server_age_secs(const quic_ticket* t, u64 now_secs) {
  if (now_secs <= t->issued_at) return 0;
  return now_secs - t->issued_at;
}

/* |claimed - measured|, in seconds, without a signed intermediate. */
static u64 freshness_skew_secs(u64 claimed_secs, u64 measured_secs) {
  if (claimed_secs > measured_secs) return claimed_secs - measured_secs;
  return measured_secs - claimed_secs;
}

int quic_ticket_freshness_ok(
    const quic_ticket* t, u32 obfuscated_age, u64 now_secs) {
  u64 claimed_secs, measured_secs, skew;
  int lifetime_ok = now_secs < t->issued_at + t->lifetime_secs;
  if (!lifetime_ok) return 0;
  claimed_secs  = quic_ticket_real_age_ms(obfuscated_age, t->age_add) / 1000;
  measured_secs = freshness_server_age_secs(t, now_secs);
  skew          = freshness_skew_secs(claimed_secs, measured_secs);
  return skew <= QUIC_TICKET_FRESHNESS_WINDOW_SECS;
}
