#include "tls/keys/ticketguard/ticketguard.h"

void quic_ticketguard_init(quic_ticketguard* g) {
  g->next = 0;
  for (usz i = 0; i < QUIC_TICKETGUARD_CAP; i++) g->live[i] = 0;
}

/* 1 if slot i holds exactly this fingerprint. */
static int tg_match(const quic_ticketguard* g, usz i, const u8* fp) {
  u8 diff = (u8)!g->live[i];
  for (usz j = 0; j < QUIC_TICKETGUARD_FP; j++) diff |= g->fp[i][j] ^ fp[j];
  return diff == 0;
}

/* 1 if the fingerprint is anywhere in the seen set. */
static int tg_seen(const quic_ticketguard* g, const u8* fp) {
  for (usz i = 0; i < QUIC_TICKETGUARD_CAP; i++)
    if (tg_match(g, i, fp)) return 1;
  return 0;
}

/* Record a fingerprint, evicting the oldest ring slot. */
static void tg_record(quic_ticketguard* g, const u8* fp) {
  for (usz j = 0; j < QUIC_TICKETGUARD_FP; j++) g->fp[g->next][j] = fp[j];
  g->live[g->next] = 1;
  g->next          = (g->next + 1) % QUIC_TICKETGUARD_CAP;
}

int quic_ticketguard_first_use(quic_ticketguard* g, quic_span sealed) {
  if (sealed.n < QUIC_TICKETGUARD_FP) return 0;
  if (tg_seen(g, sealed.p)) return 0;
  tg_record(g, sealed.p);
  return 1;
}
