#include "transport/conn/cid/pmtu/pmtu.h"

void quic_pmtu_init(quic_pmtu *p) {
  p->validated = QUIC_PMTU_BASE;
  p->probe     = 0;
  p->ceiling   = QUIC_PMTU_MAX;
  p->lost      = 0;
  p->searching = 1;
}

/* The next candidate size above the validated PMTU, capped at the ceiling. */
static usz candidate(const quic_pmtu *p) {
  usz want = p->validated + QUIC_PMTU_STEP;
  return (want < p->ceiling) ? want : p->ceiling;
}

/* A candidate is worth probing only above the validated size and never at a
 * size the path already dropped (re-probing a lost size would loop). */
static int pmtu_viable(const quic_pmtu *p, usz next) {
  return next > p->validated && next != p->lost;
}

usz quic_pmtu_next_probe(quic_pmtu *p) {
  usz next = candidate(p);
  if (!p->searching || !pmtu_viable(p, next)) {
    p->searching = 0;
    return 0;
  }
  p->probe = next;
  return next;
}

void quic_pmtu_on_ack(quic_pmtu *p, usz size) {
  if (size > p->validated) p->validated = size; /* path carries this size */
  p->probe = 0;
}

void quic_pmtu_on_loss(quic_pmtu *p, usz size) {
  if (size < p->ceiling) p->ceiling = size; /* size is too big for the path */
  p->lost  = size;
  p->probe = 0;
}
