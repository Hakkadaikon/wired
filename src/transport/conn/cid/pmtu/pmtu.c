#include "transport/conn/cid/pmtu/pmtu.h"

void quic_pmtu_init(quic_pmtu* p) {
  p->validated   = QUIC_PMTU_BASE;
  p->probe       = 0;
  p->ceiling     = QUIC_PMTU_MAX;
  p->lost        = 0;
  p->searching   = 1;
  p->probe_count = 0;
}

/* The next candidate size above the validated PMTU, capped at the ceiling. */
static usz candidate(const quic_pmtu* p) {
  usz want = p->validated + QUIC_PMTU_STEP;
  return (want < p->ceiling) ? want : p->ceiling;
}

/* A candidate is worth probing only above the validated size and never at a
 * size the path already dropped (re-probing a lost size would loop). */
static int pmtu_viable(const quic_pmtu* p, usz next) {
  return next > p->validated && next != p->lost;
}

usz quic_pmtu_next_probe(quic_pmtu* p) {
  usz next = candidate(p);
  if (!p->searching || !pmtu_viable(p, next)) {
    p->searching = 0;
    return 0;
  }
  p->probe = next;
  return next;
}

void quic_pmtu_on_ack(quic_pmtu* p, usz size) {
  if (size > p->validated) p->validated = size; /* path carries this size */
  p->probe       = 0;
  p->probe_count = 0; /* RFC 8899 5.1.3: an ack resets PROBE_COUNT */
}

/* RFC 8899 5.1.3/4.3: PROBE_COUNT exceeded MAX_PROBES for the already-
 * validated size -- a black hole, not just a failed search candidate. */
static int is_black_hole(const quic_pmtu* p, usz size) {
  return p->probe_count > QUIC_PMTU_MAX_PROBES && size == p->validated;
}

/* RFC 8899 4.3: a black hole brings the PLPMTU itself back down, not just
 * caps future growth. */
static void pmtu_black_hole(quic_pmtu* p) { p->validated = QUIC_PMTU_BASE; }

void quic_pmtu_on_loss(quic_pmtu* p, usz size) {
  p->probe_count++;                         /* RFC 8899 5.1.3 */
  if (size < p->ceiling) p->ceiling = size; /* size is too big for the path */
  p->lost  = size;
  p->probe = 0;
  if (is_black_hole(p, size)) pmtu_black_hole(p);
}

usz quic_pmtu_mps(const quic_pmtu* p) {
  return p->validated - QUIC_PMTU_OVERHEAD;
}
