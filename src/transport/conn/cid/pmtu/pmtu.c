#include "transport/conn/cid/pmtu/pmtu.h"

void pmtu_init(pmtu* p) {
  p->validated     = QUIC_PMTU_BASE;
  p->probe         = 0;
  p->ceiling       = QUIC_PMTU_MAX;
  p->lost          = 0;
  p->searching     = 1;
  p->probe_count   = 0;
  p->probe_sent_at = 0;
  p->complete_at   = 0;
}

/* The next candidate size above the validated PMTU, capped at the ceiling. */
static usz candidate(const pmtu* p) {
  usz want = p->validated + QUIC_PMTU_STEP;
  return (want < p->ceiling) ? want : p->ceiling;
}

/* A candidate is worth probing only above the validated size and never at a
 * size the path already dropped (re-probing a lost size would loop). */
static int pmtu_viable(const pmtu* p, usz next) {
  return next > p->validated && next != p->lost;
}

/* RFC 8899 5.2: mark Search Complete, recording `now` as complete_at only the
 * first time (searching was still 1) so a later re-check does not keep
 * pushing the PMTU_RAISE_TIMER's start forward. */
static void conclude_search(pmtu* p, u64 now) {
  if (p->searching) p->complete_at = now;
  p->searching = 0;
}

usz pmtu_next_probe(pmtu* p, u64 now) {
  usz next = candidate(p);
  if (!p->searching || !pmtu_viable(p, next)) {
    conclude_search(p, now);
    return 0;
  }
  p->probe         = next;
  p->probe_sent_at = now;
  return next;
}

void pmtu_on_ack(pmtu* p, usz size) {
  if (size > p->validated) p->validated = size; /* path carries this size */
  p->probe         = 0;
  p->probe_count   = 0; /* RFC 8899 5.1.3: an ack resets PROBE_COUNT */
  p->probe_sent_at = 0; /* RFC 8899 5.1.1: the PROBE_TIMER is canceled */
}

/* RFC 8899 5.1.3/4.3: PROBE_COUNT exceeded MAX_PROBES for the already-
 * validated size -- a black hole, not just a failed search candidate. */
static int is_black_hole(const pmtu* p, usz size) {
  return p->probe_count > QUIC_PMTU_MAX_PROBES && size == p->validated;
}

/* RFC 8899 4.3: a black hole brings the PLPMTU itself back down, not just
 * caps future growth. */
static void pmtu_black_hole(pmtu* p) { p->validated = QUIC_PMTU_BASE; }

void pmtu_on_loss(pmtu* p, usz size) {
  p->probe_count++;                         /* RFC 8899 5.1.3 */
  if (size < p->ceiling) p->ceiling = size; /* size is too big for the path */
  p->lost          = size;
  p->probe         = 0;
  p->probe_sent_at = 0; /* RFC 8899 5.1.1: the PROBE_TIMER is reinitialized */
  if (is_black_hole(p, size)) pmtu_black_hole(p);
}

usz pmtu_mps(const pmtu* p) { return p->validated - QUIC_PMTU_OVERHEAD; }

/* RFC 8899 5.1.1: PROBE_TIMER is running only while a probe is outstanding
 * (probe_sent_at is set the moment pmtu_next_probe sends one, and
 * cleared by on_ack/on_loss when it resolves). */
int pmtu_probe_timer_due(const pmtu* p, u64 now) {
  if (!p->probe) return 0;
  return now - p->probe_sent_at >= QUIC_PMTU_PROBE_TIMER_US;
}

int pmtu_raise_timer_due(const pmtu* p, u64 now) {
  if (p->searching) return 0;
  return now - p->complete_at >= QUIC_PMTU_RAISE_TIMER_US;
}

void pmtu_resume_search(pmtu* p) {
  p->searching   = 1;
  p->ceiling     = QUIC_PMTU_MAX;
  p->lost        = 0;
  p->probe_count = 0;
  p->complete_at = 0;
}
