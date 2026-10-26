#include "transport/conn/cid/pmtu/pmtu.h"

#include "common/bytes/util/num.h"

void pmtu_init(pmtu* p) {
  p->validated     = PMTU_BASE;
  p->probe         = 0;
  p->ceiling       = PMTU_MAX;
  p->lost          = 0;
  p->max           = PMTU_MAX;
  p->phase         = PMTU_PHASE_SEARCHING;
  p->probe_count   = 0;
  p->big_lost      = 0;
  p->big_acked_pn  = 0;
  p->probe_sent_at = 0;
  p->complete_at   = 0;
}

void pmtu_set_max(pmtu* p, usz max) {
  usz m      = (usz)u64_min(u64_max(max, PMTU_BASE), PMTU_MAX);
  p->max     = m;
  p->ceiling = (usz)u64_min(p->ceiling, m);
}

/* The next candidate size above the validated PMTU, capped at the ceiling. */
static usz candidate(const pmtu* p) {
  return (usz)u64_min(p->validated + PMTU_STEP, p->ceiling);
}

/* A candidate is worth probing only above the validated size and never at a
 * size already concluded unsupported (re-probing it would loop). */
static int pmtu_viable(const pmtu* p, usz next) {
  return next > p->validated && next != p->lost;
}

/* Start the PROBE_TIMER for a probe of `size` (RFC 8899 5.1.1: "each time a
 * probe packet is sent, the PROBE_TIMER is started"). */
static usz pmtu_offer(pmtu* p, usz size, u64 now) {
  p->probe         = size;
  p->probe_sent_at = now;
  return size;
}

/* DISABLED and SEARCH_COMPLETE send no probes (RFC 8899 5.2: an
 * acknowledged PL SHOULD NOT generate PLPMTU probes in SEARCH_COMPLETE). */
static usz pmtu_next_none(pmtu* p, u64 now) {
  (void)p;
  (void)now;
  return 0;
}

/* RFC 8899 5.2 BASE/ERROR: PROBED_SIZE is BASE_PLPMTU. */
static usz pmtu_next_base(pmtu* p, u64 now) {
  return pmtu_offer(p, PMTU_BASE, now);
}

/* RFC 8899 5.2 SEARCHING: the next larger candidate, or SEARCH_COMPLETE
 * (recording `now` for the PMTU_RAISE_TIMER) once none is viable. */
static usz pmtu_next_search(pmtu* p, u64 now) {
  usz next = candidate(p);
  if (!pmtu_viable(p, next)) {
    p->phase       = PMTU_PHASE_COMPLETE;
    p->complete_at = now;
    return 0;
  }
  return pmtu_offer(p, next, now);
}

static usz (*const pmtu_next_by_phase[])(pmtu*, u64) = {
    pmtu_next_none, pmtu_next_base, pmtu_next_search, pmtu_next_none,
    pmtu_next_base};

usz pmtu_next_probe(pmtu* p, u64 now) {
  return pmtu_next_by_phase[p->phase](p, now);
}

/* RFC 8899 5.2: an acked BASE_PLPMTU probe moves BASE and ERROR to
 * SEARCHING; the other phases stay where they are. */
static const int pmtu_ack_next[] = {
    PMTU_PHASE_DISABLED, PMTU_PHASE_SEARCHING, PMTU_PHASE_SEARCHING,
    PMTU_PHASE_COMPLETE, PMTU_PHASE_SEARCHING};

void pmtu_on_ack(pmtu* p, usz size) {
  p->validated     = (usz)u64_max(p->validated, size);
  p->phase         = pmtu_ack_next[p->phase];
  p->probe         = 0;
  p->probe_count   = 0; /* RFC 8899 5.1.3: an ack resets PROBE_COUNT */
  p->probe_sent_at = 0; /* RFC 8899 5.1.1: the PROBE_TIMER is canceled */
}

/* RFC 8899 4.3/5.2: the path no longer carries the PLPMTU `size`. The
 * PLPMTU (and the MPS derived from it) drops to BASE_PLPMTU, which BASE then
 * confirms with a probe; `size` stays ruled out until the PMTU_RAISE_TIMER. */
static void pmtu_black_hole(pmtu* p, usz size) {
  p->phase         = PMTU_PHASE_BASE;
  p->validated     = PMTU_BASE;
  p->ceiling       = size;
  p->lost          = size;
  p->big_lost      = 0;
  p->probe         = 0;
  p->probe_count   = 0;
  p->probe_sent_at = 0;
}

/* RFC 8899 5.2 DISABLED/ERROR: nothing more to conclude (ERROR keeps
 * probing BASE_PLPMTU until one is acked). */
static void pmtu_verdict_none(pmtu* p, usz size) {
  (void)p;
  (void)size;
}

/* RFC 8899 5.2 BASE: BASE_PLPMTU failed MAX_PROBES times -> ERROR. */
static void pmtu_verdict_base(pmtu* p, usz size) {
  (void)size;
  p->phase = PMTU_PHASE_ERROR;
}

/* RFC 8899 5.2 SEARCHING/SEARCH_COMPLETE: `size` is unsupported. At the
 * validated PLPMTU that is a black hole (4.3, successive loss of PLPMTU-
 * sized probes); above it, it caps the search, which then completes. */
static void pmtu_verdict_search(pmtu* p, usz size) {
  if (size == p->validated) {
    pmtu_black_hole(p, size);
    return;
  }
  p->ceiling = (usz)u64_min(p->ceiling, size);
  p->lost    = size;
}

static void (*const pmtu_verdict_by_phase[])(pmtu*, usz) = {
    pmtu_verdict_none, pmtu_verdict_base, pmtu_verdict_search,
    pmtu_verdict_search, pmtu_verdict_none};

void pmtu_on_loss(pmtu* p, usz size) {
  p->probe         = 0;
  p->probe_sent_at = 0; /* RFC 8899 5.1.1: the PROBE_TIMER is reinitialized */
  if (++p->probe_count < PMTU_MAX_PROBES) {
    return; /* RFC 8899 5.2: PROBE_COUNT < MAX_PROBES -> probe it again */
  }
  p->probe_count = 0;
  pmtu_verdict_by_phase[p->phase](p, size);
}

void pmtu_on_big_ack(pmtu* p, u64 pn) {
  if (pn < p->big_acked_pn) {
    return;
  }
  p->big_acked_pn = pn;
  p->big_lost     = 0;
}

int pmtu_big_suspect(const pmtu* p, u64 pn) { return pn > p->big_acked_pn; }

/* Data-loss black hole detection applies while the PLPMTU is above the base
 * in SEARCHING/SEARCH_COMPLETE; BASE/ERROR probe BASE_PLPMTU instead. */
static int pmtu_big_phase(const pmtu* p) {
  return p->phase == PMTU_PHASE_SEARCHING || p->phase == PMTU_PHASE_COMPLETE;
}

static int pmtu_big_watched(const pmtu* p, usz n) {
  return n && pmtu_big_phase(p) && p->validated > PMTU_BASE;
}

void pmtu_on_big_losses(pmtu* p, usz n) {
  if (!pmtu_big_watched(p, n)) {
    return;
  }
  p->big_lost += (int)n;
  if (p->big_lost >= PMTU_MAX_PROBES) {
    pmtu_black_hole(p, p->validated);
  }
}

int pmtu_halted(const pmtu* p) { return p->phase == PMTU_PHASE_ERROR; }

usz pmtu_mps(const pmtu* p) { return p->validated - PMTU_OVERHEAD; }

/* RFC 8899 5.1.1: PROBE_TIMER is running only while a probe is outstanding
 * (probe_sent_at is set the moment pmtu_next_probe sends one, and
 * cleared by on_ack/on_loss when it resolves). */
int pmtu_probe_timer_due(const pmtu* p, u64 now) {
  if (!p->probe) {
    return 0;
  }
  return now - p->probe_sent_at >= PMTU_PROBE_TIMER_US;
}

int pmtu_raise_timer_due(const pmtu* p, u64 now) {
  if (p->phase != PMTU_PHASE_COMPLETE) {
    return 0;
  }
  return now - p->complete_at >= PMTU_RAISE_TIMER_US;
}

void pmtu_resume_search(pmtu* p) {
  p->phase       = PMTU_PHASE_SEARCHING;
  p->ceiling     = p->max;
  p->lost        = 0;
  p->probe_count = 0;
  p->complete_at = 0;
}
