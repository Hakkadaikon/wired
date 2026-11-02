#include "transport/conn/lifecycle/conn/demux.h"
#include "transport/conn/lifecycle/conntable/conntable_impl.h"

static int conntable_cid_matches(wired_span want, const u8* cid, u8 cid_len) {
  return demux_match(want, wired_span_of(cid, cid_len));
}

/* The alt CID (rekey's stashed prior primary) also routes here, if set. */
static int conntable_alt_matches(const conntable* slot, wired_span want) {
  if (!slot->alt_cid_len) {
    return 0;
  }
  return conntable_cid_matches(want, slot->alt_cid, slot->alt_cid_len);
}

/* The second alternate (the spare advertised at accept) also routes here,
 * if set. */
static int conntable_alt2_matches(const conntable* slot, wired_span want) {
  if (!slot->alt2_cid_len) {
    return 0;
  }
  return conntable_cid_matches(want, slot->alt2_cid, slot->alt2_cid_len);
}

/* Either alternate CID routes here. Split out so the caller's own branch
 * count stays at the gate. */
static int conntable_any_alt_matches(const conntable* slot, wired_span want) {
  return conntable_alt_matches(slot, want) ||
         conntable_alt2_matches(slot, want);
}

static int conntable_slot_matches(const conntable* slot, wired_span want) {
  if (!slot->live) {
    return 0;
  }
  if (conntable_cid_matches(want, slot->cid, slot->cid_len)) {
    return 1;
  }
  return conntable_any_alt_matches(slot, want);
}

/* FNV-1a over the CID, keyed by the table's random seed (conntable_seed) and
 * finished with the murmur3 fmix32 avalanche, so a client cannot precompute
 * Initial DCIDs that share a bucket. Not a PRF: an attacker who learns the
 * buckets (e.g. by timing) can still cluster them, bounded by the probe
 * chain (<= 3 * cap buckets, see conntable.h). */
static u32 conntable_hash(wired_span c, u32 seed) {
  u32 h = (2166136261u ^ seed) ^ (u32)c.n;
  for (usz i = 0; i < c.n; i++) {
    h = (h ^ c.p[i]) * 16777619u;
  }
  h ^= h >> 16;
  h *= 0x85EBCA6Bu;
  h ^= h >> 13;
  h *= 0xC2B2AE35u;
  return h ^ (h >> 16);
}

/* nb == 0 (a zero-capacity table) has no bucket and no t[0] to hold the
 * seed: home 0, and the probe loops below never run. */
static usz conntable_home(const conntable* t, wired_span c, usz nb) {
  return nb ? conntable_hash(c, t[0].hseed) % nb : 0;
}

static const u16* conntable_bucket_at(const conntable* t, usz b) {
  return &t[b / CONNTABLE_HB].hix[b % CONNTABLE_HB];
}

static u16* conntable_bucket(conntable* t, usz b) {
  return (u16*)conntable_bucket_at(t, b);
}

/* Linear probing; terminates because the load is <= 3/4 (CONNTABLE_HB). */
static void conntable_index_put(conntable* t, usz cap, wired_span c, usz i) {
  usz nb = cap * CONNTABLE_HB;
  usz b  = conntable_home(t, c, nb);
  while (*conntable_bucket(t, b)) {
    b = b + 1 < nb ? b + 1 : 0;
  }
  *conntable_bucket(t, b) = (u16)(i + 1);
}

/* Index an alternate CID of slot i, if it is set. */
static void conntable_index_alt(
    conntable* t, usz cap, const u8* cid, u8 cid_len, usz i) {
  if (cid_len) {
    conntable_index_put(t, cap, wired_span_of(cid, cid_len), i);
  }
}

static void conntable_index_slot(conntable* t, usz cap, usz i) {
  if (!t[i].live) {
    return;
  }
  conntable_index_put(t, cap, wired_span_of(t[i].cid, t[i].cid_len), i);
  conntable_index_alt(t, cap, t[i].alt_cid, t[i].alt_cid_len, i);
  conntable_index_alt(t, cap, t[i].alt2_cid, t[i].alt2_cid_len, i);
}

/* Rebuild the whole index from the live slots (see conntable.h shortcut). */
void conntable_reindex(conntable* t, usz cap) {
  for (usz b = 0; b < cap * CONNTABLE_HB; b++) {
    *conntable_bucket(t, b) = 0;
  }
  for (usz i = 0; i < cap; i++) {
    conntable_index_slot(t, cap, i);
  }
}

void conntable_seed(conntable* t, usz cap, u32 seed) {
  if (cap) {
    t[0].hseed = seed;
  }
  conntable_reindex(t, cap);
}

/* One probe step: the matching slot, -1 at an empty bucket (end of chain),
 * -2 to keep probing. */
static int conntable_probe(const conntable* t, usz b, wired_span want) {
  u16 e = *conntable_bucket_at(t, b);
  if (!e) {
    return -1;
  }
  return conntable_slot_matches(&t[e - 1], want) ? e - 1 : -2;
}

int conntable_find(const conntable* t, usz cap, const u8* dcid, u8 dcid_len) {
  wired_span want = wired_span_of(dcid, dcid_len);
  usz        nb   = cap * CONNTABLE_HB;
  usz        home = conntable_home(t, want, nb);
  for (usz k = 0; k < nb; k++) {
    int r = conntable_probe(t, (home + k) % nb, want);
    if (r != -2) {
      return r;
    }
  }
  return -1;
}
