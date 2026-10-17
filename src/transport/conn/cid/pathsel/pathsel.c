#include "transport/conn/cid/pathsel/pathsel.h"

#include "common/bytes/util/ct.h"

static int pathsel_peer_eq(const sockaddr* a, const sockaddr* b) {
  return a->port_be == b->port_be && ct_diffn(a->addr, b->addr, 16) == 0;
}

int pathsel_key_eq(const pathsel_key* a, const pathsel_key* b) {
  return a->fd == b->fd && pathsel_peer_eq(&a->peer, &b->peer);
}

static int pathsel_holds(const pathsel_slot* s, const pathsel_key* k) {
  return s->in_use && pathsel_key_eq(&s->key, k);
}

pathsel_slot* pathsel_find(pathsel* p, const pathsel_key* k) {
  for (usz i = 0; i < PATHSEL_SLOTS; i++) {
    if (pathsel_holds(&p->slot[i], k)) {
      return &p->slot[i];
    }
  }
  return 0;
}

static pathsel_slot* pathsel_first_free(pathsel* p) {
  for (usz i = 0; i < PATHSEL_SLOTS; i++) {
    if (!p->slot[i].in_use) {
      return &p->slot[i];
    }
  }
  return 0;
}

/* The slot not holding keep (both are busy here). */
static pathsel_slot* pathsel_victim(pathsel* p, const pathsel_key* keep) {
  return pathsel_holds(&p->slot[0], keep) ? &p->slot[1] : &p->slot[0];
}

static pathsel_slot* pathsel_take(pathsel_slot* s, const pathsel_key* k) {
  if (!s) {
    return 0;
  }
  *s        = (pathsel_slot){0};
  s->key    = *k;
  s->in_use = 1;
  return s;
}

pathsel_slot* pathsel_claim(
    pathsel* p, const pathsel_key* k, const pathsel_key* keep) {
  pathsel_slot* s = pathsel_find(p, k);
  if (s) {
    return s;
  }
  s = pathsel_first_free(p);
  return pathsel_take(s ? s : pathsel_victim(p, keep), k);
}

pathsel_slot* pathsel_claim_free(pathsel* p, const pathsel_key* k) {
  return pathsel_take(pathsel_first_free(p), k);
}

/* Free s and report its path. */
static int pathsel_release(pathsel_slot* s, pathsel_key* out) {
  *out      = s->key;
  s->in_use = 0;
  return 1;
}

/* RFC 9000 8.2.3: resp echoes the latest or the previous challenge. */
static int pathsel_echoes(const pathsel_slot* s, const u8 resp[PATH_DATA]) {
  return ct_diff8(s->data, resp) == 0 ||
         (s->tries && ct_diff8(s->prev, resp) == 0);
}

static int pathsel_answers(const pathsel_slot* s, const u8 resp[PATH_DATA]) {
  return s->in_use && pathsel_echoes(s, resp);
}

int pathsel_match(pathsel* p, const u8 resp[PATH_DATA], pathsel_key* out) {
  for (usz i = 0; i < PATHSEL_SLOTS; i++) {
    if (pathsel_answers(&p->slot[i], resp)) {
      return pathsel_release(&p->slot[i], out);
    }
  }
  return 0;
}

static int pathsel_expired(const pathsel_slot* s, u64 now_ms, u64 timeout_ms) {
  return s->in_use && now_ms >= s->first_ms + timeout_ms;
}

int pathsel_expire(pathsel* p, u64 now_ms, u64 timeout_ms, pathsel_key* out) {
  for (usz i = 0; i < PATHSEL_SLOTS; i++) {
    if (pathsel_expired(&p->slot[i], now_ms, timeout_ms)) {
      return pathsel_release(&p->slot[i], out);
    }
  }
  return 0;
}

static int pathsel_resend(const pathsel_slot* s, u64 now_ms, u64 pto_ms) {
  return s->in_use && now_ms >= s->last_ms + (pto_ms << s->tries);
}

pathsel_slot* pathsel_resend_due(pathsel* p, u64 now_ms, u64 pto_ms) {
  for (usz i = 0; i < PATHSEL_SLOTS; i++) {
    if (pathsel_resend(&p->slot[i], now_ms, pto_ms)) {
      return &p->slot[i];
    }
  }
  return 0;
}
