#include "transport/conn/cid/peercid/peercid_impl.h"

static int peercid_checked(const peercid_entry* e);
static int peercid_resets(const peercid_entry* e, const u8* dg, usz len);

/* RFC 9000 10.3.1: e's token is checked only while e is in use and was sent
 * with (bound) -- never for an unused or retired ID. */
static int peercid_checked(const peercid_entry* e) {
  return e->in_use && e->bound && e->has_token;
}

static int peercid_resets(const peercid_entry* e, const u8* dg, usz len) {
  return peercid_checked(e) && sresetdrive_is_reset(dg, len, e->token);
}

int peercid_reset_match(const peercid* p, const u8* dg, usz len) {
  int hit = 0;
  for (usz i = 0; i < PEERCID_CAP; i++) {
    hit |= peercid_resets(&p->e[i], dg, len);
  }
  return hit;
}
