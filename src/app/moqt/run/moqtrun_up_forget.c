#include "app/moqt/run/moqtrun_impl.h"

static int moqtrun_up_failed_key(const wired_moqtrun_up* u, moqtrun_key k);
static int moqtrun_up_failed_on(
    const wired_moqtrun_up* u, const wired_wt_session* s);
static int moqtrun_up_failed_under(
    const wired_moqtrun_up* u, const wired_moqtrun_req* q);

/* u is a refusal record for k. */
static int moqtrun_up_failed_key(const wired_moqtrun_up* u, moqtrun_key k) {
  return u->failed && moqtrun_up_matches(u, k);
}

/* draft-23 7.7: a publisher that refused the hub's SUBSCRIBE is asked
 * again only on a new trigger -- a downstream SUBSCRIBE for the Track or
 * that publisher's PUBLISH_NAMESPACE covering it. Its refusal record is
 * forgotten here, never on a plain hub step (moqtrun_up_fan runs every
 * sync and would ask again without end). */
void moqtrun_up_forget_key(wired_moqt_hub* hub, moqtrun_key k) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (moqtrun_up_failed_key(&hub->ups[i], k)) {
      hub->ups[i].in_use = 0;
    }
  }
}

/* u is a refusal record toward s. */
static int moqtrun_up_failed_on(
    const wired_moqtrun_up* u, const wired_wt_session* s) {
  return u->in_use && u->failed && u->wt == s;
}

/* u is a refusal record of q's publisher for a Track under q's
 * namespace (Namespace Prefix Matching, 2.4.2). */
static int moqtrun_up_failed_under(
    const wired_moqtrun_up* u, const wired_moqtrun_req* q) {
  u64 n;
  return moqtrun_up_failed_on(u, q->wt) &&
         moqtrun_disc_starts(
             moqtrun_disc_fields(q, &n),
             moqtrun_disc_fields_of(wired_span_of(u->ns, u->ns_len), &n));
}

/* An accepted PUBLISH_NAMESPACE q forgets its publisher's refusals of the
 * Tracks it covers (moqtrun_up_forget_key's other trigger). */
void moqtrun_up_forget_under(wired_moqt_hub* hub, const wired_moqtrun_req* q) {
  for (usz i = 0; i < WIRED_MOQTRUN_MAX_UP; i++) {
    if (moqtrun_up_failed_under(&hub->ups[i], q)) {
      hub->ups[i].in_use = 0;
    }
  }
}
