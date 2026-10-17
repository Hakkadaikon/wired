#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_path_in_use(
    const srvrun_cfg* cfg, const srvrun_conn* c, const pathsel_key* k);
static void srvrun_path_valid(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k);
static int srvrun_path_strands(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    const pathsel_key* k,
    int                target);
static void srvrun_path_failed(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k);
static u64 srvrun_path_pto_ms(const srvrun_conn* c);
static u64 srvrun_path_abandon_ms(const srvrun_conn* c);

/* RFC 9000 8.2.3/9.3: k validated. The target or the send path becomes the
 * path to revert to, and a gated target becomes the send path (9.6.2). */
static int srvrun_path_in_use(
    const srvrun_cfg* cfg, const srvrun_conn* c, const pathsel_key* k) {
  pathsel_key t = srvrun_target_key(cfg, c), s = srvrun_send_key(cfg, c);
  return pathsel_key_eq(k, &t) || pathsel_key_eq(k, &s);
}

static void srvrun_path_valid(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k) {
  if (!srvrun_path_in_use(cfg, c, k)) {
    return;
  }

  c->path.last_valid = *k;
  if (!srvrun_path_is_gated_target(c, k)) {
    return;
  }
  c->path.gated = 0;
  srvrun_path_move(cfg, c, k);
}

/* RFC 9000 8.2.2: a matching PATH_RESPONSE, whatever path it arrived on,
 * validates its slot's path; mismatching data is ignored. Consumes the
 * step's latch. */
void srvrun_apply_path_response(const srvrun_cfg* cfg, srvrun_conn* c) {
  pathsel_key k;
  if (!c->l.path_response_seen_flag) {
    return;
  }
  c->l.path_response_seen_flag = 0;
  if (pathsel_match(&c->path, c->l.path_response_data, &k)) {
    srvrun_path_valid(cfg, c, &k);
  }
}

/* A failure of k moves the send path back: k is the gated target or the
 * send path itself. */
static int srvrun_path_strands(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    const pathsel_key* k,
    int                target) {
  pathsel_key s = srvrun_send_key(cfg, c);
  return target || pathsel_key_eq(k, &s);
}

/* RFC 9000 9.3.2: k's validation failed. A gated target reverts, and the
 * send path returns to the last validated path with its peer ID; any other
 * path just lost its slot. */
static void srvrun_path_failed(
    const srvrun_cfg* cfg, srvrun_conn* c, const pathsel_key* k) {
  int target = srvrun_path_is_gated_target(c, k);
  if (target) {
    c->path.gated = 0;
  }
  if (srvrun_path_strands(cfg, c, k, target)) {
    srvrun_path_move(cfg, c, &c->path.last_valid);
  }
}

/* RFC 9000 8.2.4: the larger of the current PTO and the PTO a new path
 * starts with (kInitialRtt). */
static u64 srvrun_path_pto_ms(const srvrun_conn* c) {
  rtt     r;
  pto_rtt init;
  rtt_init(&r);
  init = (pto_rtt){r.smoothed_rtt, r.rttvar};
  return u64_max(
      srvrun_pto_deadline_ms(c, 0),
      pto_duration(init, SRVRUN_MAX_ACK_DELAY_US, 0) / 1000);
}

/* RFC 9000 8.2.4: three times srvrun_path_pto_ms. */
static u64 srvrun_path_abandon_ms(const srvrun_conn* c) {
  return 3 * srvrun_path_pto_ms(c);
}

void srvrun_path_expire(const srvrun_cfg* cfg, srvrun_conn* c, u64 now) {
  pathsel_key k;
  while (pathsel_expire(&c->path, now, srvrun_path_abandon_ms(c), &k)) {
    srvrun_path_failed(cfg, c, &k);
  }
}

/* RFC 9000 9.4: resend an unanswered challenge one PTO (floored like the
 * abandon timer) after it went out, doubling per try (RFC 9002 6.2.1), in
 * the same slot with fresh data; the previous data still matches. */
void srvrun_path_resend(const srvrun_cfg* cfg, srvrun_conn* c, u64 now) {
  pathsel_slot* s = pathsel_resend_due(&c->path, now, srvrun_path_pto_ms(c));
  if (!s) {
    return;
  }
  s->tries++;
  srvrun_path_challenge(cfg, c, s, now);
}
