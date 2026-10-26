#include "app/moqt/run/moqtrun_impl.h"

static u8   moqtrun_track_prop_prio(wired_span props);
static void moqtrun_track_keep_props(wired_moqtrun_track* t, wired_span props);
static void moqtrun_refuse_or_close(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 code);
static int moqtrun_token_by_value(const moqctl_token* t);
static u32 moqtrun_token_close_code(const moqctl_token* t);
static int moqtrun_publish_slot_ok(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    wired_moqtrun_track*  t,
    const moqctl_publish* m);

static u8 moqtrun_track_prop_prio(wired_span props) {
  u64 v = moqtrun_tprop(props, MOQTRUN_PROP_DEFAULT_PUB_PRIO, 128);
  return v > 255 ? 128 : (u8)v;
}

/* Opens a track incarnation on slot t for k under the publisher's Track
 * Alias: its Largest seeded from params' LARGEST_OBJECT (10.2.16), its
 * SUBGROUP_DELIVERY_TIMEOUT (12.6) and DEFAULT_PUBLISHER_PRIORITY (12.4)
 * from props, rid the request (a
 * PUBLISH's, or the hub's own upstream SUBSCRIBE's) that claims it. */
/* Keeps props to forward (moqtrun_tprops_refused already refused a block
 * past WIRED_MOQTRUN_TRACK_PROPS_MAX). */
static void moqtrun_track_keep_props(wired_moqtrun_track* t, wired_span props) {
  bytes_memcpy(t->props, props.p, props.n);
  t->props_len = (u8)props.n;
}

void moqtrun_track_open(
    wired_moqt_hub*      hub,
    wired_moqtrun_track* t,
    moqtrun_key          k,
    u64                  alias,
    const moqctl_params* params,
    wired_span           props,
    u64                  rid) {
  moqtrun_track_claim(hub, t, k, alias);
  moqtrun_track_seed_largest(t, params);
  t->request_id = rid;
  t->subgroup_timeout_ms =
      moqtrun_tprop(props, MOQCTL_PARAM_SUBGROUP_DELIVERY_TIMEOUT, 0);
  t->default_pub_prio = moqtrun_track_prop_prio(props);
  t->max_cache_ms     = moqtrun_tprop(props, MOQTRUN_PROP_MAX_CACHE, ~(u64)0);
  t->up_streams       = 0;
  t->pubdone_pending  = 0;
  moqtrun_track_keep_props(t, props);
}

/* REQUEST_ERROR code, or for MOQTRUN_REQ_CLOSE (draft-18 12.5/12.6) a
 * PROTOCOL_VIOLATION close. */
static void moqtrun_refuse_or_close(
    wired_moqt_hub* hub, wired_moqtrun_peer* p, u64 code) {
  if (code == MOQTRUN_REQ_CLOSE) {
    moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
    return;
  }
  moqtrun_send_request_error(p, code);
}

/* draft-19 11.1 (draft-18 11.1, draft-22 3.1.3): alias, carried by a
 * PUBLISH or SUBSCRIBE_OK for slot t, already names a different live
 * track of p -- "it MUST close the session with error
 * DUPLICATE_TRACK_ALIAS"; 1 when it closed. t itself (a re-PUBLISH of
 * the same name) is the same track. */
int moqtrun_alias_dup_close(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    wired_moqtrun_track* t,
    u64                  alias) {
  wired_moqtrun_track* o = moqtrun_track_by_alias(p, alias);
  if (!o || o == t) {
    return 0;
  }
  moqtrun_close_with(hub, p, WIRED_MOQTRUN_CLOSE_DUPLICATE_TRACK_ALIAS);
  return 1;
}

/* 1 when slot t may take m: a slot exists (else REQUEST_ERROR) and m's
 * Track Alias is no other track's (else the session closed). */
static int moqtrun_publish_slot_ok(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    wired_moqtrun_track*  t,
    const moqctl_publish* m) {
  if (!t) {
    moqtrun_send_request_error(p, MOQCTL_ERR_NOT_SUPPORTED);
    return 0;
  }
  return !moqtrun_alias_dup_close(hub, p, t, m->track_alias);
}

/* A vetted PUBLISH: claim a track into a free (or matching-name) slot
 * and reply REQUEST_OK; a third distinct track name (no free slot), or a
 * name a newer session already owns (moqtrun_publish_slot), gets
 * REQUEST_ERROR instead of silently overwriting an existing track. */
void moqtrun_publish_checked(
    wired_moqt_hub*       hub,
    wired_moqtrun_peer*   p,
    usz                   peer_idx,
    const moqctl_publish* m) {
  u8  ns_buf[WIRED_MOQTRUN_MAX_NS];
  u64 code;
  if (moqtrun_publish_refused(hub, m, &code)) {
    moqtrun_refuse_or_close(hub, p, code);
    return;
  }
  moqtrun_key          k = moqtrun_key_of(&m->name, ns_buf);
  wired_moqtrun_track* t = moqtrun_publish_slot(hub, p, peer_idx, k);
  if (!moqtrun_publish_slot_ok(hub, p, t, m)) {
    return;
  }
  moqtrun_supersede_name(hub, peer_idx, k);
  moqtrun_track_open(
      hub, t, k, m->track_alias, &m->params, m->track_properties,
      m->request_id);
  moqtrun_reattach_subs(hub, t, peer_idx, k);
  moqtrun_rdv_resolve(hub, t, k);
  moqtrun_queue_request_ok(p, 0);
  moqtrun_req_mark_live(p);
}

/* draft-19 10.2 (draft-18 10.2, draft-22 9.20): a request body that fails
 * to decode -- a Message Parameter the session's draft does not define
 * among the causes -- closes the session PROTOCOL_VIOLATION, as FETCH and
 * REQUEST_UPDATE do (ledger 12-13); a known parameter whose Value does not
 * match its encoding (an undecodable AUTHORIZATION TOKEN, say) closes it
 * KEY_VALUE_FORMATTING_ERROR instead (draft-19 1.4.3, 10.2.2), as SETUP
 * does (moqtrun_setup_take_code). 1 when r is MOQCTL_OK. */
int moqtrun_take_or_close(wired_moqt_hub* hub, wired_moqtrun_peer* p, int r) {
  if (r == MOQCTL_OK) {
    return 1;
  }
  moqtrun_close_with(
      hub, p,
      r == MOQCTL_PARAMS_KVFMT ? (u32)MOQCTL_CLOSE_KVFMT_ERROR
                               : WIRED_MOQTRUN_CLOSE_PROTOCOL_VIOLATION);
  return 0;
}

/* First AUTHORIZATION TOKEN parameter (draft SS10.2.2) of a message, or
 * 0 when it carries none. */
const moqctl_token* moqtrun_auth_token_of(const moqctl_params* params) {
  const moqctl_param* t =
      moqctl_params_find(params, MOQCTL_PARAM_AUTHORIZATION_TOKEN);
  return t ? &t->token : 0;
}

/* This hub never advertises MAX_AUTH_TOKEN_CACHE_SIZE, so its token cache
 * is 0 bytes and no Alias is ever registered (draft-22 8.9): a REGISTER
 * overflows the cache, DELETE / USE_ALIAS name an unknown Alias. Both
 * close the session; only USE_VALUE passes. */
static int moqtrun_token_by_value(const moqctl_token* t) {
  return !t || t->alias_type == MOQCTL_TOKEN_USE_VALUE;
}

static u32 moqtrun_token_close_code(const moqctl_token* t) {
  if (moqtrun_token_by_value(t)) {
    return 0;
  }
  return t->alias_type == MOQCTL_TOKEN_REGISTER
             ? WIRED_MOQTRUN_CLOSE_AUTH_TOKEN_CACHE_OVERFLOW
             : WIRED_MOQTRUN_CLOSE_UNKNOWN_AUTH_TOKEN_ALIAS;
}

/* moqtrun_take_or_close, then the decoded params' Token Alias check
 * (moqtrun_token_close_code). 1 when the message may proceed. */
int moqtrun_take_tok_or_close(
    wired_moqt_hub*      hub,
    wired_moqtrun_peer*  p,
    int                  r,
    const moqctl_params* params) {
  u32 code;
  if (!moqtrun_take_or_close(hub, p, r)) {
    return 0;
  }
  code = moqtrun_token_close_code(moqtrun_auth_token_of(params));
  if (code) {
    moqtrun_close_with(hub, p, code);
  }
  return code == 0;
}
