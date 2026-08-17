#include "transport/version/version/vneg.h"

void vneg_init(vneg* v, const u32* supported, usz n) {
  v->phase       = VNEG_INITIAL;
  v->negotiated  = 0;
  v->reacted     = 0;
  v->n_supported = n;
  for (usz i = 0; i < n; i++) v->supported[i] = supported[i];
}

/* Linear membership over a version list. */
static int list_has(const u32* list, usz n, u32 version) {
  for (usz i = 0; i < n; i++)
    if (list[i] == version) return 1;
  return 0;
}

int vneg_supports(const vneg* v, u32 version) {
  return list_has(v->supported, v->n_supported, version);
}

/* The version_information passes the downgrade checks: Chosen equals the
 * version in use, Available is non-empty, and Chosen is in Available. */
static int downgrade_ok(const version_info* vi, u32 in_use) {
  if (vi->chosen != in_use || vi->n_available == 0) return 0;
  return list_has(vi->available, vi->n_available, vi->chosen);
}

int vneg_check_downgrade(vneg* v, const version_info* vi, u32 in_use) {
  if (downgrade_ok(vi, in_use)) return 1;
  v->phase = VNEG_ERROR;
  return 0;
}

/* A version qualifies if it is one we support and is not our original. */
static int qualifies(const vneg* v, u32 original, u32 ver) {
  return ver != original && vneg_supports(v, ver);
}

/* Choose the first qualifying offered version. Returns 1 with *chosen set. */
static int pick_mutual(const vneg* v, const vn_packet* pkt, u32* chosen) {
  for (usz i = 0; i < pkt->offered.n; i++)
    if (qualifies(v, pkt->original, pkt->offered.list[i])) {
      *chosen = pkt->offered.list[i];
      return 1;
    }
  return 0;
}

/* We may react to a VN only if we have not reacted before and it does not
 * list our original version (RFC 9368 4). */
static int may_react(const vneg* v, const vn_packet* pkt) {
  return !v->reacted &&
         !list_has(pkt->offered.list, pkt->offered.n, pkt->original);
}

int vneg_react(vneg* v, const vn_packet* pkt, u32* chosen) {
  if (!may_react(v, pkt)) return 0;
  if (!pick_mutual(v, pkt, chosen)) return 0;
  v->reacted = 1;
  v->phase   = VNEG_REACTED;
  return 1;
}

void vneg_confirm(vneg* v, u32 version) {
  if (v->phase == VNEG_ERROR) return; /* errors do not confirm */
  v->phase      = VNEG_CONFIRMED;
  v->negotiated = version;
}
