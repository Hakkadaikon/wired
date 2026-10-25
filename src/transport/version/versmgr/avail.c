#include "transport/version/versmgr/avail.h"

#include "transport/version/version/version.h"

void vers_init(vers_set* s) { vers_init_mask(s, 0); }

/* 0 (an application that set nothing) selects every supported version. */
static u32 vers_mask_or_all(u32 mask) {
  return mask ? mask : WIRED_VERSIONS_V1 | WIRED_VERSIONS_V2;
}

void vers_init_mask(vers_set* s, u32 mask) {
  /* RFC 9368 5: preference order, most preferred first */
  static const u32 order[2] = {VERSION_2, VERSION_1};
  static const u32 bit[2]   = {WIRED_VERSIONS_V2, WIRED_VERSIONS_V1};
  u32              m        = vers_mask_or_all(mask);
  s->n                      = 0;
  for (usz i = 0; i < 2; i++) {
    if (m & bit[i]) {
      s->versions[s->n++] = order[i];
    }
  }
}

static int in_list(const u32* list, usz n, u32 v) {
  for (usz i = 0; i < n; i++) {
    if (list[i] == v) {
      return 1;
    }
  }
  return 0;
}

int vers_supports(const vers_set* s, u32 version) {
  return in_list(s->versions, s->n, version);
}

int vers_choose_compatible(
    const vers_set* s, verlist peer_versions, u32* chosen) {
  for (usz i = 0; i < s->n; i++) {
    if (in_list(peer_versions.list, peer_versions.n, s->versions[i])) {
      *chosen = s->versions[i];
      return 1;
    }
  }
  return 0;
}
