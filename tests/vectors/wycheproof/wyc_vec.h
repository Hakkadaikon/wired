#ifndef WYC_VEC_H
#define WYC_VEC_H

/* Read-side helpers for the Wycheproof vectors converted by
 * scripts/gen_wycheproof_vectors.py. Values are decoded with the BoringSSL
 * vector helpers (bssl_bytes: hex), so every expected value comes from the
 * Wycheproof JSON, never from wired. Group fields carry a "g." prefix. */

#include "vectors/boringssl/bssl_vec.h"

#define WYC_VALID 0
#define WYC_INVALID 1
#define WYC_ACCEPTABLE 2

typedef struct {
  u32         tc_id;  /**< Wycheproof tcId */
  u8          result; /**< WYC_VALID / WYC_INVALID / WYC_ACCEPTABLE */
  const char* flags;  /**< comma-separated Wycheproof flags */
  u32         off;    /**< index of its first attribute */
  u32         n;      /**< attribute count */
} wyc_case;

/* Value of key in case c, or 0 when absent. */
static const char* wyc_get(
    const bssl_attr* attrs, const wyc_case* c, const char* key) {
  for (u32 i = 0; i < c->n; i++)
    if (bssl_streq(attrs[c->off + i].key, key)) return attrs[c->off + i].val;
  return 0;
}

/* 1 if flag appears in c's comma-separated flag list. */
static int wyc_has_flag(const wyc_case* c, const char* flag) {
  const char* p = c->flags;
  while (*p) {
    const char* q = flag;
    while (*q && *p == *q) p++, q++;
    if (!*q && (*p == ',' || !*p)) return 1;
    while (*p && *p != ',') p++;
    if (*p == ',') p++;
  }
  return 0;
}

#endif
