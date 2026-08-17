#include "app/http3/core/h3/pseudoheader.h"

/* The literal byte lit[i] is exhausted or differs from name[i]. */
static int byte_differs(const u8* name, const char* lit, usz i) {
  return lit[i] == 0 || name[i] != (u8)lit[i];
}

/* Compare a field name [name,len) against a NUL-terminated literal. */
static int name_eq(const u8* name, usz len, const char* lit) {
  usz i = 0;
  for (; i < len; i++)
    if (byte_differs(name, lit, i)) return 0;
  return lit[i] == 0; /* both ended together */
}

static const struct {
  const char* name;
  h3_ph_kind  kind;
} known[] = {
    {":method", H3_PH_METHOD},       {":scheme", H3_PH_SCHEME},
    {":authority", H3_PH_AUTHORITY}, {":path", H3_PH_PATH},
    {":protocol", H3_PH_PROTOCOL},   {":status", H3_PH_STATUS},
};

/* A field name is a pseudo-header iff it is non-empty and starts with ':'. */
static int is_pseudo(const u8* name, usz len) {
  return len != 0 && name[0] == (u8)':';
}

/* Match a ':'-prefixed name against the table; UNKNOWN if none. */
static h3_ph_kind pseudoheader_lookup(const u8* name, usz len) {
  for (usz i = 0; i < sizeof known / sizeof known[0]; i++)
    if (name_eq(name, len, known[i].name)) return known[i].kind;
  return H3_PH_UNKNOWN;
}

h3_ph_kind h3_ph_classify(const u8* name, usz len) {
  if (!is_pseudo(name, len)) return H3_PH_NONE;
  return pseudoheader_lookup(name, len);
}

void h3_ph_init(h3_ph_set* p) {
  p->seen        = 0;
  p->saw_regular = 0;
  p->ok          = 1;
}

/* Record a known pseudo-header; ordering and duplicates clear p->ok. */
static void on_pseudo(h3_ph_set* p, h3_ph_kind k) {
  u8 bit = (u8)(1u << k);
  if (p->saw_regular || (p->seen & bit)) p->ok = 0; /* after regular / dup */
  p->seen |= bit;
}

void h3_ph_field(h3_ph_set* p, const u8* name, usz len) {
  h3_ph_kind k = h3_ph_classify(name, len);
  if (k == H3_PH_NONE) {
    p->saw_regular = 1;
    return;
  }
  if (k == H3_PH_UNKNOWN) {
    p->ok = 0;
    return;
  }
  on_pseudo(p, k);
}

/* All of the bits in `req` are present in p->seen. */
static int has_all(const h3_ph_set* p, u8 req) {
  return (p->seen & req) == req;
}

#define BIT(k) ((u8)(1u << (k)))

int h3_ph_request_ok(const h3_ph_set* p) {
  u8 req = BIT(H3_PH_METHOD) | BIT(H3_PH_SCHEME) | BIT(H3_PH_PATH);
  return p->ok &&
         has_all(p, req); /* :authority is conditional (RFC 9114 4.3.1) */
}

int h3_ph_response_ok(const h3_ph_set* p) {
  return p->ok && has_all(p, BIT(H3_PH_STATUS));
}
