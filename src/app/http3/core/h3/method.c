#include "app/http3/core/h3/method.h"

/* One registered method name plus whether this server allows it through to
 * the application handler -- a flat table keeps both quic_h3_method_is_known
 * and quic_h3_method_is_allowed at a single scan with no nested branching. */
typedef struct {
  const char* name;
  usz         len;
  int         allowed;
} h3method_entry;

#define H3METHOD_ENTRY(s, allowed) {s, sizeof(s) - 1, allowed}

/* RFC 9110 9.1's registered methods plus PATCH (RFC 5789). allowed=1 marks
 * quic_h3_method_is_allowed's server-wide allow set (see method.h's doc for
 * why TRACE/CONNECT are recognized but not allowed). */
static const h3method_entry H3METHOD_TABLE[] = {
    H3METHOD_ENTRY("GET", 1),    H3METHOD_ENTRY("HEAD", 1),
    H3METHOD_ENTRY("POST", 1),   H3METHOD_ENTRY("PUT", 1),
    H3METHOD_ENTRY("DELETE", 1), H3METHOD_ENTRY("OPTIONS", 1),
    H3METHOD_ENTRY("PATCH", 1),  H3METHOD_ENTRY("CONNECT", 1),
    H3METHOD_ENTRY("TRACE", 0),
};
#define H3METHOD_TABLE_N (sizeof(H3METHOD_TABLE) / sizeof(H3METHOD_TABLE[0]))

/* All len octets of a equal b (method tokens are case-sensitive, RFC 9110
 * 9.1). */
static int h3method_bytes_eq(const u8* a, const char* b, usz len) {
  for (usz i = 0; i < len; i++)
    if (a[i] != (u8)b[i]) return 0;
  return 1;
}

static int h3method_matches(quic_span method, const h3method_entry* e) {
  return method.n == e->len && h3method_bytes_eq(method.p, e->name, e->len);
}

static const h3method_entry* h3method_find(quic_span method) {
  for (usz i = 0; i < H3METHOD_TABLE_N; i++)
    if (h3method_matches(method, &H3METHOD_TABLE[i])) return &H3METHOD_TABLE[i];
  return 0;
}

int quic_h3_method_is_known(quic_span method) {
  return h3method_find(method) != 0;
}

int quic_h3_method_is_allowed(quic_span method) {
  const h3method_entry* e = h3method_find(method);
  return e != 0 && e->allowed;
}
