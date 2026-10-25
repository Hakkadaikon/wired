#ifndef SALPN_RAW_IMPL_H
#define SALPN_RAW_IMPL_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/tls/alpn_match.h"

/* Helpers shared by salpn_raw.c (client order) and salpn_raw_server.c
 * (server order): the space-separated raw_list tokenizer and the
 * ProtocolNameList framing (RFC 7301 3.1). */

static inline const char* salpn_raw_str(const char* list) {
  return list ? list : "";
}

static inline int salpn_raw_is_tok_byte(char c) { return c != ' ' && c != 0; }

/* Bytes of the space-delimited token starting at p. */
static inline usz salpn_raw_tok_len(const char* p) {
  usz n = 0;
  while (salpn_raw_is_tok_byte(p[n])) {
    n++;
  }
  return n;
}

/* The token at p is exactly nm (RFC 7301 3.1: opaque, case-sensitive). */
static inline int salpn_raw_tok_is(const char* p, wired_span nm) {
  usz n = salpn_raw_tok_len(p);
  return n != 0 && tls_alpn_equal(wired_span_of((const u8*)p, n), nm);
}

/* Past the token at p and one separator (p at a space: past that space). */
static inline const char* salpn_raw_next(const char* p) {
  usz n = salpn_raw_tok_len(p);
  return p + n + (p[n] == ' ');
}

/* ProtocolNameList end offset, or 0 if len is short or list_len overruns. */
static inline usz salpn_raw_list_end(const u8* m, usz len) {
  usz end;
  if (len < 2) {
    return 0;
  }
  end = 2 + ((usz)m[0] << 8 | m[1]);
  return end <= len ? end : 0;
}

/* Walk state over one ProtocolNameList. */
typedef struct {
  const u8*   m;
  usz         end;
  usz         p;
  const char* raw;
  wired_span  nm; /* the entry last classified */
} salpn_raw_walk;

#endif
