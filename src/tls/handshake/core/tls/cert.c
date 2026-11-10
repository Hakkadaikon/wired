#include "tls/handshake/core/tls/cert.h"

/* TLS uses fixed big-endian length prefixes. A small cursor reads them and
 * bounds every access against the message end. */
typedef struct {
  const u8* b;
  usz       n;
  usz       off;
} cur;

/* Read a k-byte (1..3) big-endian length into *v. Returns 1 if it fits. */
static int take_len(cur* c, usz k, u32* v) {
  if (c->off + k > c->n) {
    return 0;
  }
  *v = 0;
  for (usz i = 0; i < k; i++) {
    *v = (*v << 8) | c->b[c->off + i];
  }
  c->off += k;
  return 1;
}

/* Take a view of len bytes at the cursor. Returns 1 if it fits. */
static int take_view(cur* c, u32 len, const u8** out) {
  if (c->off + len > c->n) {
    return 0;
  }
  *out = c->b + c->off;
  c->off += len;
  return 1;
}

/* Read a k-byte length then that many bytes as a view. */
static int take_vec(cur* c, usz k, wired_span* out) {
  u32       len;
  const u8* p;
  if (!take_len(c, k, &len)) {
    return 0;
  }
  if (!take_view(c, len, &p)) {
    return 0;
  }
  *out = wired_span_of(p, len);
  return 1;
}

/* The end-entity entry: cert_data (3-byte length) then its extensions
 * (2-byte length), within the certificate_list. */
static int take_entry(cur* c, tls_cert_entry* first) {
  wired_span cert, ext;
  if (!take_vec(c, 3, &cert)) {
    return 0;
  }
  if (!take_vec(c, 2, &ext)) {
    return 0;
  }
  first->cert_data = cert.p;
  first->cert_len  = (u32)cert.n;
  first->ext_len   = (u32)ext.n;
  return 1;
}

/* One more entry into out->entries[*out->count], bounded by out->cap (fail
 * closed on overflow). */
static int take_next(cur* lc, const tls_cert_chain_out* out) {
  if (*out->count >= out->cap) {
    return 0;
  }
  if (!take_entry(lc, &out->entries[*out->count])) {
    return 0;
  }
  (*out->count)++;
  return 1;
}

/* Every entry of the certificate_list, leaf first. */
static int entries_loop(cur* lc, const tls_cert_chain_out* out) {
  while (lc->off < lc->n) {
    if (!take_next(lc, out)) {
      return 0;
    }
  }
  return 1;
}

/* The context and certificate_list vectors, and nothing after them
 * (RFC 8446 6.2: trailing bytes are a malformed message). */
static int cert_take_list(cur* c, wired_span* context, wired_span* list) {
  if (!take_vec(c, 1, context)) {
    return 0;
  }
  if (!take_vec(c, 3, list)) {
    return 0;
  }
  return c->off == c->n;
}

int tls_cert_parse(wired_span buf, wired_span* context, tls_cert_entry* first) {
  cur        c = {buf.p, buf.n, 0};
  wired_span list;
  cur        lc;
  if (!cert_take_list(&c, context, &list)) {
    return 0;
  }
  lc = (cur){list.p, list.n, 0};
  return take_entry(&lc, first); /* first entry is the end-entity cert */
}

int tls_cert_chain(
    wired_span buf, wired_span* context, const tls_cert_chain_out* out) {
  cur        c = {buf.p, buf.n, 0};
  wired_span list;
  cur        lc;
  *out->count = 0;
  if (!cert_take_list(&c, context, &list)) {
    return 0;
  }
  lc = (cur){list.p, list.n, 0};
  return entries_loop(&lc, out);
}

int tls_certverify_parse(wired_span buf, u16* scheme, wired_span* sig) {
  cur c = {buf.p, buf.n, 0};
  u32 s;
  if (!take_len(&c, 2, &s)) {
    return 0;
  }
  if (!take_vec(&c, 2, sig)) {
    return 0;
  }
  *scheme = (u16)s;
  return 1;
}
