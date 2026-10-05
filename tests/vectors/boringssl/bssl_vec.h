#ifndef BSSL_VEC_H
#define BSSL_VEC_H

/* Read-side helpers for the BoringSSL FileTest vectors converted by
 * scripts/gen_bssl_vectors.py. A case is a run of attributes (instructions
 * such as "[curve = ...]" carry a leading '['); values stay as the vector
 * file's text and are decoded here, so every expected value comes from the
 * third-party file, never from wired. */

typedef struct {
  const char* key;
  const char* val;
} bssl_attr;

typedef struct {
  u32 line_first; /**< first line of the case in the source file */
  u32 line_last;  /**< last line of the case in the source file */
  u32 off;        /**< index of its first attribute */
  u32 n;          /**< attribute count */
} bssl_case;

static int bssl_streq(const char* a, const char* b) {
  while (*a && *a == *b) a++, b++;
  return *a == *b;
}

/* Value of key in case c, or 0 when absent. */
static const char* bssl_get(
    const bssl_attr* attrs, const bssl_case* c, const char* key) {
  for (u32 i = 0; i < c->n; i++)
    if (bssl_streq(attrs[c->off + i].key, key)) return attrs[c->off + i].val;
  return 0;
}

static int bssl_nib(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
  if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
  return -1;
}

static ssz bssl_hex(const char* v, u8* out, usz cap) {
  usz n = 0;
  for (; v[0] && v[1]; v += 2) {
    int hi = bssl_nib(v[0]), lo = bssl_nib(v[1]);
    if (hi < 0 || lo < 0 || n >= cap) return -1;
    out[n++] = (u8)(hi << 4 | lo);
  }
  return v[0] ? -1 : (ssz)n;
}

static ssz bssl_quoted(const char* v, u8* out, usz cap) {
  usz n = 0;
  for (v++; *v && *v != '"'; v++) {
    if (n >= cap) return -1;
    out[n++] = (u8)*v;
  }
  return (ssz)n;
}

/* Decode a value: hex, or a "quoted" byte string. -1 when it does not fit
 * or is malformed (the caller then fails the case, it never skips it). */
static ssz bssl_bytes(const char* v, u8* out, usz cap) {
  if (!v) return -1;
  return v[0] == '"' ? bssl_quoted(v, out, cap) : bssl_hex(v, out, cap);
}

#endif
