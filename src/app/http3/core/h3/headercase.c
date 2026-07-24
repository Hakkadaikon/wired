#include "app/http3/core/h3/headercase.h"

/* RFC 9114 4.3. 1 if c is an uppercase ASCII letter A-Z. */
static int upper(u8 c) { return c >= 'A' && c <= 'Z'; }

int quic_h3_header_name_ok(const u8* name, usz len) {
  for (usz i = 0; i < len; i++)
    if (upper(name[i])) return 0;
  return 1;
}

/* RFC 9114 10.3 / RFC 9110 5.5. 1 if c is CR, LF or NUL. */
static int forbidden(u8 c) { return c == 0x0d || c == 0x0a || c == 0x00; }

int quic_h3_header_bytes_ok(const u8* buf, usz len) {
  for (usz i = 0; i < len; i++)
    if (forbidden(buf[i])) return 0;
  return 1;
}

/* Length of a NUL-terminated literal (headercase-local; see naming-and-
 * unity-build.md -- kept static so a shared util helper isn't forced by a
 * single extra caller). */
static usz hc_cstr_len(const char* s) {
  usz i = 0;
  while (s[i]) i++;
  return i;
}

/* 1 if a (alen bytes) is exactly the NUL-terminated literal b, given b's
 * precomputed length blen. Accumulates a byte diff over the shorter length
 * (like quic_h3_header_bytes_ok above) so the length check stays a single
 * trailing comparison instead of an early-return branch. */
static int hc_bytes_eq(const u8* a, usz alen, const char* b, usz blen) {
  usz shorter = alen < blen ? alen : blen;
  u8  diff    = (u8)(alen != blen);
  for (usz i = 0; i < shorter; i++) diff |= a[i] ^ (u8)b[i];
  return diff == 0;
}

/* 1 if a (alen bytes) is exactly the NUL-terminated literal b. */
static int hc_str_eq(const u8* a, usz alen, const char* b) {
  return hc_bytes_eq(a, alen, b, hc_cstr_len(b));
}

/* RFC 9114 4.1 (Transfer-Encoding has no meaning in HTTP/3) and 4.2
 * (connection-specific fields carried over from HTTP/1.1). */
static const char* const forbidden_names[] = {
    "transfer-encoding", "connection", "keep-alive",
    "proxy-connection",  "upgrade",
};
#define FORBIDDEN_NAMES_N (sizeof(forbidden_names) / sizeof(forbidden_names[0]))

int quic_h3_header_name_forbidden(const u8* name, usz len) {
  for (usz i = 0; i < FORBIDDEN_NAMES_N; i++)
    if (hc_str_eq(name, len, forbidden_names[i])) return 1;
  return 0;
}

int quic_h3_header_te_ok(const u8* value, usz len) {
  return hc_str_eq(value, len, "trailers");
}
