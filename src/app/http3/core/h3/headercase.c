#include "app/http3/core/h3/headercase.h"

/* RFC 9114 4.3. 1 if c is an uppercase ASCII letter A-Z. */
static int upper(u8 c) { return c >= 'A' && c <= 'Z'; }

int h3_header_name_ok(const u8* name, usz len) {
  for (usz i = 0; i < len; i++) {
    if (upper(name[i])) {
      return 0;
    }
  }
  return 1;
}

/* RFC 9110 5.6.2 tchar as a 128-bit set ("!#$%&'*+-.^_`|~", DIGIT, ALPHA):
 * bit (c & 31) of word c >> 5. Excludes SP, ':', CTLs and every non-ASCII
 * octet. */
static const u32 hc_tchar_set[4] = {
    0x00000000u, 0x03ff6cfau, 0xc7fffffeu, 0x57ffffffu};

static int hc_tchar(u8 c) {
  return c < 128 && (hc_tchar_set[c >> 5] >> (c & 31)) & 1u;
}

int h3_header_token_ok(const u8* name, usz len) {
  for (usz i = 0; i < len; i++) {
    if (!hc_tchar(name[i])) {
      return 0;
    }
  }
  return len != 0;
}

/* RFC 9110 5.5: field-vchar (VCHAR / obs-text), SP or HTAB -- every octet
 * but the controls other than HTAB, and DEL. */
static int hc_value_octet(u8 c) {
  return (c >= 0x20 && c != 0x7f) || c == 0x09;
}

int h3_header_value_ok(const u8* value, usz len) {
  for (usz i = 0; i < len; i++) {
    if (!hc_value_octet(value[i])) {
      return 0;
    }
  }
  return 1;
}

/* RFC 9114 10.3 / RFC 9110 5.5. 1 if c is CR, LF or NUL. */
static int forbidden(u8 c) { return c == 0x0d || c == 0x0a || c == 0x00; }

int h3_header_bytes_ok(const u8* buf, usz len) {
  for (usz i = 0; i < len; i++) {
    if (forbidden(buf[i])) {
      return 0;
    }
  }
  return 1;
}

/* Length of a NUL-terminated literal (headercase-local; see naming-and-
 * unity-build.md -- kept static so a shared util helper isn't forced by a
 * single extra caller). */
static usz hc_cstr_len(const char* s) {
  usz i = 0;
  while (s[i]) {
    i++;
  }
  return i;
}

/* 1 if a (alen bytes) is exactly the NUL-terminated literal b, given b's
 * precomputed length blen. Accumulates a byte diff over the shorter length
 * (like h3_header_bytes_ok above) so the length check stays a single
 * trailing comparison instead of an early-return branch. */
static int hc_bytes_eq(const u8* a, usz alen, const char* b, usz blen) {
  usz shorter = alen < blen ? alen : blen;
  u8  diff    = (u8)(alen != blen);
  for (usz i = 0; i < shorter; i++) {
    diff |= a[i] ^ (u8)b[i];
  }
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

int h3_header_name_forbidden(const u8* name, usz len) {
  for (usz i = 0; i < FORBIDDEN_NAMES_N; i++) {
    if (hc_str_eq(name, len, forbidden_names[i])) {
      return 1;
    }
  }
  return 0;
}

int h3_header_te_ok(const u8* value, usz len) {
  return hc_str_eq(value, len, "trailers");
}
