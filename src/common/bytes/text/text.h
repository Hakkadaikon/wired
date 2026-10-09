#ifndef WIRED_TEXT_H
#define WIRED_TEXT_H

#include "common/bytes/span/span.h"
#include "common/bytes/util/bytes.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Small text helpers for application code: compare a byte view with a C
 * string, copy a view out as a C string, and dump a view as hex or as
 * text. They replace the per-program `span_is` / `log_hex` / `log_span`
 * helpers samples used to carry. */

/** printf arguments for a "%.*s" conversion of the view s, e.g.
 * `wired_dprintf(2, "path %.*s\n", WIRED_SPAN_ARG(path))`. */
#define WIRED_SPAN_ARG(s) (int)(s).n, (const char*)(s).p

/**
 * View of a NUL-terminated string's bytes (the NUL excluded).
 * @param s NUL-terminated string; must outlive the view
 * @return view of s
 */
static inline wired_span wired_span_cstr(const char* s) {
  return wired_span_of((const u8*)s, wired_cstr_len(s));
}

/**
 * Whether s holds exactly the bytes of the NUL-terminated lit.
 * @param s   byte view (e.g. a request path or a track name)
 * @param lit NUL-terminated string
 * @return 1 if equal, 0 otherwise
 */
int wired_span_eq_cstr(wired_span s, const char* lit);

/**
 * Whether a and b hold the same bytes (same length, same content).
 * Not constant-time; use the ct helpers for secrets.
 * @param a first view
 * @param b second view
 * @return 1 if equal, 0 otherwise
 */
int wired_span_eq(wired_span a, wired_span b);

/**
 * Index of the first byte c in s.
 * @param s view to search
 * @param c byte to find
 * @return its index, or -1 if s does not contain c
 */
ssz wired_span_find(wired_span s, u8 c);

/**
 * Copy s into out as a NUL-terminated string, truncated to cap - 1 bytes.
 * @param out destination (untouched when cap is 0)
 * @param cap capacity of out including the NUL
 * @param s   bytes to copy
 * @return bytes copied, excluding the NUL
 */
usz wired_span_to_cstr(char* out, usz cap, wired_span s);

/**
 * Lowercase hex of s into out, NUL-terminated; stops at the last whole
 * byte that fits in cap - 1 characters.
 * @param out destination (untouched when cap is 0)
 * @param cap capacity of out including the NUL
 * @param s   bytes to encode
 * @return characters written, excluding the NUL
 */
usz wired_hex_encode(char* out, usz cap, wired_span s);

/**
 * Write s to fd as lowercase hex, no separators and no newline.
 * @param fd file descriptor (2 = stderr)
 * @param s  bytes to dump
 */
void wired_dump_hex(i64 fd, wired_span s);

/**
 * Write the bytes of s to fd as they are (a text view needs no NUL).
 * @param fd file descriptor (2 = stderr)
 * @param s  bytes to write
 */
void wired_dump_text(i64 fd, wired_span s);

/**
 * Whether two NUL-terminated strings are equal.
 * @param a first string
 * @param b second string
 * @return 1 if equal, 0 otherwise
 */
int wired_cstr_eq(const char* a, const char* b);

/**
 * Append s to the C string in dst at offset at, keeping dst NUL-terminated
 * and cutting at cap - 1 bytes.
 * @param dst destination buffer (cap bytes; untouched when cap is 0)
 * @param cap capacity of dst including the NUL
 * @param at  current length of the string in dst; at >= cap appends
 *            nothing and returns at
 * @param s   bytes to append (wired_span_cstr for a C string)
 * @return the new length
 */
usz wired_cstr_append(char* dst, usz cap, usz at, wired_span s);

/**
 * s without one leading byte c, or s itself when it does not start with c
 * (e.g. a request path without its leading '/').
 * @param s view
 * @param c byte to drop
 * @return the possibly shortened view
 */
wired_span wired_span_strip_lead(wired_span s, u8 c);

/**
 * Append the bytes of s to b at b->len, cut at b->cap (no NUL is written).
 * @param b buffer to append to
 * @param s bytes to append
 * @return bytes appended
 */
usz wired_obuf_put(wired_obuf* b, wired_span s);

#endif
