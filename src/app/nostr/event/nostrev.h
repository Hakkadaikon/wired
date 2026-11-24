#ifndef APP_NOSTR_EVENT_NOSTREV_H
#define APP_NOSTR_EVENT_NOSTREV_H

/* NIP-01 event: a strict JSON subset parser, the canonical serialisation
 * the event id is the SHA-256 of, and full verification (id + BIP-340).
 *
 * Accepted subset (anything else is rejected): one JSON object holding each
 * of id, pubkey, created_at, kind, tags, content, sig exactly once, in any
 * order; duplicate keys rejected. Other keys are allowed by JSON and are not
 * part of the id: their values are validated and skipped, and counted in
 * unknown_keys (ignore-but-flag). Numbers are non-negative integers only
 * (no sign, fraction, exponent or leading zero, at most 19 digits). id,
 * pubkey and sig are lowercase hex of exactly 64/64/128 digits. Strings
 * decode \" \\ \/ \b \f \n \r \t and \uXXXX (surrogate pairs combined; a
 * lone surrogate is rejected); raw bytes must be valid UTF-8 (RFC 3629) and
 * not a control character < 0x20. */

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

#define NOSTREV_MAX_JSON 65536   /* whole event, bytes */
#define NOSTREV_MAX_TAGS 64      /* tags per event */
#define NOSTREV_MAX_TAG_ELEMS 16 /* strings per tag */
#define NOSTREV_MAX_ELEMS 256    /* strings over all tags */
#define NOSTREV_MAX_TAG_STR 4096 /* one decoded tag string, bytes */
#define NOSTREV_MAX_DEPTH 8      /* nesting of an ignored key's value */

/* A decoded string: [off, off + len) of the parse buffer. */
typedef struct {
  u32 off, len;
} nostrev_str;

/* One tag: elem[first .. first + n). */
typedef struct {
  u16 first, n;
} nostrev_tag;

/* views: buf=caller */
typedef struct {
  u8          id[32], pubkey[32], sig[64];
  u64         created_at, kind;
  nostrev_str content;
  nostrev_tag tag[NOSTREV_MAX_TAGS];
  nostrev_str elem[NOSTREV_MAX_ELEMS];
  u32         ntags, nelems;
  u32         unknown_keys; /* ignored keys (not covered by the id) */
  const u8*   buf;          /* decoded strings (the caller's buffer) */
} nostrev;

/* Parse json[0..len) into ev, decoding strings into buf[0..cap) (decoded
 * text is never longer than the JSON, so cap >= len always suffices).
 * 1 on success; 0 on any deviation from the subset or a cap. */
int nostrev_parse(nostrev* ev, const u8* json, usz len, u8* buf, usz cap);

/* String k of ev's first tag named name (k = 0 is the name itself), a view
 * into ev->buf; empty with p 0 when no such tag has k + 1 strings. */
wired_span nostrev_tag_value(const nostrev* ev, const char* name, u32 k);

/* Byte sink for the canonical serialisation. */
typedef struct {
  void (*put)(void* ctx, const u8* p, usz n);
  void* ctx;
} nostrev_sink;

/* NIP-01 serialisation [0,"<pubkey>",<created_at>,<kind>,<tags>,
 * "<content>"] without whitespace, escaping exactly \n \" \\ \r \t \b \f
 * and writing every other byte verbatim. 0 (fail closed) when a string
 * holds any other control byte < 0x20, whose canonical form differs
 * between implementations. */
int nostrev_serialize(const nostrev* ev, const nostrev_sink* out);

/* SHA-256 of the canonical serialisation; 0 as nostrev_serialize. */
int nostrev_compute_id(const nostrev* ev, u8 id[32]);

/* Result of nostrev_verify. */
typedef enum {
  NOSTREV_OK = 0,
  NOSTREV_BAD_ID,  /* id != SHA-256 of the canonical form (or no form) */
  NOSTREV_BAD_SIG, /* BIP-340 signature of id under pubkey fails */
} nostrev_verdict;

/* id check, then BIP-340 verification of sig over the 32-byte id. */
nostrev_verdict nostrev_verify(const nostrev* ev);

#endif
