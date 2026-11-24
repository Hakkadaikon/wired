#include "app/nostr/event/nostrev.h"

#include "nostrev_fixtures.h"
#include "test.h"

/* NIP-01 event parser, canonical serialisation and verification. */

#define NV_HEX64 \
  "0000000000000000000000000000000000000000000000000000000000000000"

static u8  nv_buf[NOSTREV_MAX_JSON + 16];
static u8  nv_json[NOSTREV_MAX_JSON + 64];
static usz nv_len;

/* JSON fragments of one event; a 0 field takes the default. */
typedef struct {
  const char *created, *kind, *tags, *content, *extra, *id;
} nv_parts;

static const char* nv_or(const char* v, const char* d) { return v ? v : d; }

static void nv_build(const nv_parts* p) {
  nv_len = (usz)snprintf(
      (char*)nv_json, sizeof(nv_json),
      "{\"id\":%s,\"pubkey\":\"%s\",\"created_at\":%s,\"kind\":%s,"
      "\"tags\":%s,\"content\":%s,\"sig\":\"%s%s\"%s}",
      nv_or(p->id, "\"" NV_HEX64 "\""), NV_HEX64, nv_or(p->created, "1"),
      nv_or(p->kind, "1"), nv_or(p->tags, "[]"), nv_or(p->content, "\"\""),
      NV_HEX64, NV_HEX64, nv_or(p->extra, ""));
}

static int nv_parse_raw(nostrev* ev, const char* json, usz n) {
  return nostrev_parse(ev, (const u8*)json, n, nv_buf, sizeof(nv_buf));
}

static int nv_parse(nostrev* ev, const nv_parts* p) {
  nv_build(p);
  return nostrev_parse(ev, nv_json, nv_len, nv_buf, sizeof(nv_buf));
}

static int nv_content_is(const nostrev* ev, const char* want, usz n) {
  return ev->content.len == n &&
         bytes_span_eq(
             wired_span_of(ev->buf + ev->content.off, n),
             wired_span_of((const u8*)want, n));
}

static nostrev nv_ev;

/* Equivalence classes of the fixed keys: the nostr-tools event parses with
 * every field in place, in its own key order. */
static void test_nostrev_parse_fixture(void) {
  nostrev* ev = &nv_ev;
  CHECK(nv_parse_raw(ev, nostrev_fx_e1, sizeof(nostrev_fx_e1) - 1));
  CHECK(ev->kind == 1 && ev->created_at == 1700000000ULL);
  CHECK(ev->pubkey[0] == 0x5c && ev->pubkey[31] == 0xbc);
  CHECK(ev->id[0] == 0x9c && ev->sig[0] == 0xc4 && ev->sig[63] == 0xaf);
  CHECK(ev->ntags == 3 && ev->nelems == 7);
  CHECK(ev->tag[0].n == 3 && ev->tag[2].first == 5);
  CHECK(ev->elem[6].len == 6); /* "日本" as 6 UTF-8 bytes */
  CHECK(ev->unknown_keys == 0);
}

/* Key set: duplicates and missing keys fail; unknown keys of every value
 * kind are skipped and counted; a malformed ignored value still fails. */
static void test_nostrev_keys(void) {
  nostrev* ev = &nv_ev;
  CHECK(!nv_parse(ev, &(nv_parts){.extra = ",\"kind\":1"}));
  CHECK(!nv_parse_raw(ev, "{\"kind\":1}", 10));
  CHECK(nv_parse(
      ev, &(nv_parts){
              .extra = ",\"x\":[1,{\"a\":[true,false,"
                       "null,\"s\"]},[]],\"y\":{}"}));
  CHECK(ev->unknown_keys == 2);
  CHECK(!nv_parse(ev, &(nv_parts){.extra = ",\"x\":1.5"}));
  CHECK(!nv_parse(ev, &(nv_parts){.extra = ",\"x\":nul"}));
  CHECK(!nv_parse(ev, &(nv_parts){.extra = ",\"x\":[1,]"}));
  CHECK(nv_parse(ev, &(nv_parts){.extra = ",\"x\":[[[[[[[[0]]]]]]]]"}));
  CHECK(!nv_parse(ev, &(nv_parts){.extra = ",\"x\":[[[[[[[[[0]]]]]]]]]"}));
  /* a key spelled with an escape is the same key */
  CHECK(!nv_parse(ev, &(nv_parts){.extra = ",\"\\u006bind\":1"}));
}

/* Integer boundaries: 0, 19 digits, kind 65535 pass; leading zero, sign,
 * fraction, exponent, 20 digits, kind 65536, a string fail. */
static void test_nostrev_integers(void) {
  nostrev*          ev    = &nv_ev;
  const char* const ok[]  = {"0", "1234567890123456789"};
  const char* const bad[] = {
      "01", "-1", "1.0", "1e3", "12345678901234567890", "\"1\"", "+1", ""};
  for (usz i = 0; i < 2; i++) {
    CHECK(nv_parse(ev, &(nv_parts){.created = ok[i]}));
  }
  CHECK(ev->created_at == 1234567890123456789ULL);
  for (usz i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    CHECK(!nv_parse(ev, &(nv_parts){.created = bad[i]}));
  }
  CHECK(nv_parse(ev, &(nv_parts){.kind = "65535"}));
  CHECK(!nv_parse(ev, &(nv_parts){.kind = "65536"}));
}

/* Hex fields: lowercase and exact length only. */
static void test_nostrev_hex(void) {
  nostrev* ev = &nv_ev;
  CHECK(!nv_parse(ev, &(nv_parts){.id = "\"" NV_HEX64 "0\""}));
  CHECK(!nv_parse(
      ev, &(nv_parts){
              .id = "\"0000000000000000000000000000000"
                    "00000000000000000000000000000000\""}));
  CHECK(!nv_parse(
      ev, &(nv_parts){
              .id = "\"000000000000000000000000000000"
                    "000000000000000000000000000000000A\""}));
  CHECK(!nv_parse(
      ev, &(nv_parts){
              .id = "\"000000000000000000000000000000"
                    "000000000000000000000000000000000g\""}));
  CHECK(!nv_parse(ev, &(nv_parts){.id = "1"}));
  CHECK(nv_parse(
      ev, &(nv_parts){
              .id = "\"000000000000000000000000000000"
                    "000000000000000000000000000000000f\""}));
  CHECK(ev->id[31] == 0x0f);
}

/* String decoding: every simple escape, \u in BMP, a surrogate pair. */
static void test_nostrev_escapes(void) {
  nostrev* ev = &nv_ev;
  CHECK(nv_parse(
      ev, &(nv_parts){
              .content = "\"\\\"\\\\\\/\\b\\f\\n\\r\\t\\u00e9"
                         "\\uD83D\\uDE00\\u0000\""}));
  /* 8 simple escapes, U+00E9 (2 bytes), U+1F600 (4), \u0000 -> NUL */
  CHECK(nv_content_is(ev, "\"\\/\b\f\n\r\t\xc3\xa9\xf0\x9f\x98\x80\0", 15));
}

/* Rejected strings: lone / reversed surrogates, bad escapes, raw control
 * bytes, ill-formed UTF-8 (overlong, surrogate, > U+10FFFF, truncated). */
static void test_nostrev_bad_strings(void) {
  nostrev*          ev    = &nv_ev;
  const char* const bad[] = {
      "\"\\uD83D\"",
      "\"\\uDE00\"",
      "\"\\uD83D\\u0041\"",
      "\"\\uD83Dx\"",
      "\"\\x\"",
      "\"\\u00g0\"",
      "\"\\u00\"",
      "\"a\001b\"",
      "\"a\tb\"",
      "\"\xc0\x80\"",
      "\"\xed\xa0\x80\"",
      "\"\xf4\x90\x80\x80\"",
      "\"\xf5\x80\x80\x80\"",
      "\"\xe2\x82\"",
      "\"\x80\"",
      "\"abc",
      "\"\\",
  };
  for (usz i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    CHECK(!nv_parse(ev, &(nv_parts){.content = bad[i]}));
  }
  CHECK(nv_parse(
      ev, &(nv_parts){
              .content = "\"\xf4\x8f\xbf\xbf\xe2\x82\xac"
                         "\xed\x9f\xbf\x7f\""}));
}

/* nostrev_tag_value: string k of the first tag of that name; empty when
 * the tag is absent or too short. */
static void test_nostrev_tag_value(void) {
  nostrev* ev = &nv_ev;
  CHECK(nv_parse_raw(ev, nostrev_fx_e1, sizeof(nostrev_fx_e1) - 1));
  CHECK(wired_span_eq_cstr(nostrev_tag_value(ev, "e", 2), "wss://r.example/"));
  CHECK(wired_span_eq_cstr(nostrev_tag_value(ev, "p", 1), "x"));
  CHECK(wired_span_eq_cstr(nostrev_tag_value(ev, "p", 0), "p"));
  CHECK(nostrev_tag_value(ev, "p", 2).p == 0);
  CHECK(nostrev_tag_value(ev, "q", 1).p == 0);
}

/* Tags: shape and caps (64 tags, 16 strings per tag, 4096 bytes). */
static void test_nostrev_tags(void) {
  nostrev*    ev = &nv_ev;
  static char t[NOSTREV_MAX_JSON];
  usz         n = 0;
  CHECK(!nv_parse(ev, &(nv_parts){.tags = "[[]]"}));
  CHECK(!nv_parse(ev, &(nv_parts){.tags = "[[1]]"}));
  CHECK(!nv_parse(ev, &(nv_parts){.tags = "[\"a\"]"}));
  CHECK(!nv_parse(ev, &(nv_parts){.tags = "{}"}));
  CHECK(nv_parse(ev, &(nv_parts){.tags = " [ [ \"a\" , \"b\" ] ] "}));
  t[n++] = '[';
  for (usz i = 0; i < 64; i++) {
    n += (usz)snprintf(t + n, sizeof(t) - n, "%s[\"a\"]", i ? "," : "");
  }
  t[n++] = ']';
  t[n]   = 0;
  CHECK(nv_parse(ev, &(nv_parts){.tags = t}));
  CHECK(ev->ntags == 64);
  t[n - 1] = ',';
  snprintf(t + n, sizeof(t) - n, "[\"a\"]]");
  CHECK(!nv_parse(ev, &(nv_parts){.tags = t}));
  n = (usz)snprintf(t, sizeof(t), "[[\"a\"");
  for (usz i = 1; i < 16; i++) {
    n += (usz)snprintf(t + n, sizeof(t) - n, ",\"a\"");
  }
  snprintf(t + n, sizeof(t) - n, "]]");
  CHECK(nv_parse(ev, &(nv_parts){.tags = t}));
  snprintf(t + n, sizeof(t) - n, ",\"a\"]]");
  CHECK(!nv_parse(ev, &(nv_parts){.tags = t}));
  n = (usz)snprintf(t, sizeof(t), "[[\"");
  for (usz i = 0; i < NOSTREV_MAX_TAG_STR; i++) {
    t[n++] = 'a';
  }
  snprintf(t + n, sizeof(t) - n, "\"]]");
  CHECK(nv_parse(ev, &(nv_parts){.tags = t}));
  snprintf(t + n, sizeof(t) - n, "a\"]]");
  CHECK(!nv_parse(ev, &(nv_parts){.tags = t}));
}

/* All-tag string cap: 16 tags x 16 strings = 256 = NOSTREV_MAX_ELEMS
 * pass; one more string (a 17th tag) fails. */
static void test_nostrev_max_elems(void) {
  nostrev*    ev = &nv_ev;
  static char t[8192];
  usz         n = 0;
  t[n++]        = '[';
  for (usz i = 0; i < 16; i++) {
    n += (usz)snprintf(t + n, sizeof(t) - n, "%s[\"a\"", i ? "," : "");
    for (usz k = 1; k < 16; k++) {
      n += (usz)snprintf(t + n, sizeof(t) - n, ",\"a\"");
    }
    t[n++] = ']';
  }
  snprintf(t + n, sizeof(t) - n, "]");
  CHECK(nv_parse(ev, &(nv_parts){.tags = t}));
  CHECK(ev->nelems == NOSTREV_MAX_ELEMS && ev->ntags == 16);
  snprintf(t + n, sizeof(t) - n, ",[\"a\"]]");
  CHECK(!nv_parse(ev, &(nv_parts){.tags = t}));
}

/* Framing: whitespace around tokens, trailing garbage, size cap, a too
 * small decode buffer. */
static void test_nostrev_framing(void) {
  nostrev* ev = &nv_ev;
  usz      n  = sizeof(nostrev_fx_e1) - 1;
  CHECK(!nv_parse_raw(ev, "{\"id\":\"\"} x", 11));
  nv_build(&(nv_parts){0});
  nv_json[nv_len] = ' ';
  CHECK(nostrev_parse(ev, nv_json, nv_len + 1, nv_buf, sizeof(nv_buf)));
  nv_json[nv_len] = 'x';
  CHECK(!nostrev_parse(ev, nv_json, nv_len + 1, nv_buf, sizeof(nv_buf)));
  CHECK(!nostrev_parse(ev, (const u8*)nostrev_fx_e1, n, nv_buf, 40));
  CHECK(!nostrev_parse(
      ev, nv_json, NOSTREV_MAX_JSON + 1, nv_buf, sizeof(nv_buf)));
  CHECK(!nv_parse_raw(ev, "", 0));
  CHECK(!nv_parse_raw(ev, "[]", 2));
}

typedef struct {
  u8  b[512];
  usz n;
} nv_out;

static void nv_put(void* ctx, const u8* p, usz n) {
  nv_out* o = ctx;
  for (usz i = 0; i < n && o->n < sizeof(o->b); i++) {
    o->b[o->n++] = p[i];
  }
}

/* Canonical form equals nostr-tools' serializeEvent byte for byte (all
 * seven escapes, '/' and non-ASCII verbatim, DEL verbatim). */
static void test_nostrev_serialize(void) {
  nostrev*     ev = &nv_ev;
  nv_out       o  = {.n = 0};
  nostrev_sink s  = {nv_put, &o};
  CHECK(nv_parse_raw(ev, nostrev_fx_e1, sizeof(nostrev_fx_e1) - 1));
  CHECK(nostrev_serialize(ev, &s));
  CHECK(o.n == sizeof(nostrev_fx_e1_ser) - 1);
  CHECK(bytes_span_eq(
      wired_span_of(o.b, o.n),
      wired_span_of((const u8*)nostrev_fx_e1_ser, o.n)));
}

/* Other C0 controls (\u0000, \u001f, \u000b) fail closed, in content and
 * in a tag; the canonical form of an empty event is exact. */
static void test_nostrev_serialize_c0(void) {
  nostrev*          ev      = &nv_ev;
  nv_out            o       = {.n = 0};
  nostrev_sink      s       = {nv_put, &o};
  const char* const c0[]    = {"\"\\u0000\"", "\"\\u001f\"", "\"\\u000b\""};
  static const char empty[] = "[0,\"" NV_HEX64 "\",1,1,[],\"\"]";
  for (usz i = 0; i < 3; i++) {
    CHECK(nv_parse(ev, &(nv_parts){.content = c0[i]}));
    CHECK(!nostrev_serialize(ev, &s));
  }
  CHECK(nv_parse(ev, &(nv_parts){.tags = "[[\"a\\u0001\"]]"}));
  CHECK(!nostrev_serialize(ev, &s));
  CHECK(nv_parse(ev, &(nv_parts){0}));
  o.n = 0;
  CHECK(nostrev_serialize(ev, &s));
  CHECK(o.n == sizeof(empty) - 1);
  CHECK(bytes_span_eq(
      wired_span_of(o.b, o.n), wired_span_of((const u8*)empty, o.n)));
}

/* Full verification of the nostr-tools event; a changed content breaks the
 * id, a changed sig byte breaks only the signature. */
static void test_nostrev_verify(void) {
  nostrev*    ev = &nv_ev;
  static char j[sizeof(nostrev_fx_e1)];
  usz         n = sizeof(nostrev_fx_e1) - 1;
  CHECK(nv_parse_raw(ev, nostrev_fx_e1, n));
  CHECK(nostrev_verify(ev) == NOSTREV_OK);
  bytes_memcpy(j, nostrev_fx_e1, sizeof(j));
  for (usz i = 0; i + 5 < n; i++) {
    if (bytes_span_eq(
            wired_span_of((const u8*)j + i, 5),
            wired_span_of((const u8*)"hello", 5))) {
      j[i] = 'H';
    }
  }
  CHECK(nv_parse_raw(ev, j, n));
  CHECK(nostrev_verify(ev) == NOSTREV_BAD_ID);
  CHECK(nv_parse_raw(ev, nostrev_fx_e1, n));
  ev->sig[10] ^= 1;
  CHECK(nostrev_verify(ev) == NOSTREV_BAD_SIG);
  CHECK(nv_parse(ev, &(nv_parts){.content = "\"\\u0001\""}));
  CHECK(nostrev_verify(ev) == NOSTREV_BAD_ID);
}

void test_nostrev(void) {
  test_nostrev_parse_fixture();
  test_nostrev_keys();
  test_nostrev_integers();
  test_nostrev_hex();
  test_nostrev_escapes();
  test_nostrev_bad_strings();
  test_nostrev_tags();
  test_nostrev_tag_value();
  test_nostrev_max_elems();
  test_nostrev_framing();
  test_nostrev_serialize();
  test_nostrev_serialize_c0();
  test_nostrev_verify();
}
