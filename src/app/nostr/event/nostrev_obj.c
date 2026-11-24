#include "app/nostr/event/nostrev_impl.h"

static int nostrev_hex_bytes(const u8* hex, u8* dst, usz nb);
static int nostrev_val_hex(nostrev_lx* lx, u8* dst, usz nb);
static int nostrev_val_id(nostrev_lx* lx);
static int nostrev_val_pubkey(nostrev_lx* lx);
static int nostrev_val_sig(nostrev_lx* lx);
static int nostrev_val_created(nostrev_lx* lx);
static int nostrev_val_kind(nostrev_lx* lx);
static int nostrev_val_content(nostrev_lx* lx);
static int nostrev_key_index(const u8* k, usz n);
static int nostrev_unknown(nostrev_lx* lx);
static int nostrev_key_value(nostrev_lx* lx, int idx);
static int nostrev_member(nostrev_lx* lx);
static int nostrev_body(nostrev_lx* lx);
static int nostrev_end(nostrev_lx* lx);

#define NOSTREV_KEYS 7
#define NOSTREV_ALL ((1u << NOSTREV_KEYS) - 1)

/* NIP-01: the seven event fields and their value parsers. */
static const struct {
  const char*  name;
  usz          len;
  nostrev_item fn;
} nostrev_keys[NOSTREV_KEYS] = {
    {"id", 2, nostrev_val_id},
    {"pubkey", 6, nostrev_val_pubkey},
    {"created_at", 10, nostrev_val_created},
    {"kind", 4, nostrev_val_kind},
    {"tags", 4, nostrev_tags},
    {"content", 7, nostrev_val_content},
    {"sig", 3, nostrev_val_sig},
};

/* Lowercase hex only (NIP-01: "lowercase hex-encoded"). */
static int nostrev_hex_bytes(const u8* hex, u8* dst, usz nb) {
  int ok = 1;
  for (usz k = 0; k < nb; k++) {
    int hi = nostrev_hexval(hex[2 * k], 0),
        lo = nostrev_hexval(hex[2 * k + 1], 0);
    ok &= (hi >= 0) & (lo >= 0);
    dst[k] = (u8)((hi & 15) << 4 | (lo & 15));
  }
  return ok;
}

static int nostrev_val_hex(nostrev_lx* lx, u8* dst, usz nb) {
  nostrev_str s;
  usz         mark = lx->olen;
  int         ok   = nostrev_lex_str(lx, &s) && s.len == nb * 2 &&
                     nostrev_hex_bytes(lx->out + s.off, dst, nb);
  lx->olen         = mark;
  return ok;
}

static int nostrev_val_id(nostrev_lx* lx) {
  return nostrev_val_hex(lx, lx->ev->id, 32);
}

static int nostrev_val_pubkey(nostrev_lx* lx) {
  return nostrev_val_hex(lx, lx->ev->pubkey, 32);
}

static int nostrev_val_sig(nostrev_lx* lx) {
  return nostrev_val_hex(lx, lx->ev->sig, 64);
}

static int nostrev_val_created(nostrev_lx* lx) {
  return nostrev_lex_uint(lx, &lx->ev->created_at);
}

/* NIP-01: kind is an integer between 0 and 65535. */
static int nostrev_val_kind(nostrev_lx* lx) {
  return nostrev_lex_uint(lx, &lx->ev->kind) && lx->ev->kind <= 65535;
}

static int nostrev_val_content(nostrev_lx* lx) {
  return nostrev_lex_str(lx, &lx->ev->content);
}

static int nostrev_key_index(const u8* k, usz n) {
  for (int i = 0; i < NOSTREV_KEYS; i++) {
    if (bytes_span_eq(
            wired_span_of(k, n),
            wired_span_of(
                (const u8*)nostrev_keys[i].name, nostrev_keys[i].len))) {
      return i;
    }
  }
  return -1;
}

static int nostrev_unknown(nostrev_lx* lx) {
  lx->ev->unknown_keys++;
  return nostrev_skip(lx);
}

static int nostrev_key_value(nostrev_lx* lx, int idx) {
  u32 bit;
  if (idx < 0) {
    return nostrev_unknown(lx);
  }
  bit = 1u << idx;
  if (lx->seen & bit) {
    return 0; /* duplicate key */
  }
  lx->seen |= bit;
  return nostrev_keys[idx].fn(lx);
}

/* The key is compared after decoding (so "id" is "id"), then its
 * bytes are dropped from the buffer. */
static int nostrev_member(nostrev_lx* lx) {
  nostrev_str k;
  usz         mark = lx->olen;
  int         idx;
  if (!nostrev_lex_str(lx, &k) || !nostrev_colon(lx)) {
    return 0;
  }
  idx      = nostrev_key_index(lx->out + k.off, k.len);
  lx->olen = mark;
  return nostrev_key_value(lx, idx);
}

static int nostrev_body(nostrev_lx* lx) {
  nostrev_ws(lx);
  return nostrev_take(lx) == '{' && nostrev_list(lx, '}', nostrev_member);
}

/* Only trailing whitespace after the object, and every key seen. */
static int nostrev_end(nostrev_lx* lx) {
  nostrev_ws(lx);
  return lx->i == lx->n && lx->seen == NOSTREV_ALL;
}

int nostrev_parse(nostrev* ev, const u8* json, usz len, u8* buf, usz cap) {
  nostrev_lx lx = {.s = json, .n = len, .out = buf, .cap = cap, .ev = ev};
  bytes_memset(ev, 0, sizeof(*ev));
  ev->buf = buf;
  if (len > NOSTREV_MAX_JSON || !nostrev_body(&lx)) {
    return 0;
  }
  return nostrev_end(&lx);
}
