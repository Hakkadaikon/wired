#include "tls/ext/salpn/salpn_raw.h"

#include "tls/handshake/core/tls/alpn_match.h"

/* RFC 7301 3.1/3.2 widened to configured raw-QUIC ids (moqt-NN,
 * draft-ietf-moq-transport-22 6.2). Statics carry the salpn_raw_ prefix:
 * negotiate.c shares the unity TU. */

static const char* salpn_raw_str(const char* list) { return list ? list : ""; }

static int salpn_raw_is_tok_byte(char c) { return c != ' ' && c != 0; }

/* Bytes of the space-delimited token starting at p. */
static usz salpn_raw_tok_len(const char* p) {
  usz n = 0;
  while (salpn_raw_is_tok_byte(p[n])) {
    n++;
  }
  return n;
}

/* The token at p is exactly nm (RFC 7301 3.1: opaque, case-sensitive). */
static int salpn_raw_tok_is(const char* p, wired_span nm) {
  usz n = salpn_raw_tok_len(p);
  return n != 0 && tls_alpn_equal(wired_span_of((const u8*)p, n), nm);
}

/* Past the token at p and one separator (p at a space: past that space). */
static const char* salpn_raw_next(const char* p) {
  usz n = salpn_raw_tok_len(p);
  return p + n + (p[n] == ' ');
}

/* The list entry equal to nm, or 0. */
static const char* salpn_raw_find(const char* list, wired_span nm) {
  const char* p = salpn_raw_str(list);
  while (*p) {
    if (salpn_raw_tok_is(p, nm)) {
      return p;
    }
    p = salpn_raw_next(p);
  }
  return 0;
}

int salpn_raw_list_has(const char* list, const u8* name, usz name_len) {
  return salpn_raw_find(list, wired_span_of(name, name_len)) != 0;
}

/* One protocol class this server speaks: h3, hq-interop, configured raw. */
typedef int (*salpn_raw_match)(wired_span nm, const char* raw);

static int salpn_raw_m_h3(wired_span nm, const char* raw) {
  (void)raw;
  return tls_alpn_is_h3(nm.p, nm.n);
}

static int salpn_raw_m_hq(wired_span nm, const char* raw) {
  (void)raw;
  return tls_alpn_is_hq(nm.p, nm.n);
}

static int salpn_raw_m_raw(wired_span nm, const char* raw) {
  return salpn_raw_find(raw, nm) != 0;
}

static const struct {
  salpn_raw_match match;
  salpn_choice    choice;
} SALPN_RAW_CLASSES[] = {
    {salpn_raw_m_h3, SALPN_H3},
    {salpn_raw_m_hq, SALPN_HQ},
    {salpn_raw_m_raw, SALPN_RAW},
};

static salpn_choice salpn_raw_name_choice(wired_span nm, const char* raw) {
  for (usz i = 0; i < sizeof SALPN_RAW_CLASSES / sizeof *SALPN_RAW_CLASSES;
       i++) {
    if (SALPN_RAW_CLASSES[i].match(nm, raw)) {
      return SALPN_RAW_CLASSES[i].choice;
    }
  }
  return SALPN_NONE;
}

/* ProtocolNameList end offset, or 0 if len is short or list_len overruns. */
static usz salpn_raw_list_end(const u8* m, usz len) {
  usz end;
  if (len < 2) {
    return 0;
  }
  end = 2 + ((usz)m[0] << 8 | m[1]);
  return end <= len ? end : 0;
}

/* Client-order walk state over one ProtocolNameList. */
typedef struct {
  const u8*   m;
  usz         end;
  usz         p;
  const char* raw;
  wired_span  nm; /* the entry last classified */
} salpn_raw_walk;

/* Classify the entry at w->p and step past it; an entry overrunning the
 * list ends the walk (RFC 7301 3.1 framing). */
static salpn_choice salpn_raw_step(salpn_raw_walk* w) {
  usz n = w->m[w->p];
  if (w->p + 1 + n > w->end) {
    w->p = w->end;
    return SALPN_NONE;
  }
  w->nm = wired_span_of(w->m + w->p + 1, n);
  w->p += 1 + n;
  return salpn_raw_name_choice(w->nm, w->raw);
}

/* On SALPN_RAW, *tok views the configured entry (outlives the CH). */
static salpn_choice salpn_raw_finish(
    salpn_choice c, const salpn_raw_walk* w, wired_span* tok) {
  if (c == SALPN_RAW) {
    *tok = wired_span_of((const u8*)salpn_raw_find(w->raw, w->nm), w->nm.n);
  }
  return c;
}

salpn_choice salpn_raw_pick(
    const u8* alpn_ext_data, usz len, const char* raw_list, wired_span* tok) {
  salpn_raw_walk w = {
      alpn_ext_data,
      salpn_raw_list_end(alpn_ext_data, len),
      2,
      raw_list,
      {0, 0}};
  salpn_choice c = SALPN_NONE;
  while (c == SALPN_NONE && w.p < w.end) {
    c = salpn_raw_step(&w);
  }
  return salpn_raw_finish(c, &w, tok);
}

/* Entry at w->p is non-empty and inside the list (RFC 7301 3.1:
 * ProtocolName<1..2^8-1>). */
static int salpn_raw_entry_ok(const salpn_raw_walk* w) {
  usz n = w->m[w->p];
  return n != 0 && w->p + 1 + n <= w->end;
}

/* The whole ProtocolNameList parses: a list length that fits, then
 * non-empty entries filling it exactly. */
static int salpn_raw_list_ok(const u8* m, usz len) {
  salpn_raw_walk w  = {m, salpn_raw_list_end(m, len), 2, 0, {0, 0}};
  int            ok = w.end != 0;
  while (ok && w.p < w.end) {
    ok = salpn_raw_entry_ok(&w);
    w.p += 1 + (usz)m[w.p];
  }
  return ok;
}

/* The client's (well-formed) list offers exactly nm. */
static int salpn_raw_offered(const u8* m, usz len, wired_span nm) {
  usz end = salpn_raw_list_end(m, len);
  usz p   = 2;
  int hit = 0;
  while (!hit && p < end) {
    hit = tls_alpn_equal(wired_span_of(m + p + 1, m[p]), nm);
    p += 1 + (usz)m[p];
  }
  return hit;
}

/* The first raw_list entry, in raw_list's own order, the client offered;
 * SALPN_RAW with *tok viewing it, else SALPN_NONE. */
static salpn_choice salpn_raw_first_offered(
    const u8* m, usz len, const char* raw_list, wired_span* tok) {
  const char* p = salpn_raw_str(raw_list);
  while (*p) {
    wired_span nm = wired_span_of((const u8*)p, salpn_raw_tok_len(p));
    if (salpn_raw_offered(m, len, nm)) { /* an empty nm never matches */
      *tok = nm;
      return SALPN_RAW;
    }
    p = salpn_raw_next(p);
  }
  return SALPN_NONE;
}

/* After the raw ids: h3, then hq-interop. */
static salpn_choice salpn_raw_fixed_offered(const u8* m, usz len) {
  if (salpn_select_h3(m, len)) {
    return SALPN_H3;
  }
  return salpn_select_hq(m, len) ? SALPN_HQ : SALPN_NONE;
}

salpn_choice salpn_raw_pick_server(
    const u8* alpn_ext_data, usz len, const char* raw_list, wired_span* tok) {
  salpn_choice c;
  if (!salpn_raw_list_ok(alpn_ext_data, len)) {
    return SALPN_NONE;
  }
  c = salpn_raw_first_offered(alpn_ext_data, len, raw_list, tok);
  return c != SALPN_NONE ? c : salpn_raw_fixed_offered(alpn_ext_data, len);
}
