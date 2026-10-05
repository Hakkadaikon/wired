#include "app/moqt/ver/moqver.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"

/* @file
 * The one table backing moqver_find/moqver_caps/wired_moqt_wt_protocols: row
 * order is the order of the server's subprotocol list. It is not a
 * preference: srvrun_wt_select picks the first member of the CLIENT's
 * wt-available-protocols offer that the list contains
 * (draft-ietf-webtrans-http3 3.4), so the client's order decides. */

typedef struct {
  int         ver;
  const char* tok;
  u32         caps;
} moqver_row;

static const moqver_row moqver_table[MOQVER_COUNT] = {
    {MOQVER_D22, "moqt-22",
     MOQVER_CAP_LOCFILTER_TYPED | MOQVER_CAP_FETCH_BODY_V22 |
         MOQVER_CAP_FILL_FETCH | MOQVER_CAP_PUBLISH_STATE_NOTIFY |
         MOQVER_CAP_FETCH_END_INCLUSIVE | MOQVER_CAP_RANGE_FILTERS |
         MOQVER_CAP_MAX_REQUEST_UPDATES | MOQVER_CAP_NS_PREFIX_MATCH |
         MOQVER_CAP_EOR_TIMED_OUT},
    {MOQVER_D19, "moqt-19",
     MOQVER_CAP_RANGE_FILTERS | MOQVER_CAP_MAX_REQUEST_UPDATES |
         MOQVER_CAP_SUBSCRIPTION_ENDED},
    {MOQVER_D18, "moqt-18",
     MOQVER_CAP_GOAWAY_REQID | MOQVER_CAP_DUP_SUBSCRIPTION |
         MOQVER_CAP_FIN_CANCEL_NS | MOQVER_CAP_PUBLISH_OK_ALIAS |
         MOQVER_CAP_SUBSCRIPTION_ENDED},
};

static int moqver_tok_eq(wired_span token, const char* tok) {
  usz n = wired_cstr_len(tok);
  if (token.n != n) return 0;
  return ct_diffn(token.p, (const u8*)tok, n) == 0;
}

static int moqver_find_row(wired_span token) {
  for (int i = 0; i < MOQVER_COUNT; i++)
    if (moqver_tok_eq(token, moqver_table[i].tok)) return moqver_table[i].ver;
  return -1;
}

int moqver_find(wired_span token) {
  if (token.n == 0) return MOQVER_D19;
  return moqver_find_row(token);
}

static int moqver_valid(int ver) { return ver >= 0 && ver < MOQVER_COUNT; }

u32 moqver_caps(int ver) {
  return moqver_valid(ver) ? moqver_table[ver].caps : 0;
}

static usz moqver_offer_len(void) {
  usz off = 0;
  for (int i = 0; i < MOQVER_COUNT; i++)
    off += wired_cstr_len(moqver_table[i].tok) + (i > 0 ? 1 : 0);
  return off;
}

static void moqver_offer_write(char* out) {
  usz off = 0;
  for (int i = 0; i < MOQVER_COUNT; i++) {
    if (i > 0) out[off++] = ' ';
    usz tn = wired_cstr_len(moqver_table[i].tok);
    bytes_memcpy(out + off, moqver_table[i].tok, tn);
    off += tn;
  }
  out[off] = 0;
}

usz wired_moqt_wt_protocols(char* out, usz cap) {
  usz len = moqver_offer_len();
  if (len + 1 > cap) return 0;
  moqver_offer_write(out);
  return len;
}
