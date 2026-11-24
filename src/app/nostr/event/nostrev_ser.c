#include "app/nostr/event/nostrev_impl.h"
#include "common/bytes/text/text.h"
#include "common/bytes/util/ct.h"
#include "common/platform/debug/debug.h"
#include "crypto/asymmetric/ecc/bip340/bip340.h"
#include "crypto/symmetric/hash/hash/sha256.h"

/* Writer: the sink plus a sticky ok bit (0 after a forbidden byte). */
typedef struct {
  const nostrev_sink* o;
  int                 ok;
} nostrev_w;

static void nostrev_w_raw(nostrev_w* w, const void* p, usz n);
static u8   nostrev_esc_char(u8 b);
static void nostrev_w_byte(nostrev_w* w, u8 b);
static void nostrev_w_str(nostrev_w* w, const nostrev* ev, nostrev_str s);
static void nostrev_w_u64(nostrev_w* w, u64 v);
static void nostrev_w_tag(nostrev_w* w, const nostrev* ev, usz i);
static void nostrev_sha_put(void* ctx, const u8* p, usz n);
static int  nostrev_id_ok(const nostrev* ev);

static void nostrev_w_raw(nostrev_w* w, const void* p, usz n) {
  w->o->put(w->o->ctx, (const u8*)p, n);
}

/* NIP-01: the only escapes in the serialisation. */
static u8 nostrev_esc_char(u8 b) {
  static const u8 map[7][2] = {
      {0x0a, 'n'}, {'"', '"'},  {'\\', '\\'}, {0x0d, 'r'},
      {0x09, 't'}, {0x08, 'b'}, {0x0c, 'f'},
  };
  for (usz k = 0; k < 7; k++) {
    if (map[k][0] == b) {
      return map[k][1];
    }
  }
  return 0;
}

static void nostrev_w_byte(nostrev_w* w, u8 b) {
  u8 two[2] = {'\\', nostrev_esc_char(b)};
  if (two[1]) {
    nostrev_w_raw(w, two, 2);
    return;
  }
  w->ok &= b >= 0x20; /* other C0 controls: no single canonical form */
  nostrev_w_raw(w, &b, 1);
}

static void nostrev_w_str(nostrev_w* w, const nostrev* ev, nostrev_str s) {
  nostrev_w_raw(w, "\"", 1);
  for (u32 k = 0; k < s.len; k++) {
    nostrev_w_byte(w, ev->buf[s.off + k]);
  }
  nostrev_w_raw(w, "\"", 1);
}

static void nostrev_w_u64(nostrev_w* w, u64 v) {
  char d[20];
  usz  at = 0;
  wired_fmt_u64(d, &at, &(wired_fmt_u64_in){.v = v, .width = 1});
  nostrev_w_raw(w, d, at);
}

static void nostrev_w_tag(nostrev_w* w, const nostrev* ev, usz i) {
  const nostrev_tag* t = &ev->tag[i];
  nostrev_w_raw(w, ",", i > 0); /* "," only between tags */
  nostrev_w_raw(w, "[", 1);
  for (u16 k = 0; k < t->n; k++) {
    nostrev_w_raw(w, ",", k > 0);
    nostrev_w_str(w, ev, ev->elem[t->first + k]);
  }
  nostrev_w_raw(w, "]", 1);
}

int nostrev_serialize(const nostrev* ev, const nostrev_sink* out) {
  nostrev_w w = {out, 1};
  char      pk[65];
  wired_hex_encode(pk, sizeof(pk), wired_span_of(ev->pubkey, 32));
  nostrev_w_raw(&w, "[0,\"", 4);
  nostrev_w_raw(&w, pk, 64);
  nostrev_w_raw(&w, "\",", 2);
  nostrev_w_u64(&w, ev->created_at);
  nostrev_w_raw(&w, ",", 1);
  nostrev_w_u64(&w, ev->kind);
  nostrev_w_raw(&w, ",[", 2);
  for (usz i = 0; i < ev->ntags; i++) {
    nostrev_w_tag(&w, ev, i);
  }
  nostrev_w_raw(&w, "],", 2);
  nostrev_w_str(&w, ev, ev->content);
  nostrev_w_raw(&w, "]", 1);
  return w.ok;
}

static void nostrev_sha_put(void* ctx, const u8* p, usz n) {
  sha256_update((sha256_ctx*)ctx, p, n);
}

int nostrev_compute_id(const nostrev* ev, u8 id[32]) {
  sha256_ctx   s;
  nostrev_sink sink = {nostrev_sha_put, &s};
  int          ok;
  sha256_init(&s);
  ok = nostrev_serialize(ev, &sink);
  sha256_final(&s, id);
  return ok;
}

/* NIP-01: id = sha256(serialisation); sig = BIP-340 over the id bytes. */
static int nostrev_id_ok(const nostrev* ev) {
  u8 id[32];
  return nostrev_compute_id(ev, id) && ct_diff32(id, ev->id) == 0;
}

nostrev_verdict nostrev_verify(const nostrev* ev) {
  if (!nostrev_id_ok(ev)) {
    return NOSTREV_BAD_ID;
  }
  if (!bip340_verify(ev->pubkey, ev->id, 32, ev->sig)) {
    return NOSTREV_BAD_SIG;
  }
  return NOSTREV_OK;
}
