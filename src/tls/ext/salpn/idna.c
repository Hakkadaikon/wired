#include "tls/ext/salpn/idna.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/num.h"
#include "tls/ext/salpn/idna_impl.h"
#include "tls/ext/salpn/punycode.h"

/* RFC 1035 2.3.4: a name is at most 255 octets, a label at most 63. */
#define IDNA_HOST_MAX 255
#define IDNA_LABEL_MAX 63
/* RFC 5891 4.4 / RFC 3492: "xn--" + the Punycode of cps, within one
 * label's 63 octets. */
static usz idna_alabel(const u32* cps, usz n, u8* out, usz cap) {
  usz k;
  if (cap < 4) {
    return 0;
  }
  bytes_memcpy(out, "xn--", 4);
  k = salpn_punycode_encode(
      cps, n, out + 4, (usz)u64_min(cap - 4, IDNA_LABEL_MAX - 4));
  return k ? 4 + k : 0;
}

/* An all-ASCII label (already an A-label, or never needed one) as is. */
static usz idna_copy(wired_span l, u8* out, usz cap) {
  if (l.n > cap) {
    return 0;
  }
  bytes_memcpy(out, l.p, l.n);
  return l.n;
}

/* One label in A-label form: code points all below 0x80 copy through,
 * otherwise it is a U-label and gets Punycode-encoded. */
static usz idna_label(wired_span l, u8* out, usz cap) {
  u32 cps[IDNA_HOST_MAX];
  usz n = salpn_idna_decode_label(l, cps);
  if (n == 0) {
    return 0;
  }
  return n == l.n ? idna_copy(l, out, cap) : idna_alabel(cps, n, out, cap);
}

typedef struct {
  wired_span host;
  usz        at; /* next label's offset in host */
  u8*        out;
  usz        cap;
  usz        len;
  int        ok;
} idna_w;

static usz idna_label_end(wired_span h, usz at) {
  while (at < h.n && h.p[at] != '.') {
    at++;
  }
  return at;
}

static int idna_put_dot(idna_w* w) {
  if (w->len >= w->cap) {
    return 0;
  }
  w->out[w->len++] = '.';
  return 1;
}

/* Convert the label at w->at, then the dot after it if any. */
static void idna_step(idna_w* w) {
  usz end = idna_label_end(w->host, w->at);
  usz k   = idna_label(
      wired_span_of(w->host.p + w->at, end - w->at), w->out + w->len,
      w->cap - w->len);
  w->ok = k != 0;
  w->len += k;
  w->at = end + 1;
  if (w->ok && end < w->host.n) {
    w->ok = idna_put_dot(w);
  }
}

static int idna_more(const idna_w* w) { return w->ok && w->at < w->host.n; }

usz salpn_idna_to_ascii(wired_span host, u8* out, usz cap) {
  idna_w w = {host, 0, out, cap, 0, host.n <= IDNA_HOST_MAX};
  while (idna_more(&w)) {
    idna_step(&w);
  }
  return w.ok ? w.len : 0;
}
