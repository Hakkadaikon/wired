#include "tls/handshake/core/sdrv/sdrv_impl.h"

/* RFC 8446 4.2.11 / 6.2: pre_shared_key's OfferedPsks must decode, one
 * binder per identity, before sdrv_ch_take_psk reads the offer. */

static usz sdrv_psk_id_step(const u8* p, usz q, usz n);
static usz sdrv_binder_step(const u8* p, usz q, usz n);
static usz sdrv_psk_ids(wired_span d, usz* end);
static int sdrv_psk_body_ok(wired_span d);

/* RFC 8446 4.2.11: PskIdentity = identity<1..2^16-1> obfuscated_ticket_age
 * (4). */
static usz sdrv_psk_id_step(const u8* p, usz q, usz n) {
  usz e = sdrv_entry_end(p, q, n, 2);
  return (e > q + 2 && e + 4 <= n) ? e + 4 : 0;
}

/* RFC 8446 4.2.11: PskBinderEntry<32..255>. */
static usz sdrv_binder_step(const u8* p, usz q, usz n) {
  usz e = sdrv_entry_end(p, q, n, 1);
  return e >= q + 33 ? e : 0;
}

/* identities<7..2^16-1>: how many, with *end just past the vector;
 * SDRV_VEC_BAD if malformed. */
static usz sdrv_psk_ids(wired_span d, usz* end) {
  *end = sdrv_entry_end(d.p, 0, d.n, 2);
  return *end ? sdrv_vec_count(d.p + 2, *end - 2, sdrv_psk_id_step)
              : SDRV_VEC_BAD;
}

/* RFC 8446 4.2.11: OfferedPsks = identities then binders<33..2^16-1>, one
 * binder per identity, exactly filling the extension. */
static int sdrv_psk_body_ok(wired_span d) {
  usz        end;
  usz        nid = sdrv_psk_ids(d, &end);
  wired_span b   = wired_span_of(d.p + end, d.n - end);
  return sdrv_count_ok(nid, 1) && sdrv_vec_ok(b, 2, sdrv_binder_step, 1) &&
         sdrv_vec_count(b.p + 2, b.n - 2, sdrv_binder_step) == nid;
}

/* RFC 8446 4.2.11: a pre_shared_key that is malformed or carries no binder
 * aborts the handshake (decode_error, 6.2) instead of being read as "no
 * offer". */
int sdrv_ch_require_psk_shape(sdrv* s, const u8* ch_msg, usz ch_len) {
  wired_span ext;
  if (!sdrv_find_client_psk_ext(ch_msg, ch_len, &ext)) {
    return 1;
  }
  if (sdrv_psk_body_ok(wired_span_of(ext.p + 4, ext.n - 4))) {
    return 1;
  }
  return sdrv_ch_reject(s, 50);
}
