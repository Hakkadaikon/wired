#ifndef TLS_HANDSHAKE_CORE_SDRV_SDRV_IMPL_H
#define TLS_HANDSHAKE_CORE_SDRV_SDRV_IMPL_H

/* Internal to the sdrv*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/datagram/datagram/datagram.h"
#include "common/arch/arch.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/diag/error/codes.h"
#include "common/diag/error/error.h"
#include "common/platform/clock/clock.h"
#include "crypto/asymmetric/ecc/p256/p256_ecdhe.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/pki/cert/p256cert/p256cert.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "tls/ext/legacy/legacy_fields.h"
#include "tls/ext/salpn/ch_ext.h"
#include "tls/ext/salpn/negotiate.h"
#include "tls/ext/salpn/salpn_raw.h"
#include "tls/ext/salpn/sni_check.h"
#include "tls/ext/stp/parse_tp.h"
#include "tls/ext/tlsext/preshared.h"
#include "tls/ext/tlsext/pskmodes.h"
#include "tls/ext/tparam/tparam.h"
#include "tls/ext/tparam/tpcheck.h"
#include "tls/handshake/core/hrr/hrr_build.h"
#include "tls/handshake/core/sdrv/sdrv.h"
#include "tls/handshake/core/tls/binder.h"
#include "tls/handshake/core/tls/chguard.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/encext_check.h"
#include "tls/handshake/core/tls/ext_algs.h"
#include "tls/handshake/core/tls/ext_keyshare.h"
#include "tls/handshake/core/tls/ext_versions.h"
#include "tls/handshake/core/tls/handshake.h"
#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/ticketfreshness.h"
#include "tls/handshake/core/tls/tpext.h"
#include "transport/conn/loop/manage/zerortt_policy.h"
#include "transport/conn/loop/manage/zerortt_seen.h"
#include "transport/version/version/verinfo.h"
#include "transport/version/version/verselect.h"
#include "transport/version/version/version.h"
#include "transport/version/versmgr/avail.h"

/* The ClientHello extensions block being walked for the key_share. */
typedef struct {
  const u8* b;
  usz       end;
} sdrv_ch_block;

/* RFC 8446 4.2.11: locate the pre_shared_key extension (0x0029) TLV, header
 * included, if the ClientHello carries one. */
#define SDRV_PSK_EXT_TYPE 0x0029

/* RFC 8446 4.2.10: locate the early_data extension (0x002a) TLV, header
 * included, if the ClientHello carries one (the body is empty in this
 * direction -- presence alone is the signal). */
#define SDRV_EARLY_DATA_EXT_TYPE 0x002a

/* RFC 8446 4.2.3: signature_algorithms_cert (0x0032), the same
 * SignatureSchemeList shape as signature_algorithms. */
#define SDRV_SIG_ALGS_CERT_EXT_TYPE 0x0032

/* mmap(2) flags for a region fork(2) children keep sharing with the parent
 * (Linux <sys/mman.h>). */
#define SDRV_PROT_RW 0x3
#define SDRV_MAP_SHARED_ANON 0x21

/* RFC 8446 3.4 vector walking shared by the ClientHello shape gates
 * (sdrv_ch_shape.c, sdrv_ch_psk.c). */
/* One entry of a vector at q (n bytes readable): the offset past it, or 0
 * if it does not fit or breaks a per-entry minimum. */
typedef usz (*sdrv_vec_step)(const u8* p, usz q, usz n);

/* sdrv_vec_count's "an entry broke" result. */
#define SDRV_VEC_BAD ((usz) - 1)

/* One pre-condition check run before any field is taken from the
 * ClientHello; each sets s->last_error and returns 0 to reject. Table-driven
 * so sdrv_recv_client_hello's own CCN stays flat as gates are added. */
typedef int (*sdrv_ch_gate)(sdrv*, const u8*, usz);

#define SDRV_CH_GATE_COUNT (sizeof(SDRV_CH_GATES) / sizeof(SDRV_CH_GATES[0]))

int sdrv_ch_hdr(const sdrv_ch_block* blk, usz* q, unsigned* type, usz* dlen);
int sdrv_ch_walk(const u8* b, usz q, usz end, u16 want_group, u8 pub[65]);
int sdrv_prefix_fits(usz p, usz w, usz n);
usz sdrv_prefix_len(const u8* b, usz p, usz w);
usz sdrv_skip_vec(wired_span b, usz p, usz w);
usz sdrv_ch_prefix(const u8* b, usz n);
int sdrv_is_client_hello(const u8* buf, usz n, usz* body_len);
int sdrv_ch_exts_span(const u8* b, usz body, usz* start, usz* end);
int sdrv_take_client_keyshare(
    const u8* ch, usz ch_len, u16 want_group, u8 pub[65]);
int sdrv_ch_find_ext(
    const u8* b, usz q, usz end, unsigned want_type, wired_span* ext);
int sdrv_find_client_tp_ext(const u8* ch, usz ch_len, wired_span* ext);
int sdrv_find_client_psk_ext(const u8* ch, usz ch_len, wired_span* ext);
int sdrv_find_client_ext(
    const u8* ch, usz ch_len, unsigned want_type, wired_span* ext);
void sdrv_take_peer_max_datagram_frame_size(const u8* ch, usz ch_len, u64* out);
void sdrv_take_peer_tp_int(const u8* ch, usz ch_len, u64 param_id, u64* out);
int  sdrv_sid_fits(const u8* ch_msg, usz ch_len);
int  sdrv_reject_nonempty_sid(sdrv* s, u8 len);
int  sdrv_take_client_sid(sdrv* s, const u8* ch_msg, usz ch_len);
void sdrv_negotiate_alpn(sdrv* s, const u8* ch_msg, usz ch_len);
int  sdrv_ch_negotiate(sdrv* s, const u8* ch_msg, usz ch_len, usz* body);
void sdrv_ch_take_optional(sdrv* s, const u8* ch_msg, usz ch_len);
void sdrv_check_sni(sdrv* s, const u8* ch_msg, usz ch_len);
void sdrv_ch_note_cert_sigs(sdrv* s, const u8* ch_msg, usz ch_len);
int sdrv_psk_open_ticket(const sdrv* s, const tlsext_psk_offer* off, ticket* t);
void sdrv_psk_from_ticket_secret(const ticket* t, u8* psk_out);
int  sdrv_psk_binder_ok(
    const sdrv*             s,
    const ticket*           t,
    const u8*               ch_msg,
    wired_span              psk_ext,
    const tlsext_psk_offer* off);
int  sdrv_ch_take_psk(sdrv* s, const u8* ch_msg, usz ch_len);
void sdrv_ch_arm_hrr(sdrv* s, const u8* ch_msg, usz ch_len);
int  sdrv_ch_required_fields(sdrv* s, const u8* ch_msg, usz ch_len);
int  sdrv_ch_require_tp_ext(sdrv* s, const u8* ch_msg, usz ch_len);
int  sdrv_ch_reject_dup_tp(sdrv* s, const u8* ch_msg, usz ch_len);
int  sdrv_ch_check_client_tp(sdrv* s, const u8* ch_msg, usz ch_len);
int  sdrv_ch_check_iscid(sdrv* s, const u8* ch_msg, usz ch_len);
int  sdrv_find_version_information(
    const u8* ch_msg, usz ch_len, wired_span* bytes);
int sdrv_ch_take_version_information(sdrv* s, const version_information* vi);
int sdrv_ch_check_version_information(sdrv* s, const u8* ch_msg, usz ch_len);
int sdrv_ch_after_gate(sdrv* s, const u8* ch_msg, usz ch_len);
int sdrv_ch_reject(sdrv* s, u8 alert);
int sdrv_ch_require_decodable(sdrv* s, const u8* ch_msg, usz ch_len);
int sdrv_ch_require_null_compression(sdrv* s, const u8* ch_msg, usz ch_len);
int sdrv_ch_require_ext_shapes(sdrv* s, const u8* ch_msg, usz ch_len);
int sdrv_ch_require_psk_shape(sdrv* s, const u8* ch_msg, usz ch_len);
int sdrv_ch_require_ks_with_groups(sdrv* s, const u8* ch_msg, usz ch_len);

/* The offset past the w-byte-length-prefixed entry at q, or 0 if its
 * prefix or its declared bytes run past n. */
static inline usz sdrv_entry_end(const u8* p, usz q, usz n, usz w) {
  usz e;
  if (q + w > n) {
    return 0;
  }
  e = q + w + sdrv_prefix_len(p, q, w);
  return e <= n ? e : 0;
}

/* Entries in p[0..n) walked by step, exactly filling n; SDRV_VEC_BAD if
 * one breaks (0 is a valid count: an empty vector). */
static inline usz sdrv_vec_count(const u8* p, usz n, sdrv_vec_step step) {
  usz q = 0, c = 0;
  while (q < n) {
    q = step(p, q, n);
    c++;
    if (q == 0) {
      return SDRV_VEC_BAD;
    }
  }
  return c;
}

/* c is a real count (not SDRV_VEC_BAD) of at least min entries. */
static inline int sdrv_count_ok(usz c, usz min) {
  return c != SDRV_VEC_BAD && c >= min;
}

/* d is exactly one w-prefixed vector of at least min well-formed entries. */
static inline int sdrv_vec_ok(
    wired_span d, usz w, sdrv_vec_step step, usz min) {
  if (d.n == 0 || sdrv_entry_end(d.p, 0, d.n, w) != d.n) {
    return 0;
  }
  return sdrv_count_ok(sdrv_vec_count(d.p + w, d.n - w, step), min);
}

extern const sdrv_ch_gate SDRV_CH_GATES[16];

#endif
