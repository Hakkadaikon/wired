#ifndef QUIC_TLSEXT_PRESHARED_H
#define QUIC_TLSEXT_PRESHARED_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4.2.11: pre_shared_key, extension_type 0x0029. The ClientHello body
 * is an OfferedPsks: an identities list (each a {opaque identity,
 * obfuscated_ticket_age}) followed by a binders list (each a PskBinderEntry).
 * This codec carries a single identity and a single binder.
 *
 * RFC 8446 4.2.11: pre_shared_key MUST be the last extension in the
 * ClientHello, because the binders are computed over the preceding bytes. */

typedef struct {
  quic_span identity;
  u32       ticket_age;
  quic_span binder;
} quic_tlsext_psk_in;

/* Encode pre_shared_key with one identity and one binder into out->p (out->cap
 * total). Sets out->len. Returns 1, or 0 if it does not fit. */
int quic_tlsext_pre_shared_key(const quic_tlsext_psk_in* in, quic_obuf* out);

/* Located fields of a parsed single-entry pre_shared_key. The pointers alias
 * the input buffer. */
typedef struct {
  const u8* identity;
  usz       id_len;
  u32       ticket_age;
  const u8* binder;
  usz       binder_len;
} quic_tlsext_psk_offer;

/* Parse a single-entry pre_shared_key at out (n readable) into *off. Returns 1
 * on success, 0 if absent or malformed. */
int quic_tlsext_pre_shared_key_parse(
    const u8* out, usz n, quic_tlsext_psk_offer* off);

#endif
