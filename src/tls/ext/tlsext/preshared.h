#ifndef QUIC_TLSEXT_PRESHARED_H
#define QUIC_TLSEXT_PRESHARED_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.2.11: pre_shared_key, extension_type 0x0029. The ClientHello body
 * is an OfferedPsks: an identities list (each a {opaque identity,
 * obfuscated_ticket_age}) followed by a binders list (each a PskBinderEntry).
 * This codec carries a single identity and a single binder.
 *
 * RFC 8446 4.2.11: pre_shared_key MUST be the last extension in the
 * ClientHello, because the binders are computed over the preceding bytes. */

/* Encode pre_shared_key with one identity and one binder into out (cap total).
 * Writes the byte count to *out_len. Returns 1, or 0 if it does not fit. */
int quic_tlsext_pre_shared_key(const u8 *identity, usz id_len, u32 ticket_age,
                               const u8 *binder, usz binder_len, u8 *out,
                               usz cap, usz *out_len);

/* Located fields of a parsed single-entry pre_shared_key. The pointers alias
 * the input buffer. */
typedef struct {
    const u8 *identity;
    usz id_len;
    u32 ticket_age;
    const u8 *binder;
    usz binder_len;
} quic_tlsext_psk_offer;

/* Parse a single-entry pre_shared_key at out (n readable) into *off. Returns 1
 * on success, 0 if absent or malformed. */
int quic_tlsext_pre_shared_key_parse(const u8 *out, usz n,
                                     quic_tlsext_psk_offer *off);

#endif
