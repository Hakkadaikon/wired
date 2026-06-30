#ifndef QUIC_TLS_EXT_ALGS_H
#define QUIC_TLS_EXT_ALGS_H

#include "common/platform/sys/syscall.h"

/* RFC 8446 4.2.7: supported_groups, extension_type 0x000a.
 * RFC 8446 4.2.3: signature_algorithms, extension_type 0x000d. Both bodies are
 * a 2-byte list length followed by 2-byte entries. */

#define QUIC_EXT_SUPPORTED_GROUPS 0x000a
#define QUIC_EXT_SIGNATURE_ALGORITHMS 0x000d

#define QUIC_GROUP_X25519 0x001d
#define QUIC_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define QUIC_SIG_RSA_PSS_RSAE_SHA256 0x0804
#define QUIC_SIG_ED25519 0x0807

/* Encode supported_groups offering x25519 only. Returns bytes written into
 * buf (cap total), or 0 if it does not fit. */
usz quic_tls_ext_supported_groups(u8 *buf, usz cap);

/* Encode signature_algorithms offering ecdsa_secp256r1_sha256,
 * rsa_pss_rsae_sha256 and ed25519. Returns bytes written, or 0 if no room. */
usz quic_tls_ext_sig_algs(u8 *buf, usz cap);

#endif
