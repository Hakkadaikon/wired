#ifndef QUIC_TLS_EXT_ALGS_H
#define QUIC_TLS_EXT_ALGS_H

#include "common/platform/sys/syscall.h"
#include "tls/handshake/core/tls/handshake.h" /* QUIC_GROUP_X25519 */

/* RFC 8446 4.2.7: supported_groups, extension_type 0x000a.
 * RFC 8446 4.2.3: signature_algorithms, extension_type 0x000d. Both bodies are
 * a 2-byte list length followed by 2-byte entries. */

#define QUIC_EXT_SUPPORTED_GROUPS 0x000a
#define QUIC_EXT_SIGNATURE_ALGORITHMS 0x000d

#define QUIC_SIG_ECDSA_SECP256R1_SHA256 0x0403
#define QUIC_SIG_RSA_PSS_RSAE_SHA256 0x0804
#define QUIC_SIG_ED25519 0x0807

/* Encode supported_groups offering x25519 only. Returns bytes written into
 * buf (cap total), or 0 if it does not fit. */
usz quic_tls_ext_supported_groups(u8* buf, usz cap);

/* Encode signature_algorithms offering ecdsa_secp256r1_sha256,
 * rsa_pss_rsae_sha256 and ed25519. Returns bytes written, or 0 if no room. */
usz quic_tls_ext_sig_algs(u8* buf, usz cap);

/* RFC 8446 4.4.3 / 4.2.3: does the ClientHello's signature_algorithms
 * extension (buf, header included, n readable) name `scheme`? Used by the
 * server to pick the CertificateVerify SignatureScheme it is about to sign
 * with from what the client actually offered, rather than assuming a fixed
 * one. Returns 1 if present, 0 if absent, malformed, or scheme is not in the
 * list. */
int quic_tls_ext_sig_algs_has(const u8* buf, usz n, u16 scheme);

#endif
