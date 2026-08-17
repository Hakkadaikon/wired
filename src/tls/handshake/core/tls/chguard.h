#ifndef QUIC_TLS_CHGUARD_H
#define QUIC_TLS_CHGUARD_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 8446 4: server-side rejection checks over a ClientHello's extensions
 * block (the 2-byte-length-prefixed TLV sequence past the extensions-length
 * field, TLV bytes only -- no outer length). Each check is independent and
 * MECE: one RFC requirement per function. */

/* RFC 8446 4.2: "There MUST NOT be more than one extension of the same type
 * in a given extension block." exts is the raw TLV sequence (type(2)
 * len(2) data). Returns 1 if every extension_type is distinct and the
 * sequence is well-formed, 0 on a repeat or a malformed TLV. */
int quic_chguard_no_dup_ext(wired_span exts);

/* RFC 8446 4.2.10 / 4.2.9: pre_shared_key MUST NOT be offered unless the
 * ClientHello also carries psk_key_exchange_modes advertising psk_dhe_ke
 * (the only mode this SDK -- and QUIC, RFC 9001 4.6.1 -- ever accepts).
 * has_psk is whether pre_shared_key is present; modes_dhe_ke is whether
 * psk_key_exchange_modes was found AND named psk_dhe_ke. Returns 1 if the
 * requirement is met (no PSK offered, or PSK offered with the mode), 0 if
 * PSK was offered without a qualifying psk_key_exchange_modes. */
int quic_chguard_psk_modes_ok(int has_psk, int modes_dhe_ke);

/* RFC 8446 4.2.11: "The pre_shared_key extension MUST be the last extension
 * in the ClientHello". exts is the raw TLV sequence; psk is the located
 * pre_shared_key TLV (header included), or a 0-length span if none was
 * found. Returns 1 if psk is absent, or present and its bytes are exactly
 * the tail of exts; 0 if something follows it. */
int quic_chguard_psk_last(wired_span exts, wired_span psk);

/* RFC 8446 9.2 / 4.2.3 / 4.2.7: a ClientHello offering certificate-based
 * authentication MUST carry both signature_algorithms and supported_groups
 * (each is required for the server to pick a CertificateVerify scheme and a
 * key exchange group). Returns 1 if both were found, 0 otherwise. */
int quic_chguard_require_algs(int found_sig_algs, int found_groups);

/* RFC 8446 4.2: "There are also cases where a client can offer an extension
 * ... An endpoint MUST NOT send an extension in any handshake message where
 * it has not been specified to appear... If an implementation receives an
 * extension which it recognizes and which is not specified for the message
 * in which it appears, it MUST abort the handshake with an
 * "illegal_parameter" alert." exts is the ClientHello's raw TLV sequence.
 * Checks each extension_type this SDK recognizes (RFC 8446's own registry,
 * table in 4.2) against the fixed set of extensions the CH column allows;
 * an unrecognized type is not this SDK's concern (never rejected here) --
 * only a type this code knows is CH-illegal fails. Returns 1 if every
 * recognized extension_type is CH-legal, 0 on the first violation or a
 * malformed TLV. */
int quic_chguard_ch_legal_exts(wired_span exts);

#endif
