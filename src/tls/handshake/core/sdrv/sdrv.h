#ifndef QUIC_SDRV_SDRV_H
#define QUIC_SDRV_SDRV_H

#include "tls/handshake/core/tls/transcript.h"
#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 8446 4 / RFC 9001 4: server-side handshake driver. Receives the client
 * ClientHello and emits the real TLS bytes of the server flight (ServerHello +
 * EncryptedExtensions + Certificate + CertificateVerify + Finished). Pure
 * orchestration over the existing build/sign/key-schedule parts. */

typedef struct {
    u8 server_priv[32];                 /* RFC 7748 x25519 private */
    u8 server_pub[32];                  /* RFC 7748 x25519 public */
    u8 p256_priv[32];                   /* RFC 5480 ECDSA P-256 signing scalar */
    u8 cert_buf[512];                   /* self-signed P-256 cert DER (owned) */
    const u8 *cert_der;                 /* RFC 8446 4.4.2 end-entity cert (view) */
    usz cert_len;
    u8 client_pub[32];                  /* RFC 8446 4.2.8 client key_share */
    u8 client_sid[32];                  /* RFC 8446 4.1.2 legacy_session_id */
    u8 client_sid_len;                  /* 0..32 */
    u8 hs_secret[QUIC_HKDF_PRK];        /* RFC 8446 7.1 Handshake Secret */
    u8 s_hs_traffic[QUIC_HKDF_PRK];     /* RFC 8446 7.1 server hs traffic secret */
    int hs_ready;                       /* hs_secret derived */
    quic_transcript tr;                 /* RFC 8446 4.4.1 Transcript-Hash */
    u8 odcid[20];                       /* RFC 9000 7.3 client first Initial DCID */
    u8 odcid_len;
    u8 iscid[20];                       /* RFC 9000 7.3 server SCID */
    u8 iscid_len;
} quic_sdrv;

/* Hold the server key material and build the self-signed P-256 certificate from
 * cert_priv (the ECDSA P-256 signing scalar); init transcript/key schedule. The
 * cert_der/cert_len arguments are ignored (the cert is built internally) and
 * kept only for caller compatibility. */
void quic_sdrv_init(quic_sdrv *s, const u8 server_priv_x25519[32],
                    const u8 server_pub_x25519[32], const u8 cert_priv[32],
                    const u8 *cert_der, usz cert_len);

/* RFC 9000 7.3: record the ODCID (the DCID of the client's first Initial) and
 * the ISCID (the server's source connection id) to advertise in the
 * EncryptedExtensions transport parameters. Must be called before
 * build_server_flight. Returns 1 on success, 0 if either length exceeds 20. */
int quic_sdrv_set_cids(quic_sdrv *s, const u8 *odcid, u8 odcid_len,
                       const u8 *iscid, u8 iscid_len);

/* RFC 8446 4.4.1: fold the ClientHello into the transcript and take the
 * client's x25519 key_share. Returns 1 on success, 0 if the key_share is
 * absent or malformed. */
int quic_sdrv_recv_client_hello(quic_sdrv *s, const u8 *ch_msg, usz ch_len);

/* RFC 8446 4.4: build the full server flight. Writes the ServerHello into
 * sh_out (sh_cap, *sh_len) and EncryptedExtensions || Certificate ||
 * CertificateVerify || Finished into hs_flight_out (hs_cap, *hs_len). Derives
 * the handshake secret over the real ECDHE. Returns 1 on success, 0 if a
 * buffer is too small. server_random is the 32-byte ServerHello.random. */
int quic_sdrv_build_server_flight(quic_sdrv *s, const u8 *server_random,
                                  u8 *sh_out, usz sh_cap, usz *sh_len,
                                  u8 *hs_flight_out, usz hs_cap, usz *hs_len);

/* Point *secret at the derived Handshake Secret (verification aid). Returns 1
 * if build_server_flight has run, 0 otherwise. */
int quic_sdrv_handshake_secret(const quic_sdrv *s, const u8 **secret);

#endif
