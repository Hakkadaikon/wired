#ifndef WIRED_SRVBOOT_SRVDEMO_H
#define WIRED_SRVBOOT_SRVDEMO_H

#include "app/http3/server/srvboot/srvboot.h"
#include "common/platform/sys/syscall.h"

/** @file
 * A fixed, deterministic server identity for samples and tests: the key
 * bytes are a counting pattern, so every run presents the same self-signed
 * certificate. Never use it for a real deployment. */

/** Storage for the demo key material; wired_srvboot_id holds views into it,
 * so it must outlive the server run (make it static). */
typedef struct {
  u8 priv[32]; /**< X25519 private key */
  u8 pub[32];  /**< X25519 public key, derived from priv */
  u8 seed[32]; /**< ECDSA P-256 certificate signing scalar */
  u8 rnd[32];  /**< ServerHello.random */
} wired_srvboot_demo_keys;

/**
 * Reset id and fill it with the demo identity: priv[i] = base + i,
 * seed[i] = base + 0x40 + i, rnd[i] = base + 0x60 + i, pub = X25519(priv),
 * scid = the bytes of scid (at most 20). Every other field is 0, so the
 * certificate is self-signed; set max_datagram_frame_size etc. afterwards.
 * @param id   identity to fill
 * @param k    key storage; must outlive every use of id
 * @param base first byte of the counting pattern
 * @param scid NUL-terminated server connection id; must outlive id
 */
void wired_srvboot_demo(
    wired_srvboot_id*        id,
    wired_srvboot_demo_keys* k,
    u8                       base,
    const char*              scid);

/**
 * SHA-256 of the leaf certificate id presents: chain[0] when an external
 * chain is set, otherwise the self-signed certificate built from cert_seed.
 * This is the value a browser's WebTransport serverCertificateHashes needs.
 * Builds the certificate in a process-wide scratch server (not reentrant).
 * @param id  server identity
 * @param out 32-byte digest
 * @return 1 ok, 0 if no certificate could be built
 */
int wired_srvboot_cert_sha256(const wired_srvboot_id* id, u8 out[32]);

/**
 * Log "cert sha-256 fingerprint: aa:bb:...\n" (colon-separated, the form
 * browsers and openssl print) for id's leaf certificate to fd.
 * @param fd file descriptor (2 = stderr)
 * @param id server identity
 * @return 1 ok, 0 if no certificate could be built (nothing is logged)
 */
int wired_srvboot_log_fingerprint(i64 fd, const wired_srvboot_id* id);

#endif
