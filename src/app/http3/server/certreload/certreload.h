#ifndef WIRED_CERTRELOAD_CERTRELOAD_H
#define WIRED_CERTRELOAD_CERTRELOAD_H

#include "app/http3/server/srvboot/srvboot.h"
#include "common/bytes/span/span.h"

/** @file
 * Load (or reload) a server's certificate chain and P-256 signing key from a
 * cert.pem (fullchain, leaf first, RFC 7468 5) and key.pem (SEC1 or PKCS#8
 * EC private key, RFC 7468 4) pair on disk. Shared by the example app's
 * startup path and by a running server's SIGHUP-triggered hot reload
 * (`app/http3/server/srvrun`), so the parsing logic exists exactly once. */

/** At most this many CERTIFICATE blocks are read from a fullchain cert.pem
 * (leaf + one intermediate; matches wired_srvboot_id.chain_count's use). */
#define WIRED_CERTRELOAD_CHAIN_MAX 2

/** Caller-owned storage a load fills: the DER bytes of every chain
 * certificate (concatenated), spans into that buffer (leaf first), and the
 * decoded P-256 private scalar. All views wired_srvboot_id would hold must
 * outlive the id — keep this struct alive for as long as the identity built
 * from it is in use. */
typedef struct {
  u8        chain_der[8192]; /**< concatenated DER of every chain cert */
  quic_span chain[WIRED_CERTRELOAD_CHAIN_MAX]; /**< views into chain_der */
  u8        priv[32];                          /**< P-256 private scalar */
} wired_certreload_store;

/** Read cert_path/key_path, decode the PEM chain and private key into store,
 * and point id->chain/chain_count/cert_seed at store's fields. id's other
 * fields (priv/pub/scid/random) are left untouched.
 * @param cert_path NUL-terminated path to a fullchain PEM (leaf first)
 * @param key_path  NUL-terminated path to a PEM P-256 private key
 * @param store     caller-owned storage; must outlive id's use
 * @param id        updated in place on success; left unmodified on failure
 * @return 1 on success; 0 if either file cannot be read, the PEM/DER is
 *   malformed, or the chain has zero certificates. */
int wired_certreload_load(
    const char*             cert_path,
    const char*             key_path,
    wired_certreload_store* store,
    wired_srvboot_id*       id);

#endif
