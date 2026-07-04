#include "app/http3/server/certreload/certreload.h"

#include "common/platform/fio/fio.h"
#include "crypto/pki/encoding/eckey/eckey.h"
#include "crypto/pki/encoding/pem/pem.h"

/* Decode one more CERTIFICATE block (RFC 7468 5) from text into der, up to
 * WIRED_CERTRELOAD_CHAIN_MAX total. */
static int certreload_next_cert(quic_span text, usz *at, quic_obuf *der, usz n) {
  quic_span label;
  return n < WIRED_CERTRELOAD_CHAIN_MAX && wired_pem_next(text, at, &label, der);
}

/* Fill store->chain[] from cert.pem's text, leaf first. Returns the number of
 * certificates decoded (0 if none). */
static usz certreload_load_chain(quic_span text, wired_certreload_store *store) {
  quic_obuf der = quic_obuf_of(store->chain_der, sizeof store->chain_der);
  usz       at = 0, n = 0, start = 0;
  while (certreload_next_cert(text, &at, &der, n)) {
    store->chain[n++] = quic_span_of(store->chain_der + start, der.len - start);
    start             = der.len;
  }
  return n;
}

/* Extract the P-256 private scalar from key.pem's first PEM block into
 * store->priv. Returns 1 on success. */
static int certreload_load_key(quic_span text, wired_certreload_store *store) {
  u8        der_buf[192];
  quic_obuf der = quic_obuf_of(der_buf, sizeof der_buf);
  quic_span label;
  usz       at = 0;
  if (!wired_pem_next(text, &at, &label, &der)) return 0;
  return wired_eckey_p256_priv(quic_span_of(der_buf, der.len), store->priv);
}

/* Read path into buf (cap bytes), returning the byte count or -1 on any
 * read failure (including WIRED_FIO_ETOOBIG). */
static ssz certreload_read_file(const char *path, u8 *buf, usz cap) {
  ssz n = wired_fio_read(path, quic_mspan_of(buf, cap));
  return n < 0 ? -1 : n;
}

/* Decode cert_text/key_text (already read into memory) into store and point
 * id at the result. Returns 1 on success. */
static int certreload_decode(
    quic_span cert_text, quic_span key_text, wired_certreload_store *store,
    wired_srvboot_id *id) {
  usz n = certreload_load_chain(cert_text, store);
  if (n == 0) return 0;
  if (!certreload_load_key(key_text, store)) return 0;
  id->chain_count = n;
  id->chain       = store->chain;
  id->cert_seed   = store->priv;
  return 1;
}

int wired_certreload_load(
    const char *cert_path, const char *key_path,
    wired_certreload_store *store, wired_srvboot_id *id) {
  u8  cert_pem[8192], key_pem[4096];
  ssz cn = certreload_read_file(cert_path, cert_pem, sizeof cert_pem);
  ssz kn = certreload_read_file(key_path, key_pem, sizeof key_pem);
  if (cn < 0 || kn < 0) return 0;
  return certreload_decode(
      quic_span_of(cert_pem, (usz)cn), quic_span_of(key_pem, (usz)kn), store,
      id);
}
