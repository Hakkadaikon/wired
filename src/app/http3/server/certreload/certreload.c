#include "app/http3/server/certreload/certreload.h"

#include "common/platform/debug/debug.h"
#include "common/platform/exit/exit.h"
#include "common/platform/fio/fio.h"
#include "crypto/pki/encoding/eckey/eckey.h"
#include "crypto/pki/encoding/pem/pem.h"

/* Decode one more CERTIFICATE block (RFC 7468 5) from text into der, up to
 * WIRED_CERTRELOAD_CHAIN_MAX total. */
static int certreload_next_cert(
    quic_span text, usz* at, quic_obuf* der, usz n) {
  quic_span label;
  return n < WIRED_CERTRELOAD_CHAIN_MAX &&
         wired_pem_next(text, at, &label, der);
}

/* Fill store->chain[] from cert.pem's text, leaf first. Returns the number of
 * certificates decoded (0 if none). */
static usz certreload_load_chain(
    quic_span text, wired_certreload_store* store) {
  quic_obuf der = quic_obuf_of(store->chain_der, sizeof store->chain_der);
  usz       at = 0, n = 0, start = 0;
  while (certreload_next_cert(text, &at, &der, n)) {
    store->chain[n++] = quic_span_of(store->chain_der + start, der.len - start);
    start             = der.len;
  }
  return n;
}

/* 1 if the cstring s still has a byte at i and it equals c. */
static int certreload_label_ch(const char* s, usz i, u8 c) {
  return s[i] != 0 && (u8)s[i] == c;
}

static int certreload_label_eq(quic_span label, const char* s) {
  usz i;
  for (i = 0; i < label.n; i++)
    if (!certreload_label_ch(s, i, label.p[i])) return 0;
  return s[i] == 0;
}

/* RFC 7468 10/13: the two labels wired_eckey_p256_priv can decode. Anything
 * else -- notably the "EC PARAMETERS" block `openssl ecparam -genkey`
 * prepends before the key -- is not the key and must be skipped. */
static int certreload_key_label(quic_span label) {
  return certreload_label_eq(label, "EC PRIVATE KEY") ||
         certreload_label_eq(label, "PRIVATE KEY");
}

/* Decode PEM blocks until one carries a private-key label; 1 with its DER
 * appended to der, 0 when text runs out first. */
static int certreload_next_key(quic_span text, usz* at, quic_obuf* der) {
  quic_span label;
  while (wired_pem_next(text, at, &label, der)) {
    if (certreload_key_label(label)) return 1;
    der->len = 0; /* discard a skipped block's DER */
  }
  return 0;
}

/* Extract the P-256 private scalar from key.pem's first private-key PEM
 * block into store->priv. Returns 1 on success. */
static int certreload_load_key(quic_span text, wired_certreload_store* store) {
  u8        der_buf[192];
  quic_obuf der = quic_obuf_of(der_buf, sizeof der_buf);
  usz       at  = 0;
  if (!certreload_next_key(text, &at, &der)) return 0;
  return wired_eckey_p256_priv(quic_span_of(der_buf, der.len), store->priv);
}

/* Read path into buf (cap bytes), returning the byte count or -1 on any
 * read failure (including WIRED_FIO_ETOOBIG). */
static ssz certreload_read_file(const char* path, u8* buf, usz cap) {
  ssz n = wired_fio_read(path, quic_mspan_of(buf, cap));
  return n < 0 ? -1 : n;
}

/* Decode cert_text/key_text (already read into memory) into store and point
 * id at the result. Returns 1 on success. */
static int certreload_decode(
    quic_span               cert_text,
    quic_span               key_text,
    wired_certreload_store* store,
    wired_srvboot_id*       id) {
  usz n = certreload_load_chain(cert_text, store);
  if (n == 0) return 0;
  if (!certreload_load_key(key_text, store)) return 0;
  id->chain_count = n;
  id->chain       = store->chain;
  id->cert_seed   = store->priv;
  return 1;
}

int wired_certreload_load(
    const char*             cert_path,
    const char*             key_path,
    wired_certreload_store* store,
    wired_srvboot_id*       id) {
  /* cert_pem sized past a real 9-cert amplificationlimit chain (13594
   * bytes of PEM text) with headroom -- see WIRED_CERTRELOAD_CHAIN_MAX. */
  u8  cert_pem[16384], key_pem[4096];
  ssz cn = certreload_read_file(cert_path, cert_pem, sizeof cert_pem);
  ssz kn = certreload_read_file(key_path, key_pem, sizeof key_pem);
  if (cn < 0 || kn < 0) return 0;
  return certreload_decode(
      quic_span_of(cert_pem, (usz)cn), quic_span_of(key_pem, (usz)kn), store,
      id);
}

/* 1 if cert_path carries a real value (non-NULL, non-empty). */
static int certreload_path_set(const char* cert_path) {
  return cert_path && cert_path[0];
}

/* Log "cert.pem: N certs\n" -- chain_count can run past a single digit
 * (WIRED_CERTRELOAD_CHAIN_MAX=10, e.g. quic-interop-runner's 9-cert
 * amplificationlimit chain), so this formats the count in full. */
static void certreload_log_chain_count(usz chain_count) {
  char buf[32];
  usz  at = 0;
  wired_fmt_u64(buf, &at, &(wired_fmt_u64_in){chain_count, 1});
  buf[at] = 0;
  wired_log_str("cert.pem: ");
  wired_log_str(buf);
  wired_log_str(chain_count == 1 ? " cert\n" : " certs\n");
}

/* Load or die: wired_certreload_load's own file/PEM/DER checks decide
 * failure; this only turns that failure into a diagnostic + process exit and
 * logs the chain length on success. */
static void certreload_load_or_die(
    const char*             cert_path,
    const char*             key_path,
    wired_certreload_store* store,
    wired_srvboot_id*       id) {
  if (!wired_certreload_load(cert_path, key_path, store, id))
    wired_die("certreload: bad cert/key file\n");
  certreload_log_chain_count(id->chain_count);
}

void wired_certreload_load_or_selfsigned(
    const char*             cert_path,
    const char*             key_path,
    wired_certreload_store* store,
    wired_srvboot_id*       id) {
  if (certreload_path_set(cert_path))
    certreload_load_or_die(cert_path, key_path, store, id);
}
