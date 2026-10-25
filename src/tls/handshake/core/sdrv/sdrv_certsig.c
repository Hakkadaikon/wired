#include "common/platform/debug/debug.h"
#include "crypto/pki/encoding/x509/sigalgoid.h"
#include "tls/handshake/core/sdrv/sdrv_impl.h"

/* RFC 8446 4.2.3: signature_algorithms_cert, when the ClientHello carries
 * it, judges the signatures in certificates; otherwise signature_algorithms
 * does. Here it only judges -- 4.4.2.2 lets the server send its one chain
 * anyway -- and records the verdict for a log and for chain selection. */

/* The SignatureScheme of a certificate signature, by x509 key kind and
 * digest (X509_SIG_*, X509_HASH_*); 0 where none exists (SHA-224). */
static const u16 SDRV_CERT_SCHEME[3][5] = {
    [X509_SIG_ECDSA]     = {0, 0x0403, 0x0503, 0x0603, 0},
    [X509_SIG_RSA_PKCS1] = {0, 0x0401, 0x0501, 0x0601, 0},
};

/* The scheme der's issuer signed it with, or 0 if unparsed or unknown. */
static u16 sdrv_cert_scheme(wired_span der) {
  x509        x;
  x509_sigalg a;
  if (!x509_parse(der, &x) || !x509_sigalg_lookup(x.sig_alg_oid, &a)) {
    return 0;
  }
  return SDRV_CERT_SCHEME[a.key_kind][a.hash_kind];
}

typedef int (*sdrv_scheme_has_fn)(const u8*, usz, u16);

/* The list judging certificate signatures and its membership test. */
typedef struct {
  wired_span         ext;
  sdrv_scheme_has_fn has;
} sdrv_cert_list;

static int sdrv_cert_list_find(const u8* ch, usz n, sdrv_cert_list* l) {
  l->has = tls_ext_sig_algs_cert_has;
  if (sdrv_find_client_ext(ch, n, EXT_SIGNATURE_ALGORITHMS_CERT, &l->ext)) {
    return 1;
  }
  l->has = tls_ext_sig_algs_has;
  return sdrv_find_client_ext(ch, n, EXT_SIGNATURE_ALGORITHMS, &l->ext);
}

/* Every certificate in s's chain is signed with a scheme l offers. */
static int sdrv_chain_offered(const sdrv* s, const sdrv_cert_list* l) {
  int ok = 1;
  for (usz i = 0; i < s->cert_count; i++) {
    ok &= l->has(l->ext.p, l->ext.n, sdrv_cert_scheme(s->certs[i]));
  }
  return ok;
}

void sdrv_ch_note_cert_sigs(sdrv* s, const u8* ch_msg, usz ch_len) {
  sdrv_cert_list l;
  s->cert_sigs_offered =
      sdrv_cert_list_find(ch_msg, ch_len, &l) && sdrv_chain_offered(s, &l);
  if (!s->cert_sigs_offered) {
    WIRED_LOG("sdrv: chain signature not offered by the client\n");
  }
}
