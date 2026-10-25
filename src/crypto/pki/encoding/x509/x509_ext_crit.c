#include "crypto/pki/encoding/x509/x509_impl.h"

static int critical_in_extensions(wired_span ext, wired_span oid);

/* Scan the extensions SEQUENCE for the wanted extnID's critical flag. */
static int critical_in_extensions(wired_span ext, wired_span oid) {
  derseq     exts;
  u8         tag;
  wired_span e;
  derseq_init(&exts, ext);
  while (derseq_next(&exts, &tag, &e)) {
    if (x509_ext_id_is(e, oid)) {
      return x509_ext_is_critical(e);
    }
  }
  return 0;
}

int x509_ext_critical(wired_span tbs, wired_span oid) {
  wired_span ext;
  if (!x509_ext_reach(tbs, &ext)) {
    return 0;
  }
  return critical_in_extensions(ext, oid);
}
