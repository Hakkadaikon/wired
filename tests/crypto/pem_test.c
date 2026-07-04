#include "crypto/pki/encoding/pem/pem.h"

#include "realchain_golden.h"
#include "test.h"

/* PEM texts generated offline from the realchain golden DER:
 *   python3: base64.b64encode(der) wrapped at 64 columns between
 *   "-----BEGIN CERTIFICATE-----" / "-----END CERTIFICATE-----" lines
 * (equivalent to `openssl x509 -inform DER -outform PEM`). */
#define PEM_LEAF                                                       \
  "-----BEGIN CERTIFICATE-----\n"                                      \
  "MIIBhjCCASygAwIBAgIBAzAKBggqhkjOPQQDAjAZMRcwFQYDVQQDDA53aXJlZC10\n" \
  "ZXN0LWludDAeFw0yNjA3MDIwMzAwMTZaFw00NjA2MjcwMzAwMTZaMBYxFDASBgNV\n" \
  "BAMMC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaiCgdwIw\n" \
  "Wr9ZW+r2+wkv3gHqRx1516+pZtZ2nXbJzBfS1WrY6Qr1eRcyEpp1qqriguUUDLnG\n" \
  "zj9dEaGlOqA6maNoMGYwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20wDAYDVR0TAQH/\n" \
  "BAIwADAdBgNVHQ4EFgQUtWK5IGsF72wY/FzDIVPcGRDA98gwHwYDVR0jBBgwFoAU\n" \
  "p0+jTTg9jyM2ABMsb5MvCggSYMEwCgYIKoZIzj0EAwIDSAAwRQIgf1pfoFLUW1fX\n" \
  "qkXST1CxjIT2zWkxf1SM922UProdj70CIQCfQ3MEJPxSIUHt3H/58fEK/cMZ+Pc9\n" \
  "iAVZ8V5X3ScnOQ==\n"                                                 \
  "-----END CERTIFICATE-----\n"

#define PEM_INT                                                        \
  "-----BEGIN CERTIFICATE-----\n"                                      \
  "MIIBdzCCAR6gAwIBAgIBAjAKBggqhkjOPQQDAjAaMRgwFgYDVQQDDA93aXJlZC10\n" \
  "ZXN0LXJvb3QwHhcNMjYwNzAyMDMwMDE2WhcNNDYwNjI3MDMwMDE2WjAZMRcwFQYD\n" \
  "VQQDDA53aXJlZC10ZXN0LWludDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABC1J\n" \
  "0leUEgGKpCaqETBMS7/jEtGz3h07ULroddx9K01Eo3iYTczzymEeUb2p9BqfiJbD\n" \
  "V4BcNUif1tod9WoSs/OjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE\n" \
  "FKdPo004PY8jNgATLG+TLwoIEmDBMB8GA1UdIwQYMBaAFHCRX98rWyiLz2Px3RbW\n" \
  "uUS6+cYDMAoGCCqGSM49BAMCA0cAMEQCIHx8A839xXe77noLiDh1iPzEFuDftwEt\n" \
  "1bEFTVlBPJ5KAiBmLezPmHFQVmTof4p/fF61tCsXAb9CHpQxFpB4zqkW7Q==\n"     \
  "-----END CERTIFICATE-----\n"

static const char pem_leaf[]  = PEM_LEAF;
static const char pem_chain[] = PEM_LEAF PEM_INT;

static quic_span pem_text(const char* s, usz n) {
  return quic_span_of((const u8*)s, n);
}

static int pem_bytes_eq(const quic_obuf* der, const u8* exp, usz n) {
  if (der->len != n) return 0;
  for (usz i = 0; i < n; i++) {
    if (der->p[i] != exp[i]) return 0;
  }
  return 1;
}

static int pem_label_is(quic_span label, const char* exp, usz n) {
  if (label.n != n) return 0;
  for (usz i = 0; i < n; i++) {
    if (label.p[i] != (u8)exp[i]) return 0;
  }
  return 1;
}

/* Decode one block of a small self-contained PEM text into out. */
static int pem_one(const char* txt, usz txt_len, quic_obuf* out) {
  usz       at    = 0;
  quic_span label = {0, 0};
  return wired_pem_next(pem_text(txt, txt_len), &at, &label, out);
}

static void test_pem_leaf_golden(void) {
  u8        buf[512];
  quic_obuf der   = quic_obuf_of(buf, sizeof(buf));
  usz       at    = 0;
  quic_span label = {0, 0};
  quic_span txt   = pem_text(pem_leaf, sizeof(pem_leaf) - 1);
  CHECK(wired_pem_next(txt, &at, &label, &der) == 1);
  CHECK(pem_label_is(label, "CERTIFICATE", 11));
  CHECK(pem_bytes_eq(
      &der, quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)));
  CHECK(at == txt.n);
  /* no further block */
  der = quic_obuf_of(buf, sizeof(buf));
  CHECK(wired_pem_next(txt, &at, &label, &der) == 0);
}

static void test_pem_fullchain(void) {
  u8        buf[512];
  quic_obuf der   = quic_obuf_of(buf, sizeof(buf));
  usz       at    = 0;
  quic_span label = {0, 0};
  quic_span txt   = pem_text(pem_chain, sizeof(pem_chain) - 1);
  CHECK(wired_pem_next(txt, &at, &label, &der) == 1);
  CHECK(pem_bytes_eq(
      &der, quic_realchain_leaf_der, sizeof(quic_realchain_leaf_der)));
  der = quic_obuf_of(buf, sizeof(buf));
  CHECK(wired_pem_next(txt, &at, &label, &der) == 1);
  CHECK(pem_bytes_eq(
      &der, quic_realchain_int_der, sizeof(quic_realchain_int_der)));
  der = quic_obuf_of(buf, sizeof(buf));
  CHECK(wired_pem_next(txt, &at, &label, &der) == 0);
}

/* RFC 4648 10 vectors: "Zg=="->f, "Zm8="->fo, "Zm9v"->foo (one line, no
 * wrapping), through both padding shapes. */
static void test_pem_padding(void) {
  u8         buf[8];
  quic_obuf  der    = quic_obuf_of(buf, sizeof(buf));
  const char two[]  = "-----BEGIN X-----\nZg==\n-----END X-----\n";
  const char one[]  = "-----BEGIN X-----\nZm8=\n-----END X-----\n";
  const char none[] = "-----BEGIN X-----\nZm9v\n-----END X-----\n";
  CHECK(pem_one(two, sizeof(two) - 1, &der) == 1);
  CHECK(pem_bytes_eq(&der, (const u8*)"f", 1));
  der = quic_obuf_of(buf, sizeof(buf));
  CHECK(pem_one(one, sizeof(one) - 1, &der) == 1);
  CHECK(pem_bytes_eq(&der, (const u8*)"fo", 2));
  der = quic_obuf_of(buf, sizeof(buf));
  CHECK(pem_one(none, sizeof(none) - 1, &der) == 1);
  CHECK(pem_bytes_eq(&der, (const u8*)"foo", 3));
}

static void test_pem_line_shapes(void) {
  u8        buf[8];
  quic_obuf der = quic_obuf_of(buf, sizeof(buf));
  /* CRLF line endings */
  const char crlf[] = "-----BEGIN X-----\r\nZm9vYmFy\r\n-----END X-----\r\n";
  CHECK(pem_one(crlf, sizeof(crlf) - 1, &der) == 1);
  CHECK(pem_bytes_eq(&der, (const u8*)"foobar", 6));
  /* no trailing newline after the END line; *at reaches text end */
  const char bare[] = "-----BEGIN X-----\nZm9v\n-----END X-----";
  usz        at     = 0;
  quic_span  label  = {0, 0};
  der               = quic_obuf_of(buf, sizeof(buf));
  CHECK(
      wired_pem_next(pem_text(bare, sizeof(bare) - 1), &at, &label, &der) == 1);
  CHECK(at == sizeof(bare) - 1);
  CHECK(pem_bytes_eq(&der, (const u8*)"foo", 3));
}

static void test_pem_surrounding_text(void) {
  u8         buf[8];
  quic_obuf  der   = quic_obuf_of(buf, sizeof(buf));
  usz        at    = 0;
  quic_span  label = {0, 0};
  const char txt[] =
      "subject=/CN=x\n"
      "-----BEGIN X-----\nZm9v\n-----END X-----\n"
      "trailing junk\n";
  quic_span t = pem_text(txt, sizeof(txt) - 1);
  CHECK(wired_pem_next(t, &at, &label, &der) == 1);
  CHECK(pem_label_is(label, "X", 1));
  CHECK(pem_bytes_eq(&der, (const u8*)"foo", 3));
  CHECK(wired_pem_next(t, &at, &label, &der) == 0);
}

static void test_pem_reject(void) {
  u8        buf[8];
  quic_obuf der = quic_obuf_of(buf, sizeof(buf));
  /* invalid base64 character */
  const char bad[] = "-----BEGIN X-----\nZm$v\n-----END X-----\n";
  CHECK(pem_one(bad, sizeof(bad) - 1, &der) == 0);
  /* incomplete final quantum */
  const char shrt[] = "-----BEGIN X-----\nZm9\n-----END X-----\n";
  der               = quic_obuf_of(buf, sizeof(buf));
  CHECK(pem_one(shrt, sizeof(shrt) - 1, &der) == 0);
  /* END line missing */
  const char noend[] = "-----BEGIN X-----\nZm9v\n";
  der                = quic_obuf_of(buf, sizeof(buf));
  CHECK(pem_one(noend, sizeof(noend) - 1, &der) == 0);
  /* no block at all */
  const char plain[] = "no pem here\n";
  der                = quic_obuf_of(buf, sizeof(buf));
  CHECK(pem_one(plain, sizeof(plain) - 1, &der) == 0);
}

static void test_pem_capacity(void) {
  u8         buf[2];
  quic_obuf  der   = quic_obuf_of(buf, sizeof(buf));
  const char txt[] = "-----BEGIN X-----\nZm9v\n-----END X-----\n";
  CHECK(pem_one(txt, sizeof(txt) - 1, &der) == 0);
}

void test_pem(void) {
  test_pem_leaf_golden();
  test_pem_fullchain();
  test_pem_padding();
  test_pem_line_shapes();
  test_pem_surrounding_text();
  test_pem_reject();
  test_pem_capacity();
}
