#include "app/http3/server/certreload/certreload.h"

#include "eckey_golden.h"
#include "realchain_golden.h"
#include "test.h"

/* @file
 * wired_certreload_load reads a cert.pem/key.pem pair from disk and points a
 * wired_srvboot_id at the decoded chain/key. PEM texts here are the same
 * golden DER as pem_test.c/eckey_test.c (realchain_golden.h/eckey_golden.h),
 * base64-encoded offline and written to build/ so the test drives the real
 * wired_fio_read path, not an in-memory shortcut. */

#define SYS_unlinkat 263
#define CRT_AT_FDCWD (-100)

static const char crt_cert_path[]    = "build/certreload_cert_test.pem";
static const char crt_key_path[]     = "build/certreload_key_test.pem";
static const char crt_cert_2_path[]  = "build/certreload_cert2_test.pem";
static const char crt_bad_key_path[] = "build/certreload_badkey_test.pem";

/* PEM_LEAF/PEM_INT match pem_test.c's realchain golden encoding. */
#define CRT_PEM_LEAF                                                   \
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

#define CRT_PEM_INT                                                    \
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

/* base64 of quic_eckey_sec1_der (eckey_golden.h), computed offline. */
#define CRT_PEM_KEY                                                    \
  "-----BEGIN EC PRIVATE KEY-----\n"                                   \
  "MHcCAQEEIGEwVXfogbUsrnfdXV/ibLZWhMGAQXbeSwuof7yWDf8PoAoGCCqGSM49\n" \
  "AwEHoUQDQgAExXHoorugQyGhZofbmSFiyMSC0ZMgR5KTsql7o85ozCdi8WXaIs9s\n" \
  "Jqr6SCDjgvw9xPMUV3UEDxCsEZbkEZpW/A==\n"                             \
  "-----END EC PRIVATE KEY-----\n"

/* openssl ecparam -genkey prepends this parameters block (the prime256v1
 * OID) before the EC PRIVATE KEY block; a loader that decodes the first PEM
 * block as the key chokes on it (quic-interop-runner's certs.sh emits keys
 * in exactly this shape). */
#define CRT_PEM_EC_PARAMS           \
  "-----BEGIN EC PARAMETERS-----\n" \
  "BggqhkjOPQMBBw==\n"              \
  "-----END EC PARAMETERS-----\n"

static const char crt_cert_pem[]  = CRT_PEM_LEAF;
static const char crt_cert2_pem[] = CRT_PEM_LEAF CRT_PEM_INT;
static const char                                crt_key_pem[] = CRT_PEM_KEY;
static const char crt_key_params_pem[] = CRT_PEM_EC_PARAMS CRT_PEM_KEY;
static const char                                          crt_bad_key_pem[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "Zm9v\n"
    "-----END EC PRIVATE KEY-----\n";

static void crt_write(const char* path, const char* text, usz n) {
  syscall3(SYS_unlinkat, CRT_AT_FDCWD, path, 0);
  wired_fio_append(path, quic_span_of((const u8*)text, n));
}

static void crt_unlink(const char* path) {
  syscall3(SYS_unlinkat, CRT_AT_FDCWD, path, 0);
}

/* BASELINE: a valid single-cert chain + valid key loads successfully and
 * points id at exactly one chain entry matching the golden leaf DER. */
static void test_certreload_loads_single_cert(void) {
  wired_certreload_store store;
  wired_srvboot_id       id = {0};
  crt_write(crt_cert_path, crt_cert_pem, sizeof(crt_cert_pem) - 1);
  crt_write(crt_key_path, crt_key_pem, sizeof(crt_key_pem) - 1);
  CHECK(wired_certreload_load(crt_cert_path, crt_key_path, &store, &id) == 1);
  CHECK(id.chain_count == 1);
  CHECK(id.chain[0].n == sizeof(quic_realchain_leaf_der));
  CHECK(id.cert_seed == store.priv);
  crt_unlink(crt_cert_path);
  crt_unlink(crt_key_path);
}

/* FULLCHAIN: a 2-certificate cert.pem yields chain_count == 2, leaf first. */
static void test_certreload_loads_two_cert_chain(void) {
  wired_certreload_store store;
  wired_srvboot_id       id = {0};
  crt_write(crt_cert_2_path, crt_cert2_pem, sizeof(crt_cert2_pem) - 1);
  crt_write(crt_key_path, crt_key_pem, sizeof(crt_key_pem) - 1);
  CHECK(wired_certreload_load(crt_cert_2_path, crt_key_path, &store, &id) == 1);
  CHECK(id.chain_count == 2);
  CHECK(id.chain[0].n == sizeof(quic_realchain_leaf_der));
  CHECK(id.chain[1].n == sizeof(quic_realchain_int_der));
  crt_unlink(crt_cert_2_path);
  crt_unlink(crt_key_path);
}

/* MISSING CERT FILE: a nonexistent cert path fails and leaves id untouched.
 */
static void test_certreload_missing_cert_file_fails(void) {
  wired_certreload_store store;
  wired_srvboot_id       id  = {0};
  const u8*              pub = (const u8*)0x1;
  id.pub                     = pub;
  crt_write(crt_key_path, crt_key_pem, sizeof(crt_key_pem) - 1);
  CHECK(
      wired_certreload_load(
          "build/no_such_cert.pem", crt_key_path, &store, &id) == 0);
  CHECK(id.chain_count == 0);
  CHECK(id.pub == pub);
  crt_unlink(crt_key_path);
}

/* EC PARAMETERS PREFIX: a key.pem whose first PEM block is openssl ecparam's
 * EC PARAMETERS (with the EC PRIVATE KEY block after it) still loads -- the
 * loader must skip non-key blocks instead of decoding the first block as the
 * key. */
static void test_certreload_key_with_ec_params_prefix(void) {
  wired_certreload_store store;
  wired_srvboot_id       id = {0};
  crt_write(crt_cert_path, crt_cert_pem, sizeof(crt_cert_pem) - 1);
  crt_write(crt_key_path, crt_key_params_pem, sizeof(crt_key_params_pem) - 1);
  CHECK(wired_certreload_load(crt_cert_path, crt_key_path, &store, &id) == 1);
  CHECK(id.chain_count == 1);
  CHECK(id.cert_seed == store.priv);
  crt_unlink(crt_cert_path);
  crt_unlink(crt_key_path);
}

/* MALFORMED KEY: a key.pem whose DER is not a valid P-256 key fails. */
static void test_certreload_malformed_key_fails(void) {
  wired_certreload_store store;
  wired_srvboot_id       id = {0};
  crt_write(crt_cert_path, crt_cert_pem, sizeof(crt_cert_pem) - 1);
  crt_write(crt_bad_key_path, crt_bad_key_pem, sizeof(crt_bad_key_pem) - 1);
  CHECK(
      wired_certreload_load(crt_cert_path, crt_bad_key_path, &store, &id) == 0);
  crt_unlink(crt_cert_path);
  crt_unlink(crt_bad_key_path);
}

/* NO-OP: cert_path unset (NULL) leaves id/store untouched. */
static void test_certreload_or_selfsigned_noop_on_null(void) {
  wired_certreload_store store;
  wired_srvboot_id       id  = {0};
  const u8*              pub = (const u8*)0x1;
  id.pub                     = pub;
  wired_certreload_load_or_selfsigned(0, crt_key_path, &store, &id);
  CHECK(id.chain_count == 0);
  CHECK(id.pub == pub);
}

/* NO-OP: cert_path unset (empty string) leaves id/store untouched. */
static void test_certreload_or_selfsigned_noop_on_empty(void) {
  wired_certreload_store store;
  wired_srvboot_id       id  = {0};
  const u8*              pub = (const u8*)0x1;
  id.pub                     = pub;
  wired_certreload_load_or_selfsigned("", crt_key_path, &store, &id);
  CHECK(id.chain_count == 0);
  CHECK(id.pub == pub);
}

/* LOADS: a valid cert_path/key_path pair updates id's chain via the same
 * decode path as wired_certreload_load. */
static void test_certreload_or_selfsigned_loads(void) {
  wired_certreload_store store;
  wired_srvboot_id       id = {0};
  crt_write(crt_cert_path, crt_cert_pem, sizeof(crt_cert_pem) - 1);
  crt_write(crt_key_path, crt_key_pem, sizeof(crt_key_pem) - 1);
  wired_certreload_load_or_selfsigned(crt_cert_path, crt_key_path, &store, &id);
  CHECK(id.chain_count == 1);
  CHECK(id.chain[0].n == sizeof(quic_realchain_leaf_der));
  crt_unlink(crt_cert_path);
  crt_unlink(crt_key_path);
}

void test_certreload(void) {
  test_certreload_loads_single_cert();
  test_certreload_loads_two_cert_chain();
  test_certreload_key_with_ec_params_prefix();
  test_certreload_missing_cert_file_fails();
  test_certreload_malformed_key_fails();
  test_certreload_or_selfsigned_noop_on_null();
  test_certreload_or_selfsigned_noop_on_empty();
  test_certreload_or_selfsigned_loads();
}
