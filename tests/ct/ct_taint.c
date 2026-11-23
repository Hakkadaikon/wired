/* Secret-taint constant-time check, ctgrind style (issue #309). Hosted
 * program, outside the unity build: it needs the host's valgrind client
 * request header, which src/ may not include. Linked against the shipped
 * freestanding objects (build/libwired.a), so it checks the code that ships.
 *
 * Each case marks its secret input undefined (VALGRIND_MAKE_MEM_UNDEFINED),
 * runs the production operation, then marks the output defined and compares
 * it with an untainted run of the same operation. Under valgrind memcheck
 * any branch or memory index that depends on the secret is reported
 * ("Conditional jump or move depends on uninitialised value(s)" / "Use of
 * uninitialised value of size N") and fails the run (RFC 7748 5 / 5.1,
 * RFC 8032 8.1, RFC 8439 4, FIPS 197 5, SP 800-38D 6.4).
 *
 * `ct_taint <case>` runs one case (2 if no case has that name);
 * `ct_taint neg` runs the negative control, a function that branches on the
 * secret: memcheck must report it, proving the harness detects. */
#include <stdio.h>
#include <string.h>
#include <valgrind/memcheck.h>

#include "common/bytes/util/ct.h"
#include "crypto/asymmetric/ecc/cvecdsa/cvecdsa.h"
#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/asymmetric/ecc/p256/p256_ecdhe.h"
#include "crypto/asymmetric/ecc/p256sign/sign.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "crypto/symmetric/aead/chacha/aead.h"
#include "crypto/symmetric/aead/gcm/gcm.h"
#include "crypto/symmetric/aead/gcm/gcm256.h"
#include "crypto/symmetric/aead/gcmx86/gcmx86.h"
#include "crypto/symmetric/hash/hash/hmac.h"
#include "tls/handshake/core/tls/x25519.h"
#include "transport/packet/protect/hp/hp_chacha.h"
#include "transport/packet/protect/protect_suite/hp_suite.h"

#define CT_SECRET_MAX 32
#define CT_OUT_MAX 80

/* One case: out = op(secret), with every other input fixed and public. */
typedef struct {
  const char* name;
  void (*op)(const u8* secret, u8* out);
  usz secret_len;
  usz out_len;
  int leak;
} ct_case;

static const u8 ct_msg[32]   = "public message, 32 bytes long..";
static const u8 ct_nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

static void ct_x25519(const u8* s, u8* out) {
  static const u8 u[X25519_LEN] = {9};
  (void)wired_x25519(out, s, u);
}

static void ct_x25519_base(const u8* s, u8* out) {
  (void)wired_x25519_base(out, s);
}

static void ct_ed25519_keypair(const u8* s, u8* out) {
  (void)ed25519_keypair(s, out);
}

/* The seed derives both the private scalar and the nonce prefix (RFC 8032
 * 5.1.5), so tainting it taints every secret the signer touches. */
static void ct_ed25519_sign(const u8* s, u8* out) {
  (void)ed25519_sign(s, ct_msg, sizeof ct_msg, out);
}

/* Secret key. */
static void ct_chapoly(const u8* s, u8* out) {
  chapoly_ctx c = {s, ct_nonce, wired_span_of(0, 0)};
  (void)chapoly_seal(&c, wired_span_of(ct_msg, sizeof ct_msg), out);
}

/* Secret plaintext under a public key. */
static void ct_chapoly_pt(const u8* s, u8* out) {
  chapoly_ctx c = {ct_msg, ct_nonce, wired_span_of(0, 0)};
  (void)chapoly_seal(&c, wired_span_of(s, 32), out);
}

/* RFC 9001 5.4.4: the header-protection key is secret, the sample public. */
static void ct_hp_chacha(const u8* s, u8* out) {
  hp_chacha_mask(s, ct_msg, out);
}

static void ct_sha256(const u8* s, u8* out) { wired_sha256(s, 32, out); }

static void ct_sha384(const u8* s, u8* out) { sha384(s, 32, out); }

static void ct_hmac_sha256(const u8* s, u8* out) {
  hmac_sha256(wired_span_of(s, 32), wired_span_of(ct_msg, sizeof ct_msg), out);
}

/* Secret IKM through Extract, then Expand of the secret PRK. */
static void ct_hkdf(const u8* s, u8* out) {
  u8 prk[HKDF_PRK];
  hkdf_extract(wired_span_of(ct_nonce, 12), wired_span_of(s, 32), prk);
  (void)hkdf_expand(
      prk, wired_span_of(ct_msg, sizeof ct_msg), wired_mspan_of(out, 64));
}

/* AES-GCM seal (SP 800-38D 7.1) with a secret key: the key schedule,
 * every AES block and GHASH under the secret H. */
static void ct_aes128gcm(const u8* s, u8* out) {
  aes128  a;
  gcm_ctx g = {&a, ct_nonce, wired_span_of(0, 0)};
  aes128_init(&a, s);
  (void)gcm_seal(&g, wired_span_of(ct_msg, sizeof ct_msg), out);
}

static void ct_aes256gcm(const u8* s, u8* out) {
  aes256     a;
  gcm256_ctx g = {&a, ct_nonce, wired_span_of(0, 0)};
  aes256_init(&a, s);
  (void)gcm256_seal(&g, wired_span_of(ct_msg, sizeof ct_msg), out);
}

/* Secret plaintext under a public key. */
static void ct_aes128gcm_pt(const u8* s, u8* out) {
  aes128  a;
  gcm_ctx g = {&a, ct_nonce, wired_span_of(0, 0)};
  aes128_init(&a, ct_msg);
  (void)gcm_seal(&g, wired_span_of(s, 32), out);
}

static void ct_aes256gcm_pt(const u8* s, u8* out) {
  aes256     a;
  gcm256_ctx g = {&a, ct_nonce, wired_span_of(0, 0)};
  aes256_init(&a, ct_msg);
  (void)gcm256_seal(&g, wired_span_of(s, 32), out);
}

/* RFC 9001 5.4.3: AES-ECB of the public sample under the secret key. */
static void ct_hp_aes128(const u8* s, u8* out) {
  (void)hp_suite_mask(0x1301, s, ct_msg, out);
}

static void ct_hp_aes256(const u8* s, u8* out) {
  (void)hp_suite_mask(0x1302, s, ct_msg, out);
}

/* The same operations on the software AES and GHASH an AES-NI host never
 * reaches on its own: gcmx86_cached = 1 reads as "no AES-NI". */
static void ct_sw(void (*op)(const u8*, u8*), const u8* s, u8* out) {
  gcmx86_cached = 1;
  op(s, out);
  gcmx86_cached = 0;
}

static void ct_aes128gcm_sw(const u8* s, u8* out) {
  ct_sw(ct_aes128gcm, s, out);
}

static void ct_aes256gcm_sw(const u8* s, u8* out) {
  ct_sw(ct_aes256gcm, s, out);
}

static void ct_aes128gcm_pt_sw(const u8* s, u8* out) {
  ct_sw(ct_aes128gcm_pt, s, out);
}

static void ct_aes256gcm_pt_sw(const u8* s, u8* out) {
  ct_sw(ct_aes256gcm_pt, s, out);
}

static void ct_hp_aes128_sw(const u8* s, u8* out) {
  ct_sw(ct_hp_aes128, s, out);
}

static void ct_hp_aes256_sw(const u8* s, u8* out) {
  ct_sw(ct_hp_aes256, s, out);
}

/* Both tag operands are secret-derived in an AEAD open. */
static void ct_diff(const u8* s, u8* out) { out[0] = ct_diff16(s, s + 16); }

static void ct_p256_pubkey(const u8* s, u8* out) {
  (void)p256_pubkey_encode(out, s);
}

static void ct_p256_ecdh(const u8* s, u8* out) {
  static const u8 peer_priv[32] = {[31] = 7};
  u8              peer[P256_PUBKEY_LEN];
  (void)p256_pubkey_encode(peer, peer_priv);
  (void)p256_ecdh(out, s, peer);
}

/* memcheck cannot taint the getrandom output, so the secret stands in for
 * one draw: the range check, then the public key of the accepted scalar. */
static void ct_p256_keygen(const u8* s, u8* out) {
  out[0] = (u8)p256_keygen_accept(s);
  (void)p256_pubkey_encode(out + 1, s);
}

/* The RFC 6979 nonce k is derived from priv, so it is tainted too. */
static void ct_p256_sign(const u8* s, u8* out) {
  (void)p256sign_sign(s, ct_msg, out, out + 32);
}

/* RFC 8446 4.4.3 CertificateVerify signed with the long-term key. */
static void ct_cvecdsa(const u8* s, u8* out) {
  usz n = 0;
  memset(out, 0, CT_OUT_MAX);
  (void)cvecdsa_build(s, wired_span_of(ct_msg, sizeof ct_msg), out, 80, &n);
}

/* Declassification hook (weak no-op in the library): the P-256 code passes
 * only values that are public by design -- the RFC 6979 / key-generation
 * accept bit of a candidate (a rejected candidate is discarded) and the
 * signature (r, s) it publishes. */
void p256_ct_public(const void* p, usz n) { VALGRIND_MAKE_MEM_DEFINED(p, n); }

/* Negative control: branches on the secret (the volatile store keeps the
 * compiler from turning it into a branchless select). Must be reported. */
static volatile u8 ct_sink;
static void        ct_neg(const u8* s, u8* out) {
  if (s[0] & 1) {
    ct_sink = 1;
  }
  out[0] = 0;
}

/* leak = 1: a case memcheck must keep reporting (exit 99); ct_check.sh fails
 * when it runs clean. Only the negative control has it. A primitive whose
 * known leak gets fixed is flipped by changing its leak from 1 to 0, which
 * moves it into the gated set. */
static const ct_case ct_cases[] = {
    {"x25519", ct_x25519, 32, 32, 0},
    {"x25519_base", ct_x25519_base, 32, 32, 0},
    {"ed25519_keypair", ct_ed25519_keypair, 32, 32, 0},
    {"ed25519_sign", ct_ed25519_sign, 32, 64, 0},
    {"chacha20poly1305_seal", ct_chapoly, 32, 48, 0},
    {"chacha20poly1305_seal_pt", ct_chapoly_pt, 32, 48, 0},
    {"hp_chacha", ct_hp_chacha, 32, 5, 0},
    {"sha256", ct_sha256, 32, 32, 0},
    {"sha384", ct_sha384, 32, 48, 0},
    {"hmac_sha256", ct_hmac_sha256, 32, 32, 0},
    {"hkdf_sha256", ct_hkdf, 32, 64, 0},
    {"ct_diff16", ct_diff, 32, 1, 0},
    {"p256_pubkey", ct_p256_pubkey, 32, P256_PUBKEY_LEN, 0},
    {"p256_ecdh", ct_p256_ecdh, 32, 32, 0},
    {"p256_keygen", ct_p256_keygen, 32, 1 + P256_PUBKEY_LEN, 0},
    {"p256_sign", ct_p256_sign, 32, 64, 0},
    {"cvecdsa_build", ct_cvecdsa, 32, CT_OUT_MAX, 0},
    {"aes128gcm_seal", ct_aes128gcm, 16, 48, 0},
    {"aes256gcm_seal", ct_aes256gcm, 32, 48, 0},
    {"aes128gcm_seal_pt", ct_aes128gcm_pt, 32, 48, 0},
    {"aes256gcm_seal_pt", ct_aes256gcm_pt, 32, 48, 0},
    {"hp_aes128", ct_hp_aes128, 16, 5, 0},
    {"hp_aes256", ct_hp_aes256, 32, 5, 0},
    {"aes128gcm_seal_sw", ct_aes128gcm_sw, 16, 48, 0},
    {"aes256gcm_seal_sw", ct_aes256gcm_sw, 32, 48, 0},
    {"aes128gcm_seal_pt_sw", ct_aes128gcm_pt_sw, 32, 48, 0},
    {"aes256gcm_seal_pt_sw", ct_aes256gcm_pt_sw, 32, 48, 0},
    {"hp_aes128_sw", ct_hp_aes128_sw, 16, 5, 0},
    {"hp_aes256_sw", ct_hp_aes256_sw, 32, 5, 0},
    {"neg", ct_neg, 1, 1, 1},
};

#define CT_NCASES (sizeof ct_cases / sizeof ct_cases[0])

/* Untainted reference run, then the tainted run; 1 if both agree. */
static int ct_run(const ct_case* c) {
  u8 s[CT_SECRET_MAX], ref[CT_OUT_MAX], out[CT_OUT_MAX];
  for (usz i = 0; i < sizeof s; i++) {
    s[i] = (u8)(0x11 + i);
  }
  c->op(s, ref);
  VALGRIND_MAKE_MEM_UNDEFINED(s, c->secret_len);
  c->op(s, out);
  VALGRIND_MAKE_MEM_DEFINED(out, c->out_len);
  printf("ct_taint: %s\n", c->name);
  return memcmp(ref, out, c->out_len) == 0;
}

/* No argument: every leak = 0 case. `leaks`: print the leak = 1 names. A
 * case name: run only that case; an unknown name exits 2. */
int main(int argc, char** argv) {
  int ok    = 1;
  int ran   = 0;
  int leaks = argc > 1 && strcmp(argv[1], "leaks") == 0;
  for (usz i = 0; i < CT_NCASES; i++) {
    const ct_case* c = &ct_cases[i];
    if (leaks && c->leak) {
      printf("%s\n", c->name);
    } else if (argc > 1 ? strcmp(argv[1], c->name) == 0 : !c->leak) {
      ok &= ct_run(c);
      ran++;
    }
  }
  if (!ran && !leaks) {
    fprintf(stderr, "ct_taint: no case named %s\n", argv[1]);
    return 2;
  }
  return !ok;
}
