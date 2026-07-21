#include "tls/handshake/core/tls/initial.h"

#include "common/bytes/util/bytes.h"
#include "transport/version/version/v2keys.h"

/* Label suffixes after the version's "quic "/"quicv2 " prefix (RFC 9001 5.1,
 * RFC 9369 3.3.1); longest is "client in" at 9 bytes. */
#define SUFFIX_MAX 9

/* Build the full HKDF-Expand-Label label ("<prefix><suffix>") for `version`
 * into buf (sized prefix_max(7) + SUFFIX_MAX) and return it as a span. An
 * unknown version falls back to the v1 prefix -- salt/prefix selection never
 * fails outright, it degrades to the invariant (v1) construction. */
static quic_span ilabel_build(u8* buf, u32 version, const char* suffix) {
  const char* prefix;
  usz         prefix_len, n = 0;
  if (!quic_version_label_prefix(version, &prefix, &prefix_len)) {
    quic_version_label_prefix(QUIC_VERSION_1, &prefix, &prefix_len);
  }
  quic_memcpy(buf, prefix, prefix_len);
  n += prefix_len;
  quic_memcpy(buf + n, suffix, quic_cstr_len(suffix));
  n += quic_cstr_len(suffix);
  return quic_span_of(buf, n);
}

/* Expand-Label one field from the per-side secret into out. */
static void derive_field(const u8* secret, quic_span label, quic_mspan out) {
  quic_hkdf_label l = {(const char*)label.p, label.n, {0, 0}};
  quic_hkdf_expand_label(secret, &l, out);
}

/* From the per-side initial secret, fill key/iv/hp (RFC 9001 5.1 / RFC 9369
 * 3.3.1 labels). */
static void derive_keys(
    const u8 secret[QUIC_HKDF_PRK], u32 version, quic_initial_keys* out) {
  u8 buf[7 + SUFFIX_MAX];
  derive_field(
      secret, ilabel_build(buf, version, "key"),
      quic_mspan_of(out->key, QUIC_INITIAL_KEY));
  derive_field(
      secret, ilabel_build(buf, version, "iv"),
      quic_mspan_of(out->iv, QUIC_INITIAL_IV));
  derive_field(
      secret, ilabel_build(buf, version, "hp"),
      quic_mspan_of(out->hp, QUIC_INITIAL_HP));
}

/* The 20-byte Initial salt for `version`, falling back to v1's if unknown
 * (mirrors ilabel_build's fallback). */
static quic_span initial_salt(u32 version) {
  const u8* salt;
  usz       len;
  if (!quic_version_initial_salt(version, &salt, &len))
    quic_version_initial_salt(QUIC_VERSION_1, &salt, &len);
  return quic_span_of(salt, len);
}

/* RFC 9001 5.2 / RFC 9369 3.3.1: "client in"/"server in" take no "quic "
 * (or "quicv2 ") prefix, unlike the "quic key"/"quic iv"/"quic hp"
 * packet-protection-key labels of 5.1 -- confirmed for both versions by
 * initial_test.c's golden vectors (RFC 9001 Appendix A.1 for v1, RFC 9369
 * Appendix A for v2). */
static quic_span side_label(u8* buf, int is_server) {
  const char* suffix = is_server ? "server in" : "client in";
  usz         n      = quic_cstr_len(suffix);
  quic_memcpy(buf, suffix, n);
  return quic_span_of(buf, n);
}

void quic_initial_derive(
    quic_span dcid, int is_server, u32 version, quic_initial_keys* out) {
  u8 initial_secret[QUIC_HKDF_PRK];
  u8 side_secret[QUIC_HKDF_PRK];
  u8 buf[SUFFIX_MAX];
  quic_hkdf_extract(initial_salt(version), dcid, initial_secret);
  derive_field(
      initial_secret, side_label(buf, is_server),
      quic_mspan_of(side_secret, QUIC_HKDF_PRK));
  derive_keys(side_secret, version, out);
}
