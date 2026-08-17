#include "crypto/pki/encoding/x509/policytree.h"

#include "crypto/pki/encoding/asn1/derval.h"

void x509_policy_tree_init(x509_policy_tree* t) {
  t->set.n  = 0;
  t->is_any = 1;
}

int x509_policy_tree_nonempty(const x509_policy_tree* t) {
  return t->is_any || t->set.n > 0;
}

/* 1 if oid appears in set (OID-equal, no policy mapping). */
static int set_contains(const x509_policy_set* set, wired_span oid) {
  for (usz i = 0; i < set->n; i++)
    if (der_oid_equal(set->oid[i], oid)) return 1;
  return 0;
}

/* Fold one candidate OID from a into out if it is also a member of b and out
 * still has room (both operands already respect QUIC_X509_CERT_POLICY_MAX,
 * so the room check only guards the redundant case of a itself being at the
 * cap). */
static void intersect_fold(
    wired_span cand, const x509_policy_set* b, x509_policy_set* out) {
  if (out->n >= QUIC_X509_CERT_POLICY_MAX) return;
  if (set_contains(b, cand)) out->oid[out->n++] = cand;
}

/* out = a intersected with b (OID-equal membership, no policy mapping). */
static void set_intersect(
    const x509_policy_set* a, const x509_policy_set* b, x509_policy_set* out) {
  out->n = 0;
  for (usz i = 0; i < a->n; i++) intersect_fold(a->oid[i], b, out);
}

/* RFC 5280 6.1.3 (d): the certificate carries certificatePolicies but no
 * anyPolicy -- narrow the tree to its own set (root anyPolicy narrowing for
 * the first time) or to the intersection with the existing narrowed set. */
static void narrow(x509_policy_tree* t, const x509_policy_set* cp) {
  if (t->is_any) {
    t->set = *cp;
  } else {
    x509_policy_set narrowed;
    set_intersect(&t->set, cp, &narrowed);
    t->set = narrowed;
  }
  t->is_any = 0;
}

/* Copy every non-anyPolicy OID from in into out (drops anyPolicy itself,
 * which is a wildcard marker, not an admissible policy identifier once it
 * is being treated as absent). */
static void strip_any(const x509_policy_set* in, x509_policy_set* out) {
  wired_span any =
      wired_span_of(x509_oid_any_policy, sizeof(x509_oid_any_policy));
  out->n = 0;
  for (usz i = 0; i < in->n; i++)
    if (!der_oid_equal(in->oid[i], any)) out->oid[out->n++] = in->oid[i];
}

/* RFC 5280 6.1.3 (d)(2): once inhibit_anypolicy has taken effect, anyPolicy
 * is treated as absent -- narrow to whatever explicit policies (if any)
 * remain after stripping it out. */
static void fold_inhibited(x509_policy_tree* t, const x509_policy_set* cp) {
  x509_policy_set stripped;
  strip_any(cp, &stripped);
  narrow(t, &stripped);
}

/* RFC 5280 6.1.3 (d)(2): anyPolicy is not inhibited -- an anyPolicy
 * statement leaves the tree unchanged; anything else narrows it. */
static void fold_uninhibited(x509_policy_tree* t, const x509_policy_set* cp) {
  if (x509_policy_set_has_any(cp)) return;
  narrow(t, cp);
}

/* RFC 5280 6.1.3 (d)(2): the certificate's certificatePolicies decision,
 * tree already known non-empty going in. */
static void fold_present(
    x509_policy_tree* t, const x509_policy_set* cp, int any_inhibited) {
  if (any_inhibited) {
    fold_inhibited(t, cp);
  } else {
    fold_uninhibited(t, cp);
  }
}

void x509_policy_tree_fold(
    x509_policy_tree* t, wired_span tbs, int any_inhibited) {
  x509_policy_set cp;
  if (!x509_policy_tree_nonempty(t)) return;
  if (!x509_cert_policies(tbs, &cp)) {
    t->is_any = 0;
    t->set.n  = 0;
    return;
  }
  fold_present(t, &cp, any_inhibited);
}
