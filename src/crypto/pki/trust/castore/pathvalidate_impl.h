#ifndef CRYPTO_PKI_TRUST_CASTORE_PATHVALIDATE_IMPL_H
#define CRYPTO_PKI_TRUST_CASTORE_PATHVALIDATE_IMPL_H

/* Internal to the pathvalidate*.c pieces of this directory: shared types,
 * macros and the functions and tables more than one piece uses. Not public API.
 */

#include "crypto/pki/encoding/x509/basicconstraints.h"
#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/eku.h"
#include "crypto/pki/encoding/x509/keyusage.h"
#include "crypto/pki/encoding/x509/nameconstraints.h"
#include "crypto/pki/encoding/x509/policyconstraints.h"
#include "crypto/pki/encoding/x509/policytree.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/validity.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/chainverify.h"
#include "crypto/pki/trust/castore/pathvalidate.h"

int castore_leaf_allows_server_auth(wired_span leaf);
int castore_cert_issuer(wired_span cert, wired_span* dn);
int castore_cert_self_issued(wired_span cert);
int castore_all_extensions_ok(const wired_span* certs, usz n_certs);
int castore_cert_spki_ku_ok(wired_span cert, int is_ca);
int castore_link_ok(wired_span child, wired_span parent);
int castore_find_ca_anchor(const castore* s, wired_span iss, wired_span* root);
int castore_tail_anchor(const castore* s, wired_span tail, wired_span* root);
int castore_links_ok(const wired_span* certs, usz n);
int castore_name_constraints_chain_ok(const wired_span* certs, usz n_certs);
int castore_policy_step(
    wired_span        cert,
    x509_policy_tree* tree,
    u64*              explicit_policy,
    u64*              inhibit_any);
int castore_policy_processing_ok(const wired_span* certs, usz n_walk);

#endif
