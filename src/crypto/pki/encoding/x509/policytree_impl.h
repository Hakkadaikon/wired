#ifndef X509_POLICYTREE_IMPL_H
#define X509_POLICYTREE_IMPL_H

/* Internal to the policytree*.c pieces: the node and auth-bit helpers
 * (policytree_node.c) the other pieces use. Not public API. */

#include "crypto/pki/encoding/x509/policytree.h"

usz  policytree_oid_index(const wired_span* s, usz n, wired_span oid);
usz  policytree_find(const x509_policy_level* l, wired_span oid);
int  policytree_has_any(const x509_policy_graph* g);
u32  policytree_auth_bit(x509_policy_graph* g, wired_span oid);
void policytree_put(
    x509_policy_graph* g,
    x509_policy_level* l,
    wired_span         oid,
    u32                auth,
    u8                 mapped);

#endif
