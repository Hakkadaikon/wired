#ifndef SFIELD_SFIELD_DICT_IMPL_H
#define SFIELD_SFIELD_DICT_IMPL_H

#include "app/http3/core/sfield/sfield.h"

/* RFC 8941 cursor primitives shared by sfield_dict.c and
 * sfield_dict_bare.c. */

/* The byte at the cursor, -1 at the end. */
int sfd_peek(const sfield_iter* it);
/* Consume c if it is at the cursor; 1 iff it was. */
int sfd_eat(sfield_iter* it, int c);
/* Skip every byte at the cursor that is in set. */
void sfd_skip(sfield_iter* it, const char* set);
/* RFC 8941 4.2.3.3: the key at the cursor into *k; 0 if none. */
int sfd_key(sfield_iter* it, wired_span* k);
/* RFC 8941 4.2.3.1: the bare item at the cursor into *v; 0 if invalid. */
int sfd_bare(sfield_iter* it, sfield_item* v);

#endif
