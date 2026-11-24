#ifndef APP_NOSTR_NIP98_NIP98_IMPL_H
#define APP_NOSTR_NIP98_NIP98_IMPL_H

/* Internal to the nip98*.c pieces. Not public API. */

#include "app/nostr/nip98/nip98.h"

/* Exactly one tag named name whose value (second string) equals want. */
int nip98_tag_is(const nostrev* ev, const char* name, wired_span want);

#endif
