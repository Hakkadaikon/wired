#ifndef KEYUPDATE_PNCHECK_H
#define KEYUPDATE_PNCHECK_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 6.4: once a key update has moved to a new key phase, a packet
 * that still decrypts under the OLD keys must not carry a packet number
 * higher than any packet number already protected with the newer keys --
 * that would mean the sender emitted it after adopting the new phase but
 * protected it with the old one, which is a connection error of type
 * KEY_UPDATE_ERROR. */

/* 1 if old_key_pn (the packet number of a packet successfully decrypted
 * with the OLD key phase) is higher than new_phase_min_pn (the lowest
 * packet number seen protected with the NEW key phase) -- a
 * KEY_UPDATE_ERROR. 0 if no new-phase packet has been seen yet
 * (new_phase_min_pn's caller-side sentinel) or old_key_pn precedes it. */
int keyupdate_pn_violates(u64 new_phase_min_pn, u64 old_key_pn);

#endif
