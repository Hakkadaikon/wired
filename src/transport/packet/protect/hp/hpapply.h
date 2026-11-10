#ifndef HP_HPAPPLY_H
#define HP_HPAPPLY_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.4.1: protect the packet-number bytes with mask[1..pn_len]. */
void hp_protect_pn(u8* pn, usz pn_len, const u8* mask);

#endif
