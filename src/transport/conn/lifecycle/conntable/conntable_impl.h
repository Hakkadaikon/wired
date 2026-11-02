#ifndef CONN_CONNTABLE_IMPL_H
#define CONN_CONNTABLE_IMPL_H

#include "transport/conn/lifecycle/conntable/conntable.h"

/* Internal to conntable: rebuild the CID hash index (conntable_hash.c) from
 * every live slot's CIDs; called after each insert/rekey/set. */
void conntable_reindex(conntable* t, usz cap);

#endif
