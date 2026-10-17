#ifndef APP_MOQT_CACHE_MOQCACHE_IMPL_H
#define APP_MOQT_CACHE_MOQCACHE_IMPL_H

/* Internal to the moqcache*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "app/moqt/cache/moqcache.h"
#include "common/bytes/util/bytes.h"

/* Record layout (moqcache.h): this header, then len payload bytes. A
 * tombstone (a dropped group) has len MOQCACHE_DEAD and no payload. */
typedef struct {
  u64 tag;
  u64 group;
  u64 object;
  u64 len;
} moqcache_rec;

#define MOQCACHE_DEAD (~(u64)0)

moqcache_rec moqcache_rec_at(const moqcache* c, usz off);
int          moqcache_dead(moqcache_rec r);
usz          moqcache_rec_size(moqcache_rec r);
int          moqcache_hit(moqcache_rec r, u64 tag, u64 group, int any);
void         moqcache_drop(moqcache* c, u64 tag, u64 group, int any);
void         moqcache_write(moqcache* c, moqcache_rec r, const u8* p, usz len);
int  moqcache_stays_open(const moqcache* c, moqcache_rec v, u64 tag, u64 group);
usz  moqcache_first_victim(const moqcache* c, u64 tag, u64 group);
void moqcache_entomb(moqcache* c, u64 tag, u64 group);
usz  moqcache_find(moqcache* c, u64 tag, moqctl_loc cur);
int  moqcache_is_obj(moqcache_rec r, moqctl_loc cur);
moqctl_loc moqcache_unknown_stop(
    const moqcache* c, usz off, moqctl_loc cur, moqctl_loc end);

#endif
