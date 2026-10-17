#include "app/moqt/dgram/moqdg_impl.h"

int moqdg_put(wired_mspan buf, usz* off, const moqdg_obj* o) {
  usz at = *off;
  if (!moqdg_put_valid(o)) return MOQDATA_VIOLATION;
  if (!moqdg_put_body(buf, &at, o)) return MOQDATA_INSUFFICIENT;
  *off = at;
  return MOQDATA_OK;
}
