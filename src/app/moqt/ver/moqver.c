#include "app/moqt/ver/moqver.h"

int moqver_find(wired_span token) {
  (void)token;
  return -1;
}

u32 moqver_caps(int ver) {
  (void)ver;
  return 0;
}

usz wired_moqt_wt_protocols(char* out, usz cap) {
  (void)out;
  (void)cap;
  return 0;
}
