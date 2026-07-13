#include "app/http3/server/srvbigbuf/srvbigbuf.h"

void wired_srvbigbuf_init(wired_srvbigbuf* p, u8* rows, usz row_cap) {
  p->rows    = rows;
  p->row_cap = row_cap;
  for (int i = 0; i < WIRED_SRVBIGBUF_ROWS; i++) p->in_use[i] = 0;
}

u8* wired_srvbigbuf_row(const wired_srvbigbuf* p, int row_idx) {
  if (row_idx < 0 || row_idx >= WIRED_SRVBIGBUF_ROWS) return 0;
  return p->rows + (usz)row_idx * p->row_cap;
}

u8* wired_srvbigbuf_claim(wired_srvbigbuf* p, int* row_idx) {
  for (int i = 0; i < WIRED_SRVBIGBUF_ROWS; i++) {
    if (!p->in_use[i]) {
      p->in_use[i] = 1;
      *row_idx     = i;
      return wired_srvbigbuf_row(p, i);
    }
  }
  return 0;
}

void wired_srvbigbuf_release(wired_srvbigbuf* p, int row_idx) {
  if (row_idx < 0 || row_idx >= WIRED_SRVBIGBUF_ROWS) return;
  p->in_use[row_idx] = 0;
}
