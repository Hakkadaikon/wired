#include "app/http3/server/srvloop/srvloop_impl.h"

/* RFC 9000 4.1 / 4.5: receive accounting for every stream the peer sends
 * on, independent of which table (request, WT, plumbing) reassembles its
 * bytes: the per-stream entry table (the frame side is
 * srvloop_rxacct_frame.c). */

static int  rxacct_is(const wired_srvloop_rxacct* e, u64 id);
static int  rxacct_find(const wired_srvloop* l, u64 id);
static int  rxacct_free_slot(const wired_srvloop* l);
static int  rxacct_known_slot(const wired_srvloop* l);
static void rxacct_retire(wired_srvloop* l, int i);
static int  rxacct_room(wired_srvloop* l);
static int  rxacct_claim(wired_srvloop* l, u64 id);
static int  rxacct_find_or_claim(wired_srvloop* l, u64 id);

void srvloop_rxacct_reset(wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_RXACCT_CAP; i++) {
    l->rxacct[i].in_use = 0;
  }
  bytes_memset(l->rxacct_done, 0, sizeof l->rxacct_done);
  l->rx_conn_bytes = 0;
  l->rx_max_data   = 0;
}

static int rxacct_is(const wired_srvloop_rxacct* e, u64 id) {
  return e->in_use && e->stream_id == id;
}

static int rxacct_find(const wired_srvloop* l, u64 id) {
  for (usz i = 0; i < WIRED_SRVLOOP_RXACCT_CAP; i++) {
    if (rxacct_is(&l->rxacct[i], id)) {
      return (int)i;
    }
  }
  return -1;
}

static int rxacct_free_slot(const wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_RXACCT_CAP; i++) {
    if (!l->rxacct[i].in_use) {
      return (int)i;
    }
  }
  return -1;
}

/* An entry whose final size is known: its bytes are all counted. */
static int rxacct_known_slot(const wired_srvloop* l) {
  for (usz i = 0; i < WIRED_SRVLOOP_RXACCT_CAP; i++) {
    if (l->rxacct[i].fs.known) {
      return (int)i;
    }
  }
  return -1;
}

static void rxacct_retire(wired_srvloop* l, int i) {
  u64 id = l->rxacct[i].stream_id;
  wired_srvloop_closed_mark(&l->rxacct_done[id & 3], id);
  l->rxacct[i].in_use = 0;
}

/* A free entry, else one retired with its final size known, else -1.
 * shortcut: with every entry live and open, a further stream goes
 * unaccounted -- the peer then has more streams open than its limits allow
 * this table to back. */
static int rxacct_room(wired_srvloop* l) {
  int i = rxacct_free_slot(l);
  if (i >= 0) {
    return i;
  }
  i = rxacct_known_slot(l);
  if (i >= 0) {
    rxacct_retire(l, i);
  }
  return i;
}

static int rxacct_claim(wired_srvloop* l, u64 id) {
  int i = rxacct_room(l);
  if (i >= 0) {
    l->rxacct[i].in_use    = 1;
    l->rxacct[i].stream_id = id;
    finalsize_init(&l->rxacct[i].fs);
  }
  return i;
}

static int rxacct_find_or_claim(wired_srvloop* l, u64 id) {
  int i = rxacct_find(l, id);
  return i >= 0 ? i : rxacct_claim(l, id);
}

/* id's entry, 0 when it was retired (already fully counted) or none fits.
 * shortcut: rxacct_done's window ceiling counts very old ids as retired. */
wired_srvloop_rxacct* srvloop_rxacct_entry(wired_srvloop* l, u64 id) {
  int i;
  if (wired_srvloop_closed_has(&l->rxacct_done[id & 3], id)) {
    return 0;
  }
  i = rxacct_find_or_claim(l, id);
  return i < 0 ? 0 : &l->rxacct[i];
}

int wired_srvloop_rx_final_known(const wired_srvloop* l, u64 stream_id) {
  int i = rxacct_find(l, stream_id);
  if (i >= 0) {
    return l->rxacct[i].fs.known;
  }
  return wired_srvloop_closed_has(&l->rxacct_done[stream_id & 3], stream_id);
}
