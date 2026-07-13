#ifndef WIRED_SRVBIGBUF_SRVBIGBUF_H
#define WIRED_SRVBIGBUF_SRVBIGBUF_H

#include "common/platform/sys/syscall.h"

/** @file
 * Fixed pool of large response-body buffers. When a response body does not
 * fit the connection slot's fixed respstore (16KB) -- e.g. a 500KB static
 * file -- the handler claims a row here as its write target instead. A
 * claimed row stays alive until the response's send session is done; after
 * release the next response reuses it. Pool exhaustion is a normal outcome:
 * the caller falls back to the 16KB slot. Nothing is allocated here -- the
 * caller (wired_srvrun_env, eventually) owns the backing bytes and the pool
 * is a view over them. */

/** Number of rows in the pool. */
#define WIRED_SRVBIGBUF_ROWS 2

/** Bytes per row. */
#define WIRED_SRVBIGBUF_ROW_CAP (640 * 1024)

/** Pool over caller-owned storage: rows points at
 * WIRED_SRVBIGBUF_ROWS * row_cap contiguous bytes. */
typedef struct {
  u8* rows;    /**< caller-owned contiguous storage, ROWS * row_cap bytes */
  usz row_cap; /**< bytes per row */
  u8  in_use[WIRED_SRVBIGBUF_ROWS]; /**< 1 while row i is claimed */
} wired_srvbigbuf;

/** Initialize p over rows (caller-owned, WIRED_SRVBIGBUF_ROWS * row_cap
 * bytes); every row starts free.
 * @param p pool to initialize
 * @param rows backing storage, owned by the caller
 * @param row_cap bytes per row */
void wired_srvbigbuf_init(wired_srvbigbuf* p, u8* rows, usz row_cap);

/** Claim the lowest free row.
 * @param p pool to claim from
 * @param row_idx receives the claimed row's index on success
 * @return the row's first byte, or 0 if every row is claimed */
u8* wired_srvbigbuf_claim(wired_srvbigbuf* p, int* row_idx);

/** Return a claimed row to the pool. Out-of-range or already-free indices
 * are ignored (idempotent).
 * @param p pool to release into
 * @param row_idx index previously produced by wired_srvbigbuf_claim */
void wired_srvbigbuf_release(wired_srvbigbuf* p, int row_idx);

/** Row lookup (inspection).
 * @param p pool to look into
 * @param row_idx row index
 * @return the row's first byte, or 0 if row_idx is out of range */
u8* wired_srvbigbuf_row(const wired_srvbigbuf* p, int row_idx);

#endif
