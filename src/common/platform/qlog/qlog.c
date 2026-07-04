#include "common/platform/qlog/qlog.h"

#include "common/bytes/util/bytes.h"
#include "common/platform/fio/fio.h"

#define QLOG_RS 0x1E
#define QLOG_FRAME_OVERHEAD 2 /* leading RS + trailing LF */
/* One qlog event as JSON (packet header + frame summary) comfortably fits;
 * raise if a caller's real event text gets ETOOBIG in practice. */
#define QLOG_MAX_RECORD 4096

ssz wired_qlog_append(const char* path, quic_span record) {
  u8 frame[QLOG_MAX_RECORD + QLOG_FRAME_OVERHEAD];
  if (record.n > QLOG_MAX_RECORD) return WIRED_FIO_ETOOBIG;
  frame[0] = QLOG_RS;
  quic_memcpy(frame + 1, record.p, record.n);
  frame[1 + record.n] = '\n';
  return wired_fio_append(
      path, quic_span_of(frame, record.n + QLOG_FRAME_OVERHEAD));
}
