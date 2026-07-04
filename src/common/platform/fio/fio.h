#ifndef QUIC_FIO_H
#define QUIC_FIO_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/**
 * @file
 * Whole-file read via raw Linux syscalls (openat/read/close). No libc.
 */

/**
 * wired_fio_read result when buf filled up but the file holds more bytes.
 * Chosen as -EFBIG (27) so it stays in the negative -errno result space.
 */
#define WIRED_FIO_ETOOBIG (-27)

/**
 * Read the whole file at path into buf.
 *
 * Opens with openat(AT_FDCWD, path, O_RDONLY), reads until end of file,
 * and closes the descriptor.
 *
 * @param path NUL-terminated file path, resolved relative to the cwd
 * @param buf  destination buffer view
 * @return total bytes read (>= 0) on success; a negative -errno when
 *         openat/read fails; WIRED_FIO_ETOOBIG when buf is full but the
 *         file still has unread bytes
 */
ssz wired_fio_read(const char *path, quic_mspan buf);

/**
 * Append data to the file at path, creating it (mode 0600) if it does not
 * exist. Opens with openat(AT_FDCWD, path, O_WRONLY|O_CREAT|O_APPEND, 0600),
 * writes the whole span, and closes the descriptor. Intended for streaming
 * output (e.g. qlog/keylog) where each call adds one record.
 *
 * @param path NUL-terminated file path, resolved relative to the cwd
 * @param data bytes to append
 * @return bytes written (== data.n) on success; a negative -errno when
 *         openat/write fails
 */
ssz wired_fio_append(const char *path, quic_span data);

#endif
