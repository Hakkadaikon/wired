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
ssz wired_fio_read(const char* path, quic_mspan buf);

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
ssz wired_fio_append(const char* path, quic_span data);

/**
 * Open path for reading (openat(AT_FDCWD, path, O_RDONLY)), leaving the
 * descriptor open for repeated wired_fio_pread calls. Pairs with
 * wired_fio_close. Intended for streaming a file too large for one buffer:
 * the caller reads it round by round instead of via wired_fio_read's single
 * whole-file call.
 *
 * @param path NUL-terminated file path, resolved relative to the cwd
 * @return an open file descriptor (>= 0) on success, a negative -errno
 *         otherwise
 */
ssz wired_fio_open(const char* path);

/**
 * The file's total size in bytes (via newfstatat's st_size), without
 * disturbing any open descriptor's read position.
 *
 * @param path NUL-terminated file path, resolved relative to the cwd
 * @return total byte count (>= 0) on success, a negative -errno otherwise
 */
ssz wired_fio_size(const char* path);

/**
 * Read up to buf.n bytes from fd starting at byte offset off (pread64:
 * does not move any shared file position, so concurrent rounds over the
 * same fd never race each other).
 *
 * @param fd  descriptor from wired_fio_open
 * @param buf destination buffer view
 * @param off byte offset to read from
 * @return bytes read (0 at EOF, < buf.n only at EOF) on success; a negative
 *         -errno when the read fails
 */
ssz wired_fio_pread(i64 fd, quic_mspan buf, u64 off);

/**
 * Create the directory at path (mkdirat(AT_FDCWD, path, 0755)). A path that
 * already exists (EEXIST) counts as success, so repeated calls are harmless.
 * Mode 0755 keeps the directory readable by other uids (e.g. a runner
 * outside the container inspecting the results).
 *
 * @param path NUL-terminated directory path, resolved relative to the cwd
 * @return 0 on success or when the path already exists; a negative -errno
 *         otherwise (e.g. a missing parent directory)
 */
i64 wired_fio_mkdir(const char* path);

/**
 * Replace the file at path with data. Opens with openat(AT_FDCWD, path,
 * O_WRONLY|O_CREAT|O_TRUNC, 0644), writes the whole span (looping past
 * short writes), and closes the descriptor. Any previous content is
 * discarded. Mode 0644 keeps the file readable by other uids.
 *
 * @param path NUL-terminated file path, resolved relative to the cwd
 * @param data bytes to write
 * @return 0 on success; a negative -errno when openat/write fails
 */
i64 wired_fio_write_new(const char* path, quic_span data);

/**
 * Close a descriptor from wired_fio_open. Idempotent misuse (already closed,
 * negative fd) is the caller's responsibility to avoid; this simply issues
 * close(2).
 *
 * @param fd descriptor to close
 */
void wired_fio_close(i64 fd);

#endif
