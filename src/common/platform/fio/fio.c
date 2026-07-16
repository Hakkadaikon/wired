#include "common/platform/fio/fio.h"

#define FIO_AT_FDCWD (-100) /* openat: resolve path against the cwd */
#define FIO_O_RDONLY 0
#define FIO_O_APPEND_WR 0x441u /* O_WRONLY|O_CREAT|O_APPEND */
#define FIO_O_TRUNC_WR 0x241u  /* O_WRONLY|O_CREAT|O_TRUNC */
#define FIO_MODE_OWNER_RW 0600
#define FIO_MODE_WORLD_R 0644 /* rw owner, r group/other */
#define FIO_MODE_DIR 0755     /* rwx owner, rx group/other */
#define FIO_EEXIST 17

/* read returning <= 0 ends the fill loop: 0 is EOF, negative is -errno. */
static int fio_read_done(i64 ret) { return ret <= 0; }

/* Classify the loop-ending read: EOF yields the byte count, error passes
 * the -errno through. */
static ssz fio_read_result(i64 ret, usz done) {
  return ret < 0 ? (ssz)ret : (ssz)done;
}

/* buf came out full: probe one more byte to tell "exact fit" (EOF now)
 * from "file larger than buf" (WIRED_FIO_ETOOBIG). */
static ssz fio_full_result(i64 fd, usz done) {
  u8  probe;
  i64 ret = syscall3(SYS_read, fd, &probe, 1);
  if (ret > 0) return WIRED_FIO_ETOOBIG;
  return fio_read_result(ret, done);
}

/* Read from fd until EOF or buf is full. */
static ssz fio_fill(i64 fd, quic_mspan buf) {
  usz done = 0;
  while (done < buf.n) {
    i64 ret = syscall3(SYS_read, fd, buf.p + done, buf.n - done);
    if (fio_read_done(ret)) return fio_read_result(ret, done);
    done += (usz)ret;
  }
  return fio_full_result(fd, done);
}

ssz wired_fio_read(const char* path, quic_mspan buf) {
  i64 fd = syscall3(SYS_openat, FIO_AT_FDCWD, path, FIO_O_RDONLY);
  ssz got;
  if (fd < 0) return (ssz)fd;
  got = fio_fill(fd, buf);
  syscall1(SYS_close, fd);
  return got;
}

/* newfstatat's struct stat layout (x86_64 Linux): st_size sits at byte
 * offset 48, sized as a signed 8-byte off_t. Only that one field is read. */
#define FIO_STAT_BUF_LEN 144
#define FIO_STAT_SIZE_OFF 48

ssz wired_fio_open(const char* path) {
  return (ssz)syscall3(SYS_openat, FIO_AT_FDCWD, path, FIO_O_RDONLY);
}

void wired_fio_close(i64 fd) { syscall1(SYS_close, fd); }

ssz wired_fio_pread(i64 fd, quic_mspan buf, u64 off) {
  return (ssz)syscall4(SYS_pread64, fd, buf.p, buf.n, off);
}

ssz wired_fio_size(const char* path) {
  u8  st[FIO_STAT_BUF_LEN];
  i64 ret = syscall4(SYS_newfstatat, FIO_AT_FDCWD, path, st, 0);
  if (ret < 0) return (ssz)ret;
  return (ssz) * (const i64*)(st + FIO_STAT_SIZE_OFF);
}

/* Write the whole span to fd, looping past short writes. A negative return
 * from write(2) (-errno) ends the loop early. */
static ssz fio_write_all(i64 fd, quic_span data) {
  usz done = 0;
  while (done < data.n) {
    i64 ret = syscall3(SYS_write, fd, data.p + done, data.n - done);
    if (ret <= 0) return (ssz)ret;
    done += (usz)ret;
  }
  return (ssz)done;
}

ssz wired_fio_append(const char* path, quic_span data) {
  i64 fd = syscall6(
      SYS_openat, FIO_AT_FDCWD, (i64)path, FIO_O_APPEND_WR, FIO_MODE_OWNER_RW,
      0, 0);
  ssz put;
  if (fd < 0) return (ssz)fd;
  put = fio_write_all(fd, data);
  syscall1(SYS_close, fd);
  return put;
}

/* An already existing directory is not a failure for wired_fio_mkdir. */
static int fio_mkdir_ok(i64 ret) { return ret == 0 || ret == -FIO_EEXIST; }

i64 wired_fio_mkdir(const char* path) {
  i64 ret = syscall3(SYS_mkdirat, FIO_AT_FDCWD, path, FIO_MODE_DIR);
  return fio_mkdir_ok(ret) ? 0 : ret;
}

i64 wired_fio_write_new(const char* path, quic_span data) {
  i64 fd = syscall6(
      SYS_openat, FIO_AT_FDCWD, (i64)path, FIO_O_TRUNC_WR, FIO_MODE_WORLD_R, 0,
      0);
  ssz put;
  if (fd < 0) return fd;
  put = fio_write_all(fd, data);
  syscall1(SYS_close, fd);
  return put < 0 ? (i64)put : 0;
}
