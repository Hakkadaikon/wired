/* word_list's static-file mode (--root) and its access log. */

#include "word_list.h"

/* One line per request: "METHOD PATH STATUS BYTES\n" (ponytail: fixed
 * single-line format, no log levels/rotation -- add if an operator needs it).
 */
void wl_access_log(
    const app_config* cfg,
    wired_span        method,
    wired_span        path,
    u64               status,
    u64               nbytes) {
  char line[512];
  usz  at = 0;
  if (!cfg->access_log) {
    return;
  }
  at         = wired_cstr_append(line, sizeof line, at, method);
  line[at++] = ' ';
  at         = wired_cstr_append(line, sizeof line - 39, at, path);
  at += wired_snprintf(
      line + at, sizeof line - at, " %llu %llu\n", status, nbytes);
  wired_fio_append(cfg->access_log, wired_span_of((const u8*)line, at));
}

/* Write the 404 body and return its status code. */
static u64 not_found(wired_obuf* body_out) {
  body_out->len = 0;
  wired_obuf_put(body_out, wired_span_cstr("404 Not Found\n"));
  return 404;
}

/* 1 when a read of got bytes at offset left bytes of total unread. */
static int static_has_more(ssz got, u64 offset, ssz total) {
  return got >= 0 && offset + (u64)got < (u64)total;
}

/* Read one round of the open fd (resolved's bytes) at offset into
 * body_out's storage; negative when the size or the read fails. */
static ssz static_read(
    ssz         fd,
    const char* resolved,
    u64         offset,
    wired_obuf* body_out,
    int*        more,
    u64*        total_size) {
  ssz total = wired_fio_size(resolved);
  ssz got;
  if (total < 0) {
    return -1;
  }
  if (offset == 0) {
    *total_size = (u64)total;
  }
  got = wired_fio_pread(fd, wired_mspan_of(body_out->p, body_out->cap), offset);
  *more |= static_has_more(got, offset, total);
  return got;
}

/* Read one round of resolved's bytes starting at offset into body_out,
 * requesting another round (*more = 1) whenever bytes remain past this
 * round. total_size is reported once, on the first round, so a caller that
 * frames the body with an upfront length field (HTTP/3's DATA frame) can
 * write that length before the rest of the bytes exist. A file that fits in
 * one round (the common case) never sets *more: this is plain
 * wired_fio_read's whole-file behavior, only reached via open+pread so the
 * two paths share one read loop instead of diverging. */
static u64 serve_static_round(
    const char* resolved,
    u64         offset,
    wired_obuf* body_out,
    int*        more,
    u64*        total_size) {
  ssz fd = wired_fio_open(resolved);
  ssz got;
  if (fd < 0) {
    return not_found(body_out);
  }
  got = static_read(fd, resolved, offset, body_out, more, total_size);
  wired_fio_close(fd);
  if (got < 0) {
    return not_found(body_out);
  }
  body_out->len = (usz)got;
  return 200;
}

/* Static-file mode (quiche-server's --root/--index): resolve the request path
 * under cfg->root and serve the file's bytes, or a 404 body when it does not
 * resolve/open (the wire :status stays 200 -- see srvloop/respond.c, which
 * hard-codes 200 for every decoded request; changing that is a larger,
 * separate change). The logged status reflects whether the file was found.
 * A body larger than one round (body_out->cap) streams via serve_static_round
 * across repeated calls at increasing offset (see wired_srvloop_handler). */
u64 wl_serve_static(
    const app_config* cfg,
    wired_span        path,
    u64               offset,
    wired_obuf*       body_out,
    const char**      content_type,
    int*              more,
    u64*              total_size) {
  char resolved[512];
  char reqpath[400];
  wired_span_to_cstr(reqpath, sizeof reqpath, path);
  if (!wired_staticfile_resolve(
          cfg->root, reqpath, cfg->index, resolved, sizeof resolved)) {
    return not_found(body_out);
  }
  if (offset == 0) {
    *content_type = wired_mimetype_for_path(resolved);
  }
  return serve_static_round(resolved, offset, body_out, more, total_size);
}
