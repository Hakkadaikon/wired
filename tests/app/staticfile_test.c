#include "test.h"

/* Local nul-terminated string compare; src/ has no libc strcmp. */
static int staticfile_streq(const char* a, const char* b) {
  usz i = 0;
  for (; a[i] || b[i]; i++)
    if (a[i] != b[i]) return 0;
  return 1;
}

/* Static file serving: resolve an HTTP request path into a document-root
 * relative file path, rejecting path traversal. */
void test_staticfile(void) {
  char out[64];

  /* normal path */
  CHECK(wired_staticfile_resolve(
      "/root", "/foo.txt", "index.html", out, sizeof out));
  CHECK(staticfile_streq(out, "/root/foo.txt"));

  /* root path -> index */
  CHECK(wired_staticfile_resolve("/root", "/", "index.html", out, sizeof out));
  CHECK(staticfile_streq(out, "/root/index.html"));

  /* empty path -> index, same as root */
  CHECK(wired_staticfile_resolve("/root", "", "index.html", out, sizeof out));
  CHECK(staticfile_streq(out, "/root/index.html"));

  /* directory-looking path -> index appended */
  CHECK(wired_staticfile_resolve(
      "/root", "/sub/", "index.html", out, sizeof out));
  CHECK(staticfile_streq(out, "/root/sub/index.html"));

  /* traversal: leading ../ */
  CHECK(!wired_staticfile_resolve(
      "/root", "/../etc/passwd", "index.html", out, sizeof out));

  /* traversal: embedded ../../ */
  CHECK(!wired_staticfile_resolve(
      "/root", "/foo/../../etc/passwd", "index.html", out, sizeof out));

  /* traversal: trailing /.. */
  CHECK(!wired_staticfile_resolve(
      "/root", "/foo/..", "index.html", out, sizeof out));

  /* not a false positive: ".." as substring of a legit filename */
  CHECK(wired_staticfile_resolve(
      "/root", "/foo..bar.txt", "index.html", out, sizeof out));
  CHECK(staticfile_streq(out, "/root/foo..bar.txt"));

  /* overflow: output buffer too small must fail, not overrun */
  {
    char tiny[4];
    CHECK(!wired_staticfile_resolve(
        "/root", "/foo.txt", "index.html", tiny, sizeof tiny));
  }

  /* traversal detector as its own unit */
  CHECK(wired_staticfile_has_traversal("/../etc/passwd"));
  CHECK(wired_staticfile_has_traversal("/foo/../../etc/passwd"));
  CHECK(wired_staticfile_has_traversal("/foo/.."));
  CHECK(!wired_staticfile_has_traversal("/foo.txt"));
  CHECK(!wired_staticfile_has_traversal("/foo..bar.txt"));
  CHECK(!wired_staticfile_has_traversal("/"));
  CHECK(!wired_staticfile_has_traversal(""));
}
