"""Reachability check for closed vuln-ledger rows (issue #173).

A `fixed` / `already-safe` row is only as good as its pointers: the cited
code must be on the production path (examples/ -> srvrun / srvloop / sdrv /
moqtrun) and the cited test must be wired into tests/run.c and reach the
cited code. This module builds a textual call graph of the C tree (every
top-level definition -> the identifiers its body uses, macros and
initializer tables included) and walks it forward from the roots.

shortcut: names are global (two `static put` helpers merge into one node),
so the closure over-approximates; an "unreachable" finding is reliable, a
"reachable" one is not a proof. Upgrade to a clang call graph if that bites.
"""

import glob
import os
import pathlib
import re

_ATTR = re.compile(r"__attribute__\s*\(\((?:[^()]|\([^()]*\))*\)\)")
_COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
_STRING = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'')
_PREPRO = re.compile(r"^[ \t]*#(?:[^\n]*\\\n)*[^\n]*", re.M)
_DEFINE = re.compile(r"#\s*define\s+(\w+)(.*)", re.S)
_IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
_CHUNK = re.compile(r"[{};]")
_FUNC_NAME = re.compile(r"(\w+)\s*\($")
_PATH = re.compile(r"[\w./-]+\.[ch]\b")
_SYMBOL = re.compile(r"\b[A-Za-z]\w*_\w+\b")


def strip(text):
    return _ATTR.sub(" ", _STRING.sub('""', _COMMENT.sub(" ", text)))


def _defname(head):
    """The name a top-level chunk defines: the function before its `(`,
    else the last identifier before `=` / `[` (a variable or table)."""
    head = head.split("=")[0]
    return _func_name(head) if "(" in head else _last_ident(head)


def _func_name(head):
    m = _FUNC_NAME.search(head[: head.index("(") + 1])
    return m.group(1) if m else ""


def _last_ident(head):
    names = _IDENT.findall(head.split("[")[0])
    return names[-1] if names else ""


def _chunks(code):
    """Top-level chunks: split where the brace depth returns to 0."""
    out, depth, start = [], 0, 0
    for m in _CHUNK.finditer(code):
        depth += {"{": 1, "}": -1, ";": 0}[m.group()]
        start = _close(out, code, start, m, depth)
    return out


def _close(out, code, start, m, depth):
    if depth or m.group() == "{":
        return start
    out.append(code[start : m.end()])
    return m.end()


def _add(graph, name, body):
    graph.setdefault(name, set()).update(_IDENT.findall(body))


def _add_chunk(graph, chunk):
    head = chunk.split("{")[0]
    _add(graph, _defname(head), chunk[len(head) :] + head.split("=", 1)[-1])


def _add_macros(graph, code):
    for line in _PREPRO.findall(code):
        _add_define(graph, _DEFINE.match(line.strip()))


def _add_define(graph, m):
    if m:
        _add(graph, m.group(1), m.group(2))


def file_graph(text, graph):
    code = strip(text)
    _add_macros(graph, code)
    for chunk in _chunks(_PREPRO.sub(" ", code)):
        _add_chunk(graph, chunk)
    graph.pop("", None)
    return graph


def build(paths):
    graph, defined = {}, {}
    for p in paths:
        g = file_graph(
            pathlib.Path(p).read_text(encoding="utf-8", errors="replace"), {}
        )
        defined.update(dict.fromkeys(g, p))
        for k, v in g.items():
            graph.setdefault(k, set()).update(v)
    return graph, defined


def closure(graph, roots):
    seen, todo = set(), list(roots)
    while todo:
        todo += _visit(graph, seen, todo.pop())
    return seen


def _visit(graph, seen, name):
    if name in seen or name not in graph:
        return []
    seen.add(name)
    return list(graph[name] - seen)


def _sources(*globs):
    return sorted(p for g in globs for p in glob.glob(g, recursive=True))


class Tree:
    """Production and test graphs of the C tree under `root`."""

    def __init__(self, root="."):
        old = os.getcwd()
        os.chdir(root)
        try:
            self._load()
        finally:
            os.chdir(old)

    def _load(self):
        src = _sources("src/**/*.c", "src/**/*.h")
        ex = _sources("examples/**/*.c", "examples/**/*.h")
        self.prod, self.defined = build(src + ex)
        self.files = src + ex + _sources("tests/**/*.c", "tests/**/*.h")
        # identifiers used anywhere (struct fields, constants) and path parts
        # (`moqt_chat`) are not dead pointers even though they define nothing
        self.words = set(self.prod).union(*self.prod.values(), _path_words(self.files))
        self.live = closure(self.prod, build(ex)[0])
        self.test, self.test_defined = build(
            src + _sources("tests/**/*.c", "tests/**/*.h")
        )
        self.wired = closure(self.test, build(_sources("tests/run.c"))[0])
        self._reach = {}

    def reaches(self, test):
        if test not in self._reach:
            self._reach[test] = closure(self.test, [test])
        return self._reach[test]


def _path_words(files):
    return {w for f in files for w in re.split(r"[/.]", f)}


def cited(text):
    """(paths, symbols) named in an `Our code` cell."""
    paths = _PATH.findall(text)
    rest = _PATH.sub(" ", text)
    return paths, _SYMBOL.findall(rest)


def _exists(tree, path):
    """A cited path may be repo-relative or a unique-enough tail
    (`srvloop/dispatch_max.c`, `srvrun_dcid.c`)."""
    return any(f == path or f.endswith("/" + path) for f in tree.files)


def _flag(msg, items, pred):
    return [f"{msg}: {x}" for x in items if pred(x)]


def _code_errors(tree, paths, symbols):
    return (
        _flag("cited file missing", paths, lambda p: not _exists(tree, p))
        + _flag("unknown symbol", symbols, lambda s: s not in tree.words)
        + _flag("not on production path", symbols, lambda s: _dead(tree, s))
    )


def _dead(tree, s):
    return s in tree.defined and s not in tree.live


def _test_errors(tree, tests, symbols):
    live = set(symbols) & tree.live
    return _flag(
        "test not wired into tests/run.c", tests, lambda t: t not in tree.wired
    ) + _flag("test does not reach cited code", tests, lambda t: _misses(tree, t, live))


def _misses(tree, test, live):
    return bool(live) and test in tree.wired and not live & tree.reaches(test)


def _closed(row):
    return row["status"] == "done" and row["verdict"] in ("fixed", "already-safe")


def row_errors(tree, row):
    if not _closed(row):
        return []
    paths, symbols = cited(row["ours"])
    tests = re.findall(r"\btest_\w+", row["test"])
    bad = _code_errors(tree, paths, symbols) + _test_errors(tree, tests, symbols)
    return [f"{row['id']}: {b}" for b in bad]


def check(rows, root="."):
    tree = Tree(root)
    return [e for r in rows for e in row_errors(tree, r)]
