"""Struct parsing and rule 1 of viewcheck.py: which structs are stored
(reachable from ROOTS) and whether every view member names its storage."""

import re

ROOTS = (
    "wired_srvrun_env",
    "wired_moqt_hub",
    "wired_server",
    "sdrv",
    "srvrun_cfg",
    "wired_srvrun_opt",
)
CLASSES = {"static", "env", "slot", "own", "caller"}
OPEN = re.compile(r"^(?:typedef\s+)?(?:struct|union)(?:\s+(\w+))?\s*\{")
CLOSE = re.compile(r"^\}\s*(\w*)\s*;")
VIEW = re.compile(
    r"^\s+(?:const\s+)?(?:wired_span|wired_mspan|(?:const\s+)?"
    r"(?:u8|char|i8)\s*\*)\s*[\w\s*]*?\b(\w+)\s*(?:\[[^\]]*\])?\s*;"
)
FIELD = re.compile(r"^\s+(?:const\s+)?(?:struct\s+)?(\w+)(?:\s*\*+\s*|\s+)(\w+)")
TAG = re.compile(r"views:(.*)$", re.S)
ENTRY = re.compile(r"(\w+)\s*=\s*([a-z|]+)")
COMMENT = re.compile(r"^\s*(?:/\*|\*|//)")


def comment_block(lines, start):
    """The comment lines right above line start, nearest first."""
    i = start - 1
    while i >= 0 and COMMENT.match(lines[i]):
        yield lines[i]
        i -= 1


def tag_of(lines, start):
    """member -> storage classes from the `views:` part of the comment block
    right above line start (empty when there is none)."""
    block = " ".join(reversed([strip(x) for x in comment_block(lines, start)]))
    m = TAG.search(block)
    return entries(m.group(1)) if m else {}


def strip(line):
    return line.strip().lstrip("/*").rstrip("*/").strip()


def entries(text):
    return {n: set(c.split("|")) for n, c in ENTRY.findall(text)}


def member(rec, line):
    """Record one struct body line: a view member or a named field."""
    m = VIEW.match(line)
    if m:
        rec["views"].append(m.group(1))
        return
    field(rec, FIELD.match(line))


def field(rec, f):
    if f:
        rec["types"].add(f.group(1))
        rec["fields"][f.group(2)] = f.group(1)


def close(rec, line, out):
    """1 when line ends rec's body (rec then lands in out by name)."""
    m = CLOSE.match(line)
    if not m:
        return 0
    out[m.group(1) or rec["name"]] = rec
    return 1


def structs(path, text):
    """Every struct/union in one header: name -> views, fields, tag."""
    st = {"out": {}, "rec": None, "lines": text.split("\n"), "path": path}
    for i, line in enumerate(st["lines"]):
        step(st, i, line)
    return st["out"]


def step(st, i, line):
    o = OPEN.match(line)
    if o:
        name = o.group(1) or ""
        st["rec"] = new_rec(st["path"], i, name, tag_of(st["lines"], i))
        return
    body_line(st, line)


def body_line(st, line):
    rec = st["rec"]
    if rec is None:
        return
    st["rec"] = None if close(rec, line, st["out"]) else feed(rec, line)


def new_rec(path, i, name, tag):
    return {
        "path": path,
        "line": i + 1,
        "name": name,
        "tag": tag,
        "views": [],
        "types": set(),
        "fields": {},
    }


def feed(rec, line):
    member(rec, line)
    return rec


def reachable(table):
    """Names of the structs reachable from ROOTS through member types."""
    seen, todo = set(), known(table, ROOTS)
    while todo:
        visit(table, seen, todo, todo.pop())
    return seen


def known(table, names):
    return [t for t in names if t in table]


def visit(table, seen, todo, name):
    if name in seen:
        return
    seen.add(name)
    todo.extend(known(table, table[name]["types"]))


def tag_errors(table, live):
    """Rule 1 over every stored struct that has views."""
    return [untagged(table[n], n) for n in sorted(live) if needs_tag(table[n])]


def needs_tag(rec):
    return bool(missing(rec) or stale(rec))


def untagged(rec, name):
    return (
        f"{rec['path']}:{rec['line']}: {name}: views without a `views: "
        f"member=class` storage class ({'/'.join(sorted(CLASSES))}): "
        f"{', '.join(missing(rec)) or '-'}; entries naming no view member: "
        f"{', '.join(stale(rec)) or '-'}"
    )


def stale(rec):
    """Tag entries left behind by a renamed or removed view member."""
    return sorted(set(rec["tag"]) - set(rec["views"]))


def missing(rec):
    return [v for v in rec["views"] if not class_ok(rec["tag"].get(v))]


def class_ok(tag):
    return bool(tag) and tag <= CLASSES
