"""Check that stored views point into storage that outlives them (issue #183).

Usage: viewcheck.py

A view is a struct member of type wired_span / wired_mspan or a borrowed
byte or string pointer (u8*, char*); an opaque callback context (void*) is
the application's object, not a view of bytes. A view is *stored* when its
struct is reachable from the SDK's long-lived state (ROOTS in
viewcheck_structs.py: the per-worker env, the run's cfg and opt, the MoQT
hub, a connection's server and TLS driver). Two rules:

1. Every view member of such a struct names its storage class in the
   comment block right above the struct, as its last part:
   `views: <member>=<class>[|<class>...], ...` with each class one of static
   (string literals, const tables), env (the SDK's own env tables), slot
   (another member of the same struct, connection or stream slot), own (an
   SDK-owned copy made at start) or caller (memory the application keeps
   alive under a lifetime its API documents). Any other struct is
   call-scoped: an argument, cursor or frame whose views live only as long
   as its caller.
2. No function assigns a function-local array, or a view of one, into a
   stored view member: `x->m = buf`, `x.m = wired_span_of(buf, n)`, where
   x is declared (in the same file, or as a struct field) with a stored
   struct type. A line that must do so on purpose ends with the comment
   `view-ok: <reason>`.

Rule 2 is a grep-level net, not a proof: it does not follow a local array
through another variable (`p = buf; x->m = p`), a compound literal
(`*x = (T){buf, n}`), `&buf[0]`, or a function argument that stores it
(`sdrv_init(&d, local_der)`). Clang covers part of that: with the pinned
clang, wired_span_of/wired_mspan_of are lifetimebound, so returning a view
of a local array is an error (-Wreturn-stack-address, on by default).
"""

import pathlib
import re
import sys

from viewcheck_structs import reachable, structs, tag_errors

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCAL = re.compile(
    r"^\s+(?!static\b|extern\b|return\b|else\b|do\b|case\b)(?:const\s+)?\w+[\w\s*]*?\b\w+\s*\["
)
NAMES = re.compile(r"\b(\w+)\s*\[[^\]]+\]")
LITERAL = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
END = re.compile(r"^\s*$|^\}|.*[;}]\s*$")
ASSIGN = re.compile(r"(\w+)(?:\[[^\]]*\])*(?:\.|->)(\w+)\s*=(?!=)\s*([^;]*);")


def field_types(table):
    """Every struct field name -> its type name (a base the file does not
    declare resolves through it)."""
    return {n: t for rec in table.values() for n, t in rec["fields"].items()}


def decl_type(text, name, fields):
    """The type the file declares name with, else its struct field type."""
    m = re.search(
        rf"\b(?!return\b|const\b|struct\b|sizeof\b)(\w+)\s*\*?\s*(?:const\s+)?"
        rf"\b{name}\b\s*[;,)=\[]",
        text,
    )
    return m.group(1) if m else fields.get(name)


def target(ctx, base, mem):
    """1 when base.mem is a view member of a stored struct."""
    t = decl_type(ctx["body"], base, {}) or decl_type(ctx["text"], base, ctx["fields"])
    return t in ctx["live"] and mem in ctx["table"][t]["views"]


def locals_in(body):
    """Names of the non-static arrays declared in one function body."""
    return {n for line in filter(LOCAL.match, body) for n in NAMES.findall(line)}


def assign_errors(ctx, body, first):
    """Rule 2 over one function body starting at line number first."""
    errs, local = [], locals_in(body)
    fctx = dict(ctx, body="\n".join(signature(ctx["lines"], first) + body))
    for k, line in enumerate(body):
        errs += [
            f"{ctx['path']}:{first + k}: stored view `{m}` set from local array `{a}`"
            for m, a in hits(fctx, line, local)
        ]
    return errs


def signature(lines, first):
    """The lines of a multi-line parameter list above the body's `{` line
    (first is 1-based), back to a blank or a closing line."""
    i = first - 1
    while i > 0 and head_line(lines[i - 1]):
        i -= 1
    return lines[i : first - 1]


def head_line(line):
    """A line that can still belong to a parameter list: not blank, not a
    closing brace, not the end of a statement or of a previous body."""
    return END.match(line) is None


def hits(ctx, line, local):
    """(member, local) pairs line assigns, unless it says view-ok."""
    return [] if "view-ok:" in line else assigned_locals(ctx, line, local)


def assigned_locals(ctx, line, local):
    return [
        (m.group(2), a)
        for m in stored_assigns(ctx, line)
        for a in uses(m.group(3), local)
    ]


def stored_assigns(ctx, line):
    return [m for m in ASSIGN.finditer(line) if target(ctx, m.group(1), m.group(2))]


def uses(rhs, local):
    """The local arrays rhs refers to as a whole (not one element)."""
    return [a for a in local if re.search(rf"\b{a}\b(?!\s*\[)", rhs)]


def functions(text):
    """(first line number, body lines) of every top-level brace block."""
    out, depth = [], 0
    for i, line in enumerate(text.split("\n")):
        code = LITERAL.sub('""', line)
        opened = depth == 0 and "{" in code
        depth += code.count("{") - code.count("}")
        add_line(out, i, line, opened)
    return out


def add_line(out, i, line, opened):
    if opened:
        out.append((i + 1, []))
    if out:
        out[-1][1].append(line)


def check(headers, sources):
    """All rule violations over (path, text) headers and sources."""
    table = header_table(headers)
    live = reachable(table)
    base = {"table": table, "live": live, "fields": field_types(table)}
    return tag_errors(table, live) + source_errors(base, sources)


def header_table(headers):
    table = {}
    for path, text in headers:
        table.update(structs(path, text))
    return table


def source_errors(base, sources):
    return [
        e
        for path, text in sources
        for e in file_errors(dict(base, path=path, text=text, lines=text.split("\n")))
    ]


def file_errors(ctx):
    return [
        e
        for first, body in functions(ctx["text"])
        for e in assign_errors(ctx, body, first)
    ]


def read(pattern):
    src = ROOT / "src"
    return [
        (str(p.relative_to(ROOT)), p.read_text(errors="replace"))
        for p in sorted(src.rglob(pattern))
    ]


def main():
    headers = read("*.h")
    errs = check(headers, read("*.c") + headers)
    print("\n".join(errs) or "viewcheck: every stored view has a storage class")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
