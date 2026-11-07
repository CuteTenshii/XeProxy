#!/usr/bin/env python3
"""Turns xeproxy.ini into src/default_ini.h, the copy the plugin writes for
itself when it cannot find one on the console.

The reference ini is the only source of truth: edit it and re-run this. Both
build scripts run it when python is on PATH, and fall back to the committed
header when it is not, so a build never silently uses a stale default - it
either regenerates or keeps what was committed.

Usage:  python tools/mkdefaults.py [--check]

--check exits non-zero if the committed header does not match the ini, which
is what CI (or a suspicious human) wants.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, "xeproxy.ini")
DST = os.path.join(ROOT, "src", "default_ini.h")

# The generated default must not come up live: see the comment on `enabled` in
# xeproxy.ini. A build that would have shipped an enabled one is a bug, so it
# fails here rather than on someone's console.
REQUIRED = "enabled = 0"

MAX_LINE = 240          # must stay under the C string literal the table holds


def c_escape(line):
    out = []
    for ch in line:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "?":
            out.append("?")         # trigraphs need two ?? to matter; harmless
        elif " " <= ch <= "~":
            out.append(ch)
        else:
            raise SystemExit(
                "error: xeproxy.ini has a non-ASCII or control byte "
                "(%r) in: %s" % (ch, line)
            )
        if len(out) > MAX_LINE * 2:
            raise SystemExit("error: line too long to embed: %s" % line)
    return "".join(out)


def generate():
    with open(SRC, "rb") as f:
        raw = f.read()

    if b"\r" in raw:
        raise SystemExit("error: %s has CRLF endings; keep it LF" % SRC)

    text = raw.decode("ascii")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()                 # trailing newline, not a trailing line

    if not any(l.strip() == REQUIRED for l in lines):
        raise SystemExit(
            "error: %s does not contain a bare '%s' line.\n"
            "The config the plugin writes for itself must be inert; refusing "
            "to generate one that patches xam on first boot." % (SRC, REQUIRED)
        )

    for i, l in enumerate(lines):
        if len(l) > MAX_LINE:
            raise SystemExit("error: %s:%d is %d chars, max %d"
                             % (SRC, i + 1, len(l), MAX_LINE))

    body = [
        "// default_ini.h - GENERATED FILE, do not edit.",
        "//",
        "// Produced from xeproxy.ini by tools/mkdefaults.py. Edit the ini and",
        "// re-run the generator; build.sh and build.bat do it for you when python",
        "// is on PATH.",
        "//",
        "// %d lines, %d bytes of source." % (len(lines), len(raw)),
        "",
        "#ifndef XEP_DEFAULT_INI_H",
        "#define XEP_DEFAULT_INI_H",
        "",
        "static const char *const kDefaultIni[] = {",
    ]
    for l in lines:
        body.append('    "%s",' % c_escape(l))
    # The plugin writes CRLF, so the file it produces is one byte per line
    # longer than the source. It then has to be able to read it back, so this
    # count is asserted against INI_MAX_BYTES at compile time.
    crlf_bytes = sum(len(l) + 2 for l in lines)

    body += [
        "};",
        "",
        "#define XEP_DEFAULT_INI_LINES "
        "((int)(sizeof(kDefaultIni) / sizeof(kDefaultIni[0])))",
        "",
        "// Size of what the plugin writes, CRLF endings included.",
        "#define XEP_DEFAULT_INI_BYTES %d" % crlf_bytes,
        "",
        "#endif // XEP_DEFAULT_INI_H",
        "",
    ]
    return "\n".join(body)


def main():
    want = generate()
    check = "--check" in sys.argv[1:]

    have = None
    if os.path.exists(DST):
        with open(DST, "r", newline="") as f:
            have = f.read()

    if have == want:
        if not check:
            print("mkdefaults: src/default_ini.h is up to date")
        return 0

    if check:
        sys.stderr.write("error: src/default_ini.h is stale; run "
                         "python tools/mkdefaults.py\n")
        return 1

    with open(DST, "w", newline="\n") as f:
        f.write(want)
    print("mkdefaults: wrote src/default_ini.h")
    return 0


if __name__ == "__main__":
    sys.exit(main())
