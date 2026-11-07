#!/usr/bin/env python
"""Non-halting breakpoint tracer for the XHttp cert path.

Sets execution breakpoints on a set of addresses, opens the XBDM notification
channel, and counts how often each fires AND on which thread, over a window.
It also learns netprobe's thread id from its "[netprobe ...]" debugstr lines,
so we can tell the cert path (netprobe thread) from background noise.

Usage:
  python docs/research/cert-trust/trace.py <seconds> <addr> [addr ...]
  python docs/research/cert-trust/trace.py <seconds> --slice <start> <count>   # from entries file
  python docs/research/cert-trust/trace.py <seconds> --all                     # all entries

NEVER uses stopon (that suspends threads). Breakpoints are notify-only.
"""
import os, re, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools"))
import xbdm

ENTRIES = os.path.join(os.path.dirname(__file__), "cert-cluster-entries.txt")
RESULTS = os.path.join(os.path.dirname(__file__), "trace-results.md")


def load_entries():
    out = []
    for line in open(ENTRIES):
        line = line.strip()
        if line.startswith("0x"):
            out.append(int(line, 16))
    return out


def trace(addrs, seconds):
    cmd = xbdm.Xbdm()
    nf = xbdm.Xbdm()
    for a in addrs:
        cmd.set_break(a)
    nf.open_notify()
    hits = {}                    # (addr, thread) -> count
    netprobe_thread = None
    bp = re.compile(r"break addr=0x([0-9a-f]+) thread=0x([0-9a-f]+)")
    ds = re.compile(r"\[netprobe .*?\].*thread=0x([0-9a-f]+)")
    # also handle "debugstr thread=0xXXXX ... string=[netprobe"
    ds2 = re.compile(r"thread=0x([0-9a-f]+).*\[netprobe")
    try:
        for ln in nf.read_notifications(seconds):
            m = bp.search(ln)
            if m:
                key = (int(m.group(1), 16), m.group(2))
                hits[key] = hits.get(key, 0) + 1
                continue
            m = ds2.search(ln)
            if m and netprobe_thread is None:
                netprobe_thread = m.group(1)
    finally:
        for a in addrs:
            cmd.clear_break(a)
        cmd.close()
        nf.close()
    return hits, netprobe_thread


def main(argv):
    seconds = int(argv[0])
    rest = argv[1:]
    if rest and rest[0] == "--all":
        addrs = load_entries()
    elif rest and rest[0] == "--slice":
        start, count = int(rest[1]), int(rest[2])
        addrs = load_entries()[start:start + count]
    else:
        addrs = [int(a, 16) for a in rest]

    print("tracing %d breakpoints for %ds (non-halting)..." % (len(addrs), seconds))
    hits, npt = trace(addrs, seconds)
    print("netprobe thread:", ("0x" + npt) if npt else "(not seen this window)")

    # collapse per-addr, split netprobe vs other threads
    rows = []
    addrset = set(addrs)
    byaddr = {}
    for (addr, thr), n in hits.items():
        d = byaddr.setdefault(addr, {})
        d[thr] = d.get(thr, 0) + n
    for addr in addrs:
        d = byaddr.get(addr, {})
        np_hits = d.get(npt, 0) if npt else 0
        other = sum(v for t, v in d.items() if t != npt)
        if d:
            rows.append((addr, np_hits, other, d))

    rows.sort(key=lambda r: (-r[1], -r[2]))
    print("\n addr          netprobe  other   (threads)")
    for addr, np_hits, other, d in rows:
        tinfo = " ".join("%s:%d" % (t, v) for t, v in sorted(d.items(), key=lambda kv: -kv[1]))
        print("  0x%08X  %6d  %6d   %s" % (addr, np_hits, other, tinfo))

    # the interesting ones: fire on netprobe's thread
    on_path = [addr for addr, np_hits, other, d in rows if np_hits > 0]
    print("\nON netprobe thread (%d): %s" % (len(on_path), " ".join("0x%08X" % a for a in on_path)))

    with open(RESULTS, "a") as f:
        f.write("\n## trace %s  (%ds, %d bps, netprobe=%s)\n" %
                (time.strftime("%H:%M:%S"), seconds, len(addrs), ("0x" + npt) if npt else "?"))
        for addr in on_path:
            f.write("- 0x%08X  netprobe-hits=%d\n" % (addr, byaddr[addr].get(npt, 0)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
