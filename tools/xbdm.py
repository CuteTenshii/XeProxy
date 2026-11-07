#!/usr/bin/env python
"""xbdm.py - a small, readable client for the Xbox 360 debug monitor (XBDM).

XBDM is a line-based text protocol on TCP (this console: 192.168.50.30:730).
A command is one CRLF-terminated line; the reply starts with a 3-digit status:

    200  OK, single line
    201  greeting ("201- connected") sent once on connect
    202  multi-line text follows, terminated by a line containing only "."
    203  raw binary follows (length is command-specific)
    204  server expects binary FROM us
    205  connection is now dedicated / a notification channel
    4xx  error (405 no such thread, 407 unknown command, 408 not stopped, ...)

Args are `key=value`, space-separated; DWORDs are hex like 0x81955E38.

Use it as a library:

    from xbdm import Xbdm
    x = Xbdm()                       # connects, reads greeting
    print(x.getmem(0x81955E38, 16))  # -> bytes
    x.setmem(0x81955E38, "38600000")
    print(x.cmd("threads").lines)

...or from the shell (each action is one legible line, not a socket blob):

    python tools/xbdm.py getmem 0x81955E38 16
    python tools/xbdm.py setmem 0x81955E38 38600000
    python tools/xbdm.py words  0x81955E38 8          # decode as big-endian u32s
    python tools/xbdm.py cmd    "threads"
    python tools/xbdm.py context 0x12345678           # getcontext thread=...
    python tools/xbdm.py break   0x8195F4C0           # set exec breakpoint
    python tools/xbdm.py unbreak 0x8195F4C0
    python tools/xbdm.py notify                       # stream notifications

Override the target with --host/--port or env XBDM_HOST / XBDM_PORT.
"""

import os
import socket
import sys
import time

DEFAULT_HOST = os.environ.get("XBDM_HOST", "192.168.50.30")
DEFAULT_PORT = int(os.environ.get("XBDM_PORT", "730"))


class Reply:
    """One XBDM response: status code, message, and any follow-on lines/bytes."""
    def __init__(self, code, message, lines=None, data=b""):
        self.code = code
        self.message = message
        self.lines = lines or []      # for 202 multi-line replies
        self.data = data              # for 203 binary replies

    @property
    def ok(self):
        return 200 <= self.code < 300

    def __repr__(self):
        tail = ""
        if self.lines:
            tail = " +%d lines" % len(self.lines)
        elif self.data:
            tail = " +%d bytes" % len(self.data)
        return "<%d %s%s>" % (self.code, self.message, tail)


class XbdmError(Exception):
    pass


class Xbdm:
    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=5.0, connect=True):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self._buf = b""
        self.greeting = None
        if connect:
            self.connect()

    # --- connection / line plumbing ------------------------------------
    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.settimeout(self.timeout)
        self.greeting = self._readline()        # "201- connected"
        return self.greeting

    def close(self):
        if self.sock:
            try:
                self._send("bye")
            except Exception:
                pass
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    def _send(self, line):
        self.sock.sendall(line.encode("ascii") + b"\r\n")

    def _readline(self):
        while b"\r\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise XbdmError("connection closed")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\r\n", 1)
        return line.decode("ascii", "replace")

    def _readbytes(self, n):
        while len(self._buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise XbdmError("connection closed")
            self._buf += chunk
        data, self._buf = self._buf[:n], self._buf[n:]
        return data

    # --- core command ---------------------------------------------------
    def cmd(self, line, binary_len=None):
        """Send one command line and parse the reply (status + any body)."""
        self._send(line)
        status = self._readline()
        if len(status) < 3 or not status[:3].isdigit():
            raise XbdmError("bad status line: %r" % status)
        code = int(status[:3])
        message = status[5:] if len(status) > 5 else ""
        rep = Reply(code, message)
        if code == 202:                     # multi-line text until "."
            while True:
                ln = self._readline()
                if ln == ".":
                    break
                rep.lines.append(ln)
        elif code == 203 and binary_len:    # raw binary of known length
            rep.data = self._readbytes(binary_len)
        return rep

    # --- memory ---------------------------------------------------------
    def getmem(self, addr, length):
        """Read `length` bytes at `addr`. Returns bytes ('??' pages -> 0xFF)."""
        rep = self.cmd("getmem addr=0x%X length=0x%X" % (addr, length))
        if not rep.ok:
            raise XbdmError("getmem 0x%X: %d %s" % (addr, rep.code, rep.message))
        out = bytearray()
        for ln in rep.lines:
            ln = ln.strip()
            for i in range(0, len(ln), 2):
                pair = ln[i:i + 2]
                out.append(0xFF if pair == "??" else int(pair, 16))
        return bytes(out)

    def words(self, addr, count):
        """Read `count` big-endian u32s at `addr`. Returns list of ints."""
        raw = self.getmem(addr, count * 4)
        return [int.from_bytes(raw[i:i + 4], "big") for i in range(0, len(raw), 4)]

    def setmem(self, addr, data):
        """Write bytes at `addr`. `data` is a hex string or bytes."""
        if isinstance(data, (bytes, bytearray)):
            data = data.hex()
        data = data.replace(" ", "")
        rep = self.cmd("setmem addr=0x%X data=%s" % (addr, data))
        if not rep.ok:
            raise XbdmError("setmem 0x%X: %d %s" % (addr, rep.code, rep.message))
        return rep

    def setword(self, addr, value):
        """Write one big-endian u32."""
        return self.setmem(addr, "%08X" % (value & 0xFFFFFFFF))

    # --- threads / context ---------------------------------------------
    def threads(self):
        rep = self.cmd("threads")
        return [int(x.strip(), 0) for x in rep.lines if x.strip()]

    def getcontext(self, thread, flags="full"):
        rep = self.cmd("getcontext thread=0x%X %s" % (thread, flags))
        ctx = {}
        for ln in rep.lines:
            if "=" in ln:
                k, v = ln.split("=", 1)
                try:
                    ctx[k.strip()] = int(v.strip(), 0)
                except ValueError:
                    ctx[k.strip()] = v.strip()
        return ctx

    # --- breakpoints ----------------------------------------------------
    def set_break(self, addr):
        return self.cmd("break addr=0x%08X" % addr)

    def clear_break(self, addr):
        return self.cmd("break addr=0x%08X clear" % addr)

    # --- notification channel ------------------------------------------
    def open_notify(self, reconnectport=0):
        """Turn THIS connection into a notification channel (reply 205).
        Returns the reply; afterwards call read_notifications()/_readline()."""
        rep = self.cmd("notify reconnectport=%d" % reconnectport)
        return rep

    def read_notifications(self, seconds):
        """Yield notification lines for `seconds` (use after open_notify)."""
        end = time.time() + seconds
        self.sock.settimeout(1.0)
        while time.time() < end:
            try:
                yield self._readline()
            except socket.timeout:
                continue
            except XbdmError:
                break


# ------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------
def _p(x):
    print(x)


def main(argv):
    host, port = DEFAULT_HOST, DEFAULT_PORT
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--host":
            host = argv[i + 1]; i += 2; continue
        if a == "--port":
            port = int(argv[i + 1]); i += 2; continue
        args.append(a); i += 1

    if not args:
        _p(__doc__)
        return 1

    op, rest = args[0], args[1:]
    x = Xbdm(host, port)
    try:
        if op == "cmd":
            rep = x.cmd(rest[0])
            _p("%d %s" % (rep.code, rep.message))
            for ln in rep.lines:
                _p("  " + ln)
        elif op == "getmem":
            addr = int(rest[0], 0); length = int(rest[1], 0)
            _p(x.getmem(addr, length).hex())
        elif op == "words":
            addr = int(rest[0], 0); count = int(rest[1], 0)
            for j, w in enumerate(x.words(addr, count)):
                _p("0x%08X: %08X" % (addr + j * 4, w))
        elif op == "setmem":
            addr = int(rest[0], 0)
            _p(repr(x.setmem(addr, rest[1])))
        elif op == "context":
            thread = int(rest[0], 0)
            for k, v in x.getcontext(thread).items():
                _p("  %-8s = %s" % (k, ("0x%X" % v) if isinstance(v, int) else v))
        elif op == "threads":
            for t in x.threads():
                _p("thread 0x%X" % t)
        elif op == "break":
            _p(repr(x.set_break(int(rest[0], 0))))
        elif op == "unbreak":
            _p(repr(x.clear_break(int(rest[0], 0))))
        elif op == "notify":
            secs = int(rest[0]) if rest else 15
            rep = x.open_notify()
            _p("open_notify: %d %s" % (rep.code, rep.message))
            if rep.code == 205:
                _p("--- notifications for %ds ---" % secs)
                for ln in x.read_notifications(secs):
                    _p("  " + ln)
        else:
            _p("unknown op: %s" % op)
            return 2
    finally:
        x.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
