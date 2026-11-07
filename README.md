# XeProxy

A DashLaunch plugin for the Xbox 360 that hooks xam.xex's `NetDll_*` exports -
the XNet and Winsock layer every title, the dashboard and xbdm go through - so
console traffic can be pointed somewhere other than Xbox Live. DNS answers,
TCP/UDP destinations and `XHttpConnect` targets are all rewritten from an ini
file that the plugin re-reads whenever it changes.

Nothing is baked into the xex. One build, and a text file decides where traffic
goes.

Tested working on a console running the latest Xbox 360 dashboard (17559).

## What it can do

| | |
|---|---|
| Answer DNS itself | `*.xboxlive.com = 192.168.1.50`, no resolver involved |
| Rewrite destinations | per address, CIDR block and/or port, for TCP and UDP |
| SOCKS5 | `CONNECT` through a proxy, performed inside the hooked `connect()` |
| Drop traffic | make a send look like it succeeded and send nothing |
| Rewrite XHttp | `XHttpConnect`'s server name and port, for the Live services that use it |
| Force `XNetStartup` flags | notably `XNET_STARTUP_BYPASS_SECURITY`, so traffic is plain |
| Undo the rewrite on the way back | replies from the proxy are handed to the title as if they came from the address it asked for |
| Trace | one log line per intercepted call, when you need to see what a title does |
| MITM TLS | a one-instruction xam fix so XHttp completes a handshake with a proxy's certificate |

## Install

1. Build `XeProxy.xex` (below), or drop in a prebuilt one.
2. Copy `XeProxy.xex` to the console, and `xeproxy.ini` next to it if you
   have one ready. The ini is looked for at, in order:

   ```
   Usb0:\xeproxy.ini   Usb1:\xeproxy.ini   Usb2:\xeproxy.ini
   Hdd:\xeproxy.ini    Hdd:\plugins\xeproxy.ini
   Flash:\xeproxy.ini  Game:\xeproxy.ini
   ```

   If none of them exists, the plugin writes one itself - the annotated
   reference config, verbatim, with a header saying where it came from - to
   `Hdd:\xeproxy.ini`, or to the first USB stick it can write to. A toast
   names the file. So the first boot gives you something real to edit instead
   of settings you cannot see, and nothing is patched on that boot because
   what it writes has `enabled = 0`.

3. Add the xex to `launch.ini`:

   ```ini
   [Plugins]
   plugin1 = Hdd:\XeProxy.xex
   plugin2 = Hdd:\xbdm.xex
   ```

   Put it early. A plugin that opens sockets before this one loads will have
   already called `XNetStartup` with its own flags.

4. Reboot. The plugin logs what it did; read the log to confirm. Its first lines
   say which ini was found, which exports resolved, which hooks went in, and
   whether the TLS fix was applied:

   ```
   XeProxy 1.0 starting, image at ~91E80000
   XeProxy: 9 hooks, 3 rules, log on Hdd:
   ```

   Everything also goes out over `OutputDebugString`, so you can watch it live
   over xbdm even when no log file can be written (see Troubleshooting).

Hot reload is off by default (`config_reload_seconds = 0`), so the ini is read
once at boot and the plugin runs silently. Set `config_reload_seconds` to a
nonzero number of seconds to have edits applied live without a reboot - that
also turns the log on, since logging is coupled to it (off when reload is off).
`[hooks]` and `[ordinals]` are always read once at boot.

## Configuring it

`xeproxy.ini` in this repo is the reference: every key is documented inline
next to a commented-out example. The shape of it:

```ini
[general]     log path, log level, reload interval, a few global switches
[xnetstartup] what to force into XNetStartup's parameters
[proxy]       the default upstream, so rules can just say "proxy"
[dns]         hostname pattern = address
[redirect]    address[/bits][:port] = address[:port][, mode]
[xhttp]       hostname pattern = host[:port]
[hooks]       which xam exports to patch (boot only)
[ordinals]    override an export ordinal (boot only)
```

A worked example - send everything Xbox Live to a server at 192.168.1.50 and
watch what happens:

```ini
[general]
log_level = 3

[proxy]
host = 192.168.1.50
port = 3074

[dns]
*.xboxlive.com = 192.168.1.50

[redirect]
*:3074 = proxy
```

Through mitmproxy in its default (regular) mode, `mode = http` makes each
redirected `connect()` open a `CONNECT ip:port` tunnel, the same request an
HTTP-proxy-aware client sends:

```ini
[proxy]
host = 192.168.1.50
port = 8080
mode = http

[redirect]
* = proxy
```

And the same traffic through a SOCKS5 proxy instead:

```ini
[proxy]
host = 192.168.1.50
port = 1080
mode = socks5

[redirect]
*:80  = proxy
*:443 = proxy
```

## How it works

`NetDll_socket`, `NetDll_connect`, `NetDll_XNetDnsLookup` and the rest are
ordinary exports of `xam.xex`; the XDK's `xnet.lib` wrappers only hide the
leading `XNCALLER_TYPE` argument. Hooking them inside xam catches every caller
at once, including titles launched long after the plugin loaded.

At boot the worker thread:

1. Recreates the `Hdd:` / `Usb0:` / `Flash:` links, since a plugin can load
   before xam has published them, then waits for the ini to appear.
2. Resolves each export with `XexGetModuleHandle("xam.xex", ...)` and
   `XexGetProcedureAddress(..., ordinal, ...)`.
3. Allocates a trampoline pool and **proves it is executable** by running two
   instructions out of it under SEH before installing anything. Physical
   memory is tried first, the plugin's own image data second.
4. **Assembles its own cache-flush routine** into that pool. Patching code on
   this CPU means `dcbst` to push the line out of the data cache and `icbi` to
   invalidate the matching instruction cache line, but the XDK's
   `ppcintrinsics.h` has no `__icbi` and no `__isync`, and `icbi` needs its
   address in a register no intrinsic lets you name. Eight words of hand-
   assembled PowerPC in the pool solve that; until it is in place the only
   thing flushed is the one page the CPU has never executed from, where
   `dcbst`/`sync`/`isync` is enough.
5. Detours each enabled export: four instructions at the function's entry
   (`lis`/`addi`/`mtctr`/`bctr` through r11, which is volatile at a call
   boundary) jump to the hook, and the instructions they displaced are
   relocated into the trampoline followed by a jump back. A relative branch in
   a prologue is re-encoded for its new address; one that will not reach makes
   the hook refuse itself rather than corrupt xam.
6. Applies the TLS handshake fix when `tls_ignore_cert_errors = 1` - one xam
   instruction so XHttp completes a handshake with a proxy's certificate (see
   "TLS for MITM").
7. Stays resident, re-reading the ini when its size or write time changes.
   Parsing goes into whichever of two config buffers is not live, and the live
   pointer is then flipped, so a hook that is already running finishes against
   a coherent snapshot.

Every hook is transparent when no rule matches: it calls the trampoline with
the arguments it was handed and returns the result unchanged. With an empty ini
the console behaves as though the plugin were not loaded.

### Why `bypass_security` matters

Xbox Live traffic normally rides the secure-socket layer: addresses are
`XNADDR`s resolved against Microsoft's security gateway, and payloads are
encrypted with keys the console gets from Live. A proxy in the middle sees
nothing it can route. `XNET_STARTUP_BYPASS_SECURITY` (bit 0 of
`XNetStartupParams.cfgFlags`) turns that off, which is why it is forced by
default.

One caveat, in the XDK's own words: that flag is "devkit-only" and is
"silently ignored by the secure versions of the library", in which case
"attempts to send or receive packets from untrusted hosts will fail". On a
retail console running a retail xam it may do nothing - setting it costs
nothing and it is the right flag on a devkit xam, but if proxied peer traffic
is being dropped and the log shows the flag going in, that is the reason, not
a bug in the redirect rules. `map_xnaddr_to_ina` is the fallback that does not
depend on it: it answers `XNetXnAddrToInAddr` with the peer's plain address
whenever secure registration fails. `XNET_STARTUP_DISABLE_PEER_ENCRYPTION`
(0x08) is also available through `force_flags` and is worth trying alongside
it.

### TLS for MITM

`tls_ignore_cert_errors = 1` makes xam's XHttp complete a TLS handshake with a
certificate the console would normally reject, so an intercepting proxy
(mitmproxy etc.) can read the console's own HTTPS. The console already accepts
the proxy's leaf - its XHttp cert check is essentially a hostname match - so the
real blocker is a xam bug: after the Certificate message the TLS state machine is
left in a state with no handler for the ServerHelloDone that follows, and the
handshake silently stalls. The fix is one instruction in xam that selects the
working state. It is applied once at startup, refuses itself unless the live
bytes match (so a different xam build is never corrupted), and affects every
XHttp TLS handshake system-wide - so pair it with a proxy that relays to the
real servers.

## Limits worth knowing before you debug something

- **Overlapped UDP receives.** `WSARecvFrom` with an `OVERLAPPED` writes the
  source address after the call returns, so the address rewrite cannot be
  undone for it. Synchronous `recvfrom` and `WSARecvFrom` are handled. A title
  that uses overlapped receives *and* validates source addresses will drop
  proxied datagrams.
- **`forward_lan = 0` beats every rule.** With it off, a destination in
  10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, multicast or broadcast is
  never redirected, dropped or tunnelled, even by a rule that names it
  explicitly - use it to put a catch-all `* = proxy` in front of a console
  whose LAN traffic (system link, local servers) should stay local. XHttp
  hostnames can't be judged until they resolve, so for those it is the
  `connect` hook that keeps the LAN address local.
- **xbdm is invisible to every hook.** Its own sockets are neither redirected
  nor logged: logging them would loop, because each log line goes out through
  `OutputDebugString`, which xbdm sends over those same sockets.
- **SOCKS5 and HTTP CONNECT need blocking sockets, and carry TCP only.** The handshake runs inside `connect()`. A
  title that set `FIONBIO` first gets `WSAEWOULDBLOCK` out of the first
  recv; the plugin logs that and fails the connect rather than leave half a
  handshake in the stream. SOCKS5 UDP `ASSOCIATE` is not implemented - a
  socks5 rule that matches a datagram passes it through untouched and says so
  in the log.
- **Reverse mapping is per socket, most-recent-wins.** Several destinations
  behind one proxy endpoint on one socket are genuinely ambiguous on the way
  back. With `closesocket = 0` in `[hooks]` (the default) stale entries are
  only evicted by LRU; turn it on if a title churns sockets.
- **`XNetStartup` is only patched for callers that come after the hooks.** xam
  starts its own network context very early in boot, possibly before the
  plugin is loaded. Titles, which call it on launch, are always covered.
- **Hooks go in once.** Changing `[hooks]` or `[ordinals]` needs a reboot;
  nothing is ever unhooked.
- **`force_connect_status`, `bypass_qos` and `map_xnaddr_to_ina` each need
  their hook enabled** in `[hooks]` - the switch alone does nothing. The ini
  says which.

## Build

You need an Xbox 360 XDK with the PowerPC `cl.exe`, `include/xbox` and
`lib/xbox`. 21256 is the usual one, and the scripts default to
`C:\Program Files (x86)\Microsoft Xbox 360 SDK`.

```bash
./build.sh                  # git bash / msys
```

```bat
build.bat                   :: cmd
```

Both produce `build/XeProxy.xex`. Point them elsewhere with the variables
they document at the top:

```bash
XEDK=/c/XDK21256/XDK ./build.sh
EXTRA_DEFS="-W4" ./build.sh          # stricter warnings
```

The toolchain steps, for reference: `cl -c -W4 -Ox -MT -GR- -EHsc -TP` per
source, then `link -DLL -ENTRY:_DllMainCRTStartup -XEX:NO -ALIGN:128,4096`
against `xboxkrnl.lib xapilib.lib`, then `imagexex -config:XeProxy.xex.xml`.
The xex is a `<sysdll/>`, which is what DashLaunch loads.

Both scripts first run `tools/mkdefaults.py`, which regenerates
`src/default_ini.h` from `xeproxy.ini` so the config the plugin writes for
itself cannot drift from the reference one. The header is committed, so a
build without python uses it as-is; `mkdefaults.py --check` fails if it is
stale.

### Build status

Built and verified against XDK 21256 on this machine, through both
`build.sh` and `build.bat`:

- all nine sources compile with **zero warnings at `/W4`**, and link clean
- output is a valid `XEX2` DLL, 44 KB, PPCBE, subsystem Xbox, based where
  `XeProxy.xex.xml` says
- it imports **only `xboxkrnl.exe`** - everything from xam is resolved at
  runtime by ordinal, so there is no load-order dependency on xam's exports
- every hand-assembled instruction word was fed back through the XDK's own
  PowerPC disassembler and decodes as intended:

  ```
  7C8903A6 mtctr r4        3D601234 lis   r11,0x1234
  7C00186C dcbst r0,r3     396B5678 addi  r11,r11,0x5678
  7C0004AC sync            7D6903A6 mtctr r11
  7C001FAC icbi  r0,r3     4E800420 bctr
  38630020 addi  r3,r3,32
  4200FFF0 bdnz  -16       (lands on the dcbst)
  4C00012C isync
  4E800020 blr
  ```

Loaded and verified on a console (JTAG/RGH, DashLaunch, dashboard 17559): hooks
install, traffic redirects through a SOCKS5 proxy, and the TLS fix lets XHttp
complete a handshake with mitmproxy's certificate - confirmed by reading the
console's own decrypted HTTPS (e.g. `login.live.com`) in the proxy.

## Troubleshooting

**"no ini found", or no log file anywhere.** These are usually the same fault:
the plugin cannot open files by the names you gave it.

`Hdd:`, `Usb0:` and `Flash:` are **not kernel device links**. A real retail
kernel's object namespace contains only `\??\D:` - the drive-style names are a
convention of DashLaunch, XeXMenu and FSD, each of which resolves them
privately. A plugin calling `CreateFile("Hdd:\\xeproxy.ini")` is relying on
a link that may simply not be published, and when it is not, every open fails
and the plugin reports "no ini found" having never read a byte.

So each path is now tried three ways, and the log names the one that worked:

```
log: writing to Hdd:\xeproxy.log (opened via native-device)
config: opened Hdd:\xeproxy.ini via native-device
```

| `how` | meaning |
|---|---|
| `link` | plain `CreateFile` on `Hdd:\...` worked - a link existed |
| `win32-device` | `CreateFile` on `\Device\Harddisk0\Partition1\...` worked |
| `native-device` | only `NtCreateFile` on the raw device path worked |
| `native` | you gave a `\Device\...` path yourself |

The device paths come from the kernel's own strings:
`\Device\Harddisk0\Partition1` (HDD), `\Device\Mass0`-`Mass2` (USB),
`\Device\Flash` (NAND). You can also put a raw path straight into
`[general] log`, and `mount: n/6 device links usable` says how many
drive-letter links exist at all.

**The ini is found but ignored.** There is a size limit (16 KB) and a file over
it is refused, which reads downstream as "not found". The annotated
`xeproxy.ini` here is already 7.9 KB of comments, so there is room, but the
log says so explicitly: `config: ... is N bytes, limit is 16384`.

**No log at all - check this first.** A DashLaunch system plugin loads *only* at
the base address built into its xex; nothing relocates it. If its range overlaps
a plugin already mapped, it does not load at all - no `DllMain`, no thread, no
log - and the one listed later in `launch.ini` is the one that loses. This is the
single most common reason a plugin is silently absent, and it looks identical to
"the code is broken".

Known occupants, from [Xbox360AutoDNS PR #4](https://github.com/dclstn/Xbox360AutoDNS/pull/4):

| Range | Plugin |
|---|---|
| `0x91000000` | xbdm |
| `0x91900000` | JRPC2 |
| `0x91C10000-0x91D2A000` | NiNJA_WAW |
| `0x91D00000-0x91D8A000` | codxe, XeCord, iw3-codjumper, PcMic-360, 0xJ |
| `0x91DC0000-0x91DC8000` | AutoDNS |
| `0x91DE0000-0x91DE8000` | CoronaKeysFix |
| `0x91DF0000-0x91DF8000` | UsbdSecPatch |
| `0x91E00000-0x91E6D000` | RPC360 |
| `0x91F00000-` | **DashLaunch's own `launch.xex`** |

XeProxy is built at `0x91E80000` and needs about 116 KB, so it occupies
`0x91E80000-0x91EAB000` - in the gap between RPC360's end and `launch.xex`.

Anything *not* in that table is unknown, not free. Copy your other plugins off
the console and check for yourself:

```
python tools/xexbase.py XeProxy.xex Xbdm.xex XeCord.xex HvP2.xex Proto.xex
```

It prints each one's real mapped range (from the xex security header, which is
readable even on a compressed xex) and names any pair that overlaps. If
XeProxy clashes, pick a free address, change `baseaddr` in
`XeProxy.xex.xml`, and rebuild.

Once it does load, the first log line reports where it landed -
`XeProxy 1.0 starting, image at ~91E80000` - so a later collision caused by
adding another plugin is visible rather than mysterious.

**Still nothing, and the base is clear.** Then either the `[Plugins]` path is
wrong, or you are out of plugin slots (`plugin1`-`plugin5` only). Failing
that, watch the debug output live - see below.

**Watching it live over xbdm.** Everything the plugin logs also goes out via
`OutputDebugString`, which does not depend on any filesystem. With
`debugout = true` in `launch.ini` and `xbdm.xex` loaded as a plugin, point the
XDK's `xbwatson.exe` (in `bin\win32`) at the console and reboot. If lines
appear there but no file is written, the plugin is running fine and the
problem is only the log device. If nothing appears at all, it never loaded.

**`NetDll_x (ordinal n) did not resolve`.** That ordinal is not an export on
your kernel. Put the right one under `[ordinals]`; the names there match the
log exactly.

**`no executable memory available, hooks disabled`.** Neither
`XPhysicalAlloc`'d memory nor the plugin's own image data would execute. The
plugin stops instead of writing a jump to a trampoline that cannot run.

**`prologue insn N (xxxxxxxx) will not reach`.** That function starts with a
branch that cannot be relocated into the trampoline. The hook refused itself
and xam is untouched; everything else still installed.

**Title hangs where it used to work.** Set `log_level = 3`, reproduce, and read
the last few lines. Then narrow `[redirect]` - a `*` rule catches the console's
own traffic to Microsoft as well as the game's.

## Layout

```
src/xep.h        shared types, config model, prototypes
src/netdll.h     NetDll_* signatures and the constants they use
src/main.cpp     DllMain, worker thread, the reload loop
src/hooks.cpp    resolve, install, and every hook body
src/patch.cpp    PowerPC detour engine, cache maintenance, executable probe
src/config.cpp   ini discovery, parsing, hot reload, rule matching
src/defaults.cpp writes xeproxy.ini when the console has not got one
src/default_ini.h  generated from xeproxy.ini by tools/mkdefaults.py
src/socks.cpp    SOCKS5 CONNECT
src/log.cpp      flushed-per-line log
src/vfs.cpp      opening files without depending on drive-letter links
src/util.cpp     strings, addresses, device links
XeProxy.xex.xml  imagexex config - the load address lives here
xeproxy.ini      annotated reference config
tools/xexbase.py   prints xex load ranges and finds overlaps between plugins
tools/mkdefaults.py  regenerates src/default_ini.h from xeproxy.ini
```

## Credit

The build recipe for a DashLaunch sysdll plugin - the `cl`/`link`/`imagexex`
invocation and the `<sysdll/>` xex config - follows
[dclstn/Xbox360AutoDNS](https://github.com/dclstn/Xbox360AutoDNS), which does
the same thing for the console's stored DNS settings. Export ordinals come from
Xenia's `xam_table`
([gist](https://gist.github.com/emoose/c12ae9ced0ffa94a8d287e082ff9866c)).

Intended for a console you own, pointed at a server you run.
