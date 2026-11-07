# XeProxy

A DashLaunch plugin for the Xbox 360 that hooks xam.xex's `NetDll_*` exports - the XNet and Winsock layer every title and the dashboard go through - so console traffic can be pointed somewhere other than Xbox Live. DNS answers, TCP/UDP destinations and `XHttpConnect` targets are all rewritten from an ini file that the plugin can re-read whenever it changes.

Nothing is baked into the xex. One build, and a text file decides where traffic goes.

Tested on a JTAG/RGH console running the latest Xbox 360 dashboard (17559).

## What it can do

| | |
|---|---|
| Answer DNS itself | `*.xboxlive.com = 192.168.1.50`, no resolver involved |
| Rewrite destinations | per address, CIDR block and/or port, for TCP and UDP |
| Tunnel through a proxy | HTTP `CONNECT` (mitmproxy's default mode) or SOCKS5, performed inside the hooked `connect()`, blocking and non-blocking sockets alike |
| Keep the LAN local | `forward_lan = 0` keeps private, loopback, multicast and broadcast destinations off every rule |
| Drop traffic | make a send look like it succeeded and send nothing |
| Rewrite XHttp | `XHttpConnect`'s server name and port, for the Live services that use it |
| Force `XNetStartup` flags | notably `XNET_STARTUP_BYPASS_SECURITY`, so traffic is plain |
| Undo the rewrite on the way back | replies from the proxy are handed to the title as if they came from the address it asked for |
| Trace | one log line per intercepted call, when you need to see what a title does |
| MITM TLS | a one-instruction xam fix so XHttp completes a handshake with a proxy's certificate |

## Install

1. Build `XeProxy.xex` ([docs/building.md](docs/building.md)), or drop in a prebuilt one.
2. Copy `XeProxy.xex` to the console, and `xeproxy.ini` next to it. If there is no ini anywhere the plugin looks, it writes the annotated reference config itself on first boot, with `enabled = 0` so nothing is patched until you edit it.
3. Add the xex to `launch.ini`, early - a plugin that opens sockets before this one loads will already have called `XNetStartup` with its own flags:

   ```ini
   [Plugins]
   plugin1 = Hdd:\XeProxy.xex
   plugin2 = Hdd:\xbdm.xex
   ```

4. Reboot and read the log. Its first lines say which ini was found, which exports resolved, which hooks went in, and whether the TLS fix was applied:

   ```
   XeProxy 1.0 starting, image at ~91E80000
   XeProxy: 9 hooks, 3 rules, log on Hdd:
   ```

## Quick start: everything through mitmproxy

Run mitmproxy as usual (regular mode, port 8080) and set:

```ini
[general]
enabled = 1
tls_ignore_cert_errors = 1

[proxy]
host = 192.168.1.50
port = 8080
mode = http
forward_lan = 0

[redirect]
*:123 = passthrough
* = proxy
```

Every TCP connection the console makes then shows up in mitmproxy, HTTPS from XHttp decrypted. More setups, and what every section does, in [docs/configuration.md](docs/configuration.md).

## Documentation

- [Configuration](docs/configuration.md) - where the ini is found, reloading, proxy modes, examples
- [How it works](docs/how-it-works.md) - the detour engine, proxy tunnels, `bypass_security`, the TLS fix
- [Limits and known issues](docs/limits.md) - read before debugging something
- [Troubleshooting](docs/troubleshooting.md) - no log, no ini, load-address clashes, log messages, hangs
- [Building](docs/building.md) - XDK toolchain and build status
- [Research](docs/research/cert-trust/NOTES.md) - the XHttp TLS investigation behind the MITM fix

## Layout

```
src/xep.h          shared types, config model, prototypes
src/netdll.h       NetDll_* signatures and the constants they use
src/main.cpp       DllMain, worker thread, the reload loop
src/hooks.cpp      resolve, install, and every hook body
src/patch.cpp      PowerPC detour engine, cache maintenance, executable probe, TLS fix
src/config.cpp     ini discovery, parsing, hot reload, rule matching
src/defaults.cpp   writes xeproxy.ini when the console has not got one
src/default_ini.h  generated from xeproxy.ini by tools/mkdefaults.py
src/socks.cpp      SOCKS5 and HTTP CONNECT handshakes
src/log.cpp        flushed-per-line log
src/vfs.cpp        opening files without depending on drive-letter links
src/util.cpp       strings, addresses, device links
XeProxy.xex.xml    imagexex config - the load address lives here
xeproxy.ini        annotated reference config
tools/xbdm.py      talks to xbdm over TCP 730 (memory, threads, breakpoints, notifications)
tools/xexbase.py   prints xex load ranges and finds overlaps between plugins
tools/mkdefaults.py  regenerates src/default_ini.h from xeproxy.ini
netprobe/          test title: DNS, raw HTTP and XHttp HTTPS through a proxy
docs/              documentation, and docs/research for investigation notes
```

## Credit

The build recipe for a DashLaunch sysdll plugin - the `cl`/`link`/`imagexex` invocation and the `<sysdll/>` xex config - follows [dclstn/Xbox360AutoDNS](https://github.com/dclstn/Xbox360AutoDNS), which does the same thing for the console's stored DNS settings. Export ordinals come from Xenia's `xam_table` ([gist](https://gist.github.com/emoose/c12ae9ced0ffa94a8d287e082ff9866c)).

Intended for a console you own, pointed at a server you run.
