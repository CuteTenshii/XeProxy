# Configuration

`xeproxy.ini` in the repository root is the reference: every key is documented inline next to a commented-out example. This page covers how the file is found, when it is re-read, and a few complete setups.

## Where the ini is looked for

In order, first match wins:

```
Usb0:\xeproxy.ini   Usb1:\xeproxy.ini   Usb2:\xeproxy.ini
Hdd:\xeproxy.ini    Hdd:\plugins\xeproxy.ini
Flash:\xeproxy.ini  Game:\xeproxy.ini
```

USB comes first on purpose: a stick with a different `xeproxy.ini` overrides the one on the hard drive without touching it, which makes it a safe way to try a risky config or to recover from a bad one (put `enabled = 0` on a stick and boot).

If none exists, the plugin writes the reference config itself - verbatim, with a header saying where it came from - to `Hdd:\xeproxy.ini`, or to the first USB stick it can write to. A toast names the file. What it writes has `enabled = 0`, so nothing is patched on that first boot.

Unless `[general] log` names a path, the log goes next to whichever ini was found - so a config on a USB stick also logs to the stick, where you can still read it after a hang.

## Reloading

Hot reload is off by default (`config_reload_seconds = 0`): the ini is read once at boot and the plugin runs silently. Set `config_reload_seconds` to a nonzero number of seconds to have edits applied live without a reboot - that also turns the log on, since logging is coupled to it.

Some things only happen at boot regardless:

- `[hooks]` and `[ordinals]` - hooks are installed once and never removed.
- `tls_ignore_cert_errors` - the xam patch is applied at startup and not reverted by a reload.

## Sections

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

`[redirect]` rules are matched top to bottom and the first match wins, so put exceptions (`... = passthrough`) above a catch-all.

`[proxy] mode` picks what a rule that says `proxy` does:

| mode | what happens on `connect()` |
|---|---|
| `redirect` | the destination address/port is rewritten; works for TCP and UDP |
| `http` | connects to the proxy and opens an HTTP `CONNECT ip:port` tunnel (mitmproxy's default "regular" mode) |
| `socks5` | connects to the proxy and performs a SOCKS5 `CONNECT` (`mitmproxy --mode socks5`) |
| `drop` | the call appears to succeed and nothing is sent |

`http` and `socks5` tunnel TCP only; a datagram that matches such a rule is sent to its real destination unchanged.

`[proxy] forward_lan = 0` keeps destinations in 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, multicast and broadcast away from every rule, so a catch-all can't capture system link or local servers.

## Examples

Everything Xbox Live to a server at 192.168.1.50, logged:

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

All TCP through mitmproxy in its default (regular) mode, LAN left alone:

```ini
[general]
tls_ignore_cert_errors = 1   ; so XHttp completes TLS with mitmproxy's cert

[proxy]
host = 192.168.1.50
port = 8080
mode = http
forward_lan = 0

[redirect]
*:123 = passthrough          ; NTP: nothing listens on TCP 123, a CONNECT only stalls
* = proxy
```

The same web traffic through a SOCKS5 proxy instead:

```ini
[proxy]
host = 192.168.1.50
port = 1080
mode = socks5

[redirect]
*:80  = proxy
*:443 = proxy
```
