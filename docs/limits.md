# Limits and known issues

Worth knowing before you debug something.

## Known issues

- **Enabling every hook has frozen a console.** With all 23 `[hooks]` on, a JTAG on dashboard 17559 froze within a few minutes of boot (xbdm still accepted TCP but never answered). The default nine hooks ran stable under the same config, so the cause is one of the other fourteen (`socket`, `closesocket`, `bind`, `setsockopt`, `send`, `recv`, `select`, the `XNet*Addr` family, `XNetGetConnectStatus`, the QoS lookups). Not yet bisected - turn extra hooks on a few at a time, ideally with the config on a USB stick so a bad boot is easy to undo.
- **Xbox Live sign-in failing with the plugin loaded is unexplained.** Sign-in returned `8015190E` even with no redirect rules and the TLS fix off. Whether the plugin is involved at all has not been established yet.

## Limits

- **Proxy tunnels carry TCP only.** SOCKS5 UDP `ASSOCIATE` is not implemented and HTTP `CONNECT` cannot carry datagrams, so a `socks5` or `http` rule that matches a datagram sends it to its real destination unchanged. UDP can still be pointed at a proxy with a plain `redirect` rule (e.g. to a mitmproxy `reverse:udp://host:port` listener), one destination per listener.
- **A tunnelled connect blocks its caller.** The proxy handshake runs inside `connect()`, for non-blocking sockets too, for up to `socks_timeout_ms`. A destination that never answers (mitmproxy connects upstream before replying to `CONNECT`) holds that thread for the full timeout - pass such ports through.
- **Overlapped UDP receives.** `WSARecvFrom` with an `OVERLAPPED` writes the source address after the call returns, so the address rewrite cannot be undone for it. Synchronous `recvfrom` and `WSARecvFrom` are handled. A title that uses overlapped receives *and* validates source addresses will drop proxied datagrams.
- **`forward_lan = 0` beats every rule.** With it off, a destination in 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, multicast or broadcast is never redirected, dropped or tunnelled, even by a rule that names it explicitly. XHttp hostnames can't be judged until they resolve, so for those it is the `connect` hook that keeps the LAN address local.
- **xbdm is invisible to every hook.** Its own calls are neither redirected nor logged, so a bad catch-all can't cut off the debug channel you would use to fix it.
- **Reverse mapping is per socket, most-recent-wins.** Several destinations behind one proxy endpoint on one socket are genuinely ambiguous on the way back. With `closesocket = 0` in `[hooks]` (the default) stale entries are only evicted by LRU; turn it on if a title churns sockets.
- **`XNetStartup` is only patched for callers that come after the hooks.** xam starts its own network context very early in boot, possibly before the plugin is loaded. Titles, which call it on launch, are always covered.
- **Hooks go in once.** Changing `[hooks]` or `[ordinals]` needs a reboot; nothing is ever unhooked.
- **`force_connect_status`, `bypass_qos` and `map_xnaddr_to_ina` each need their hook enabled** in `[hooks]` - the switch alone does nothing. The ini says which.
- **The log can't be copied off while the plugin runs.** It holds the file open for writing and xbdm refuses to open it alongside; read it after a reboot with logging off, from a USB stick on a PC, or live over xbdm (see [Troubleshooting](troubleshooting.md#watching-it-live-over-xbdm)).
