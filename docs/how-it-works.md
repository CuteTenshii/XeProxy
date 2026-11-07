# How it works

`NetDll_socket`, `NetDll_connect`, `NetDll_XNetDnsLookup` and the rest are ordinary exports of `xam.xex`; the XDK's `xnet.lib` wrappers only hide the leading `XNCALLER_TYPE` argument. Hooking them inside xam catches every caller at once, including titles launched long after the plugin loaded.

At boot the worker thread:

1. Recreates the `Hdd:` / `Usb0:` / `Flash:` links, since a plugin can load before xam has published them, then waits for the ini to appear.
2. Resolves each export with `XexGetModuleHandle("xam.xex", ...)` and `XexGetProcedureAddress(..., ordinal, ...)`.
3. Allocates a trampoline pool and **proves it is executable** by running two instructions out of it under SEH before installing anything. Physical memory is tried first, the plugin's own image data second.
4. **Assembles its own cache-flush routine** into that pool. Patching code on this CPU means `dcbst` to push the line out of the data cache and `icbi` to invalidate the matching instruction cache line, but the XDK's `ppcintrinsics.h` has no `__icbi` and no `__isync`, and `icbi` needs its address in a register no intrinsic lets you name. Eight words of hand-assembled PowerPC in the pool solve that; until it is in place the only thing flushed is the one page the CPU has never executed from, where `dcbst`/`sync`/`isync` is enough.
5. Detours each enabled export: four instructions at the function's entry (`lis`/`addi`/`mtctr`/`bctr` through r11, which is volatile at a call boundary) jump to the hook, and the instructions they displaced are relocated into the trampoline followed by a jump back. A relative branch in a prologue is re-encoded for its new address; one that will not reach makes the hook refuse itself rather than corrupt xam.
6. Applies the TLS handshake fix when `tls_ignore_cert_errors = 1` - one xam instruction so XHttp completes a handshake with a proxy's certificate (see [TLS for MITM](#tls-for-mitm)).
7. Stays resident, re-reading the ini when its size or write time changes. Parsing goes into whichever of two config buffers is not live, and the live pointer is then flipped, so a hook that is already running finishes against a coherent snapshot.

Every hook is transparent when no rule matches: it calls the trampoline with the arguments it was handed and returns the result unchanged. With an empty ini the console behaves as though the plugin were not loaded.

Calls made by xbdm (`XNCALLER_XBDM`) are passed straight through - never redirected and never logged - so the debug channel and Neighborhood file transfers keep working whatever the rules say.

## Proxy tunnels

In `http` and `socks5` mode the hooked `connect()` connects the socket to the proxy instead, then performs the proxy handshake on it (`CONNECT ip:port HTTP/1.1`, or the SOCKS5 greeting and `CONNECT`) before returning, so the caller's first byte already travels inside the tunnel.

Non-blocking sockets - XHttp uses them, Live sign-in among others - report a connect as "in progress". Returning that would leave the socket heading for the proxy with no tunnel, and the caller's raw TLS or HTTP would hit the proxy directly. So the hook waits for the connection on `select()`, runs the handshake (waiting out any would-block the same way), and reports the connect as already complete, which the Winsock contract allows for a non-blocking socket. Every wait is bounded by `socks_timeout_ms`.

## Why `bypass_security` matters

Xbox Live traffic normally rides the secure-socket layer: addresses are `XNADDR`s resolved against Microsoft's security gateway, and payloads are encrypted with keys the console gets from Live. A proxy in the middle sees nothing it can route. `XNET_STARTUP_BYPASS_SECURITY` (bit 0 of `XNetStartupParams.cfgFlags`) turns that off, which is why it is forced by default.

One caveat, in the XDK's own words: that flag is "devkit-only" and is "silently ignored by the secure versions of the library", in which case "attempts to send or receive packets from untrusted hosts will fail". On a retail console running a retail xam it may do nothing - setting it costs nothing and it is the right flag on a devkit xam, but if proxied peer traffic is being dropped and the log shows the flag going in, that is the reason, not a bug in the redirect rules. `map_xnaddr_to_ina` is the fallback that does not depend on it: it answers `XNetXnAddrToInAddr` with the peer's plain address whenever secure registration fails. `XNET_STARTUP_DISABLE_PEER_ENCRYPTION` (0x08) is also available through `force_flags` and is worth trying alongside it.

## TLS for MITM

`tls_ignore_cert_errors = 1` makes xam's XHttp complete a TLS handshake with a certificate the console would normally reject, so an intercepting proxy (mitmproxy etc.) can read the console's own HTTPS. The console already accepts the proxy's leaf - its XHttp cert check is essentially a hostname match - so the real blocker is a xam bug: after the Certificate message the TLS state machine is left in a state with no handler for the ServerHelloDone that follows, and the handshake silently stalls. The fix is one instruction in xam that selects the working state. It is applied once at startup, refuses itself unless the live bytes match (so a different xam build is never corrupted), and affects every XHttp TLS handshake system-wide - so pair it with a proxy that relays to the real servers.

The investigation that found it, with traces and addresses, is in [`docs/research/cert-trust/NOTES.md`](research/cert-trust/NOTES.md).
