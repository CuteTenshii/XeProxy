// netprobe title: a launchable Xbox 360 homebrew that runs one DNS, one
// raw-socket HTTP, and one XHttp HTTPS request, logging each result to the
// debug channel (xbWatson), then exits back to the dashboard. Unlike the
// plugin version this runs in its own process, so it gets the insecure-socket
// privilege (launch.ini sockpatch=true) and cannot freeze the system.

#include <xtl.h>
#include <winsockx.h>
#include <xhttp.h>
#include <ppcintrinsics.h>
#include <stdio.h>
#include <string.h>

static const char *kHost  = "www.google.com";          // serves :80 and :443, public CA
static const char *kProxy = "192.168.50.180:8080";     // mitmproxy, hardcoded

static const char *IpStr(IN_ADDR a, char *out)
{
    const unsigned char *p = (const unsigned char *)&a.s_addr;
    _snprintf(out, 16, "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    out[15] = 0;
    return out;
}

static void Log(const char *fmt, ...)
{
    char buf[320];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
    buf[sizeof(buf) - 1] = 0;
    va_end(ap);

    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[400];
    int n = _snprintf(line, sizeof(line) - 1, "[netprobe %02u:%02u:%02u.%03u] %s\r\n",
                      st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, buf);
    line[sizeof(line) - 1] = 0;
    if (n < 0) n = (int)strlen(line);
    OutputDebugStringA(line);

    // Also append to a file so results can be pulled with xbcp without a live
    // debug session (lets the run be driven headlessly).
    HANDLE h = CreateFileA("\\Device\\Harddisk0\\Partition1\\netprobe.log",
                           GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD wrote;
        SetFilePointer(h, 0, NULL, FILE_END);
        WriteFile(h, line, (DWORD)n, &wrote, NULL);
        FlushFileBuffers(h);
        CloseHandle(h);
    }
}

// Xbox XHttp is asynchronous: XHttpSendRequest/XHttpReceiveResponse return
// immediately and completion arrives through a status callback that fires while
// XHttpDoWork pumps the session. These flags turn that back into a simple
// blocking wait for one request at a time.
static volatile LONG g_sendDone;
static volatile LONG g_headersDone;
static volatile LONG g_reqError;
static volatile LONG g_reqApi;    // which XHttp API failed (API_SEND_REQUEST, ...)
static volatile LONG g_reqErr;    // dwError from the REQUEST_ERROR callback

static VOID CALLBACK HttpCb(HINTERNET h, DWORD_PTR ctx, DWORD status,
                            PVOID info, DWORD len)
{
    (void)h; (void)ctx; (void)len;
    if (status == XHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE) g_sendDone = 1;
    else if (status == XHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE) g_headersDone = 1;
    else if (status == XHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
        g_reqError = 1;
        if (info != NULL) {
            XHTTP_ASYNC_RESULT *r = (XHTTP_ASYNC_RESULT *)info;
            g_reqApi = (LONG)r->dwResult;
            g_reqErr = (LONG)r->dwError;
        }
    }
}

static BOOL PumpUntil(HINTERNET hSession, volatile LONG *flag, int timeoutMs)
{
    int elapsed = 0;
    while (!*flag && !g_reqError && elapsed < timeoutMs) {
        XHttpDoWork(hSession, 200);
        elapsed += 200;
    }
    return (*flag != 0) ? TRUE : FALSE;
}

// One async XHttp GET of http(s)://host:port/ , optionally through a named
// proxy. Logs the HTTP status on success or the failing stage on error.
static void DoXHttp(const char *host, WORD port, BOOL secure, const char *proxy)
{
    const char *scheme = secure ? "https" : "http";
    const char *tag = (proxy != NULL) ? "proxy" : "direct";
    DWORD access = (proxy != NULL) ? XHTTP_ACCESS_TYPE_NAMED_PROXY
                                   : XHTTP_ACCESS_TYPE_DEFAULT_PROXY;

    HINTERNET hs = XHttpOpen("netprobe/1.0", access, proxy, NULL, XHTTP_FLAG_ASYNC);
    if (hs == NULL) {
        Log("XHttp[%s %s %s:%u] Open FAIL err=%d", tag, scheme, host, port, GetLastError());
        return;
    }

    // XHttp wants the SECURE flag on XHttpConnect (not XHttpOpenRequest like
    // WinHTTP). With it here, a proxied request does a proper CONNECT + TLS.
    HINTERNET hc = XHttpConnect(hs, host, port, secure ? XHTTP_FLAG_SECURE : 0);
    HINTERNET hr = (hc != NULL)
        ? XHttpOpenRequest(hc, "GET", "/", NULL, NULL, NULL, 0)
        : NULL;

    if (hr == NULL) {
        Log("XHttp[%s %s %s:%u] Connect/Open FAIL err=%d", tag, scheme, host, port, GetLastError());
    } else {
        XHttpSetStatusCallback(hr, HttpCb, XHTTP_CALLBACK_FLAG_ALL_COMPLETIONS, 0);

        // The real fix: tell XHttp to accept a cert LIVE/validation rejects.
        // The 360 otherwise aborts the TLS handshake the instant it sees an
        // untrusted cert (confirmed by packet capture). This is the documented
        // debug bypass (xhttp.h). Must be set before the handshake (the send).
        if (secure) {
            DWORD sec = SECURITY_FLAG_ALLOW_LIVE_REJECTED_CERT |
                        SECURITY_FLAG_IGNORE_LIVE_VALIDATION_CACHE;
            BOOL so = XHttpSetOption(hr, XHTTP_OPTION_SECURITY_FEATURE, &sec, sizeof(sec));
            Log("XHttp[%s %s %s:%u] SECURITY_FEATURE=%08X set=%d err=%d",
                tag, scheme, host, port, sec, so, so ? 0 : (int)GetLastError());
        }

        g_sendDone = 0; g_headersDone = 0; g_reqError = 0; g_reqApi = 0; g_reqErr = 0;
        if (!XHttpSendRequest(hr, NULL, 0, NULL, 0, 0, 0)) {
            Log("XHttp[%s %s %s:%u] Send FAIL err=%d", tag, scheme, host, port, GetLastError());
        } else if (!PumpUntil(hs, &g_sendDone, 20000)) {
            Log("XHttp[%s %s %s:%u] send FAIL api=%ld err=%ld", tag, scheme, host, port, g_reqApi, g_reqErr);
        } else {
            g_headersDone = 0; g_reqError = 0; g_reqApi = 0; g_reqErr = 0;
            if (!XHttpReceiveResponse(hr, NULL)) {
                Log("XHttp[%s %s %s:%u] Receive FAIL err=%d", tag, scheme, host, port, GetLastError());
            } else if (!PumpUntil(hs, &g_headersDone, 20000)) {
                Log("XHttp[%s %s %s:%u] recv FAIL api=%ld err=%ld", tag, scheme, host, port, g_reqApi, g_reqErr);
            } else {
                DWORD status = 0, len = sizeof(status);
                XHttpQueryHeaders(hr, XHTTP_QUERY_STATUS_CODE | XHTTP_QUERY_FLAG_NUMBER,
                                  NULL, &status, &len, NULL);
                Log("XHttp[%s %s %s:%u] OK status=%u", tag, scheme, host, port, status);
            }
        }
    }

    if (hr != NULL) XHttpCloseHandle(hr);
    if (hc != NULL) XHttpCloseHandle(hc);
    XHttpCloseHandle(hs);
}

static void DoProbe(void)
{
    Log("probe host=%s", kHost);

    IN_ADDR addr;
    addr.s_addr = 0;

    // 1) DNS
    {
        XNDNS *dns = NULL;
        WSAEVENT ev = WSACreateEvent();
        INT r = XNetDnsLookup(kHost, ev, &dns);
        WaitForSingleObject(ev, 15000);
        if (dns != NULL && dns->iStatus == 0 && dns->cina > 0) {
            addr = dns->aina[0];
            char ip[16];
            Log("DNS ok: %s -> %s (%u addr)", kHost, IpStr(addr, ip), dns->cina);
        } else {
            Log("DNS FAIL: call=%d status=%d", r, dns != NULL ? dns->iStatus : -999);
        }
        if (dns != NULL) XNetDnsRelease(dns);
        WSACloseEvent(ev);
    }

    (void)addr;   // raw :80/:443 socket tests removed: secure mode always
                  // times them out (~20s each), nothing to learn.

    // XHttp (async) through the hardcoded mitmproxy. HTTP confirms the path;
    // HTTPS is the one we care about now.
    DoXHttp(kHost, 80,  FALSE, kProxy);   // HTTP  via proxy
    DoXHttp(kHost, 443, TRUE,  kProxy);   // HTTPS via proxy
}

// --- in-title patch of xam's cert validator (diagnostic) --------------------
#define CACHE_LINE 32
#define ISYNC()    __emit(0x4C00012Cu)
static const DWORD kFlushCode[8] = {
    0x7C8903A6u, 0x7C00186Cu, 0x7C0004ACu, 0x7C001FACu,
    0x38630020u, 0x4200FFF0u, 0x4C00012Cu, 0x4E800020u,
};
typedef void (*FlushFn)(void *, int);
static FlushFn g_flush;
static void LineRange(void *a, int len, BYTE **first, int *lines) {
    DWORD s = (DWORD)a & ~(DWORD)(CACHE_LINE-1);
    DWORD e = ((DWORD)a + len + CACHE_LINE-1) & ~(DWORD)(CACHE_LINE-1);
    *first = (BYTE *)s; *lines = (int)((e-s)/CACHE_LINE);
}
static void WeakFlush(void *a, int len) {
    BYTE *p; int lines, i; LineRange(a, len, &p, &lines);
    for (i=0;i<lines;i++) __dcbst(i*CACHE_LINE, p);
    __sync(); ISYNC();
}
static void FlushRange(void *a, int len) {
    BYTE *p; int lines; LineRange(a, len, &p, &lines);
    if (g_flush) g_flush(p, lines); else WeakFlush(a, len);
}
static const DWORD kProbe[2] = { 0x38601234u, 0x4E800020u };
typedef DWORD (*ProbeFn)(void);
static DWORD g_staticPool[16];          // executable image data (title .data)
static BOOL TryPool(DWORD *code) {
    BOOL ok = FALSE;
    memcpy(code, kProbe, sizeof(kProbe)); WeakFlush(code, sizeof(kProbe));
    __try { ok = (((ProbeFn)(void*)code)() == 0x1234u); } __except (EXCEPTION_EXECUTE_HANDLER) { ok = FALSE; }
    if (!ok) return FALSE;
    memcpy(code, kFlushCode, sizeof(kFlushCode)); WeakFlush(code, sizeof(kFlushCode));
    g_flush = (FlushFn)(void*)code; FlushRange(code, sizeof(kFlushCode));
    return TRUE;
}
static void SetupFlusher(void) {
    DWORD *phys = (DWORD *)XPhysicalAlloc(64, MAXULONG_PTR, 0, PAGE_READWRITE);
    if (phys != NULL && TryPool(phys)) { Log("flush: icbi via physical %08X", (DWORD)phys); return; }
    if (phys != NULL) XPhysicalFree(phys);
    if (TryPool(g_staticPool)) { Log("flush: icbi via static %08X", (DWORD)g_staticPool); return; }
    Log("flush: no executable memory; weak flush only");
}
// Each xam TLS validator does its full work, then returns its verdict via a
// single `mr r3, rN` at the end. Rewrite just that to `li r3, 0` so the chain
// always validates while the function still fills its output buffers (no crash).
typedef struct { DWORD addr, exp, neww; } Patch;
static const Patch kPatches[] = {
    // Validator 2 (0x8195FB40) sets the cert's handshake status ctx->4 = 0x8a
    // (good), then overrides it to 0x25 (untrusted) iff the chain's 0x8000
    // "untrusted root" flag is set. The response generator refuses to send
    // ClientKeyExchange when it sees 0x25, so the 360 silently drops. Turn the
    // override's guard branch (beq, "flag clear -> keep 0x8a") into an
    // unconditional branch so the 0x25 override never runs: ctx->4 stays 0x8a
    // and the handshake completes using the real (mitmproxy) cert. The function
    // still does all its work -> no fabricated data, no crash. Legit Live certs
    // never set the 0x8000 flag, so they are unaffected.
    { 0x8195FDE4u, 0x41820014u, 0x48000014u },  // beq 0x8195fdf8 -> b 0x8195fdf8 (keep ctx->4=0x8a)
    // Validator 2's caller aborts if the function returns nonzero (bne 0x8196149c)
    // before it even checks ctx->4. All return paths converge at this final
    // `mr r3,r29`; force it to `li r3,0` so validator 2 always reports success.
    { 0x8195FDF8u, 0x7FA3EB78u, 0x38600000u },  // mr r3,r29 -> li r3,0
};

static void PatchOne(const Patch *p) {
    volatile DWORD *t = (volatile DWORD *)p->addr;
    DWORD w;
    __try { w = t[0]; }
    __except (EXCEPTION_EXECUTE_HANDLER) { Log("patch %08X: cannot read", p->addr); return; }

    if (w == p->neww) {
        Log("patch %08X: already patched, re-flushing", p->addr);
    } else if (w == p->exp) {
        __try {
            t[0] = p->neww;
            Log("patch %08X: return -> li r3,0", p->addr);
        } __except (EXCEPTION_EXECUTE_HANDLER) { Log("patch %08X: WRITE FAULTED", p->addr); return; }
    } else {
        Log("patch %08X: unexpected %08X, skip", p->addr, w); return;
    }
    FlushRange((void *)p->addr, 4);
}

static void PatchCertValidator(void) {
    int i;
    SetupFlusher();
    for (i = 0; i < (int)(sizeof(kPatches) / sizeof(kPatches[0])); i++)
        PatchOne(&kPatches[i]);
    Log("patch: done (g_flush=%s)", g_flush ? "icbi" : "weak");
}

// Read a memory region and POST it through the proxy to a loopback collector
// (http://127.0.0.1:8888/mem) for inspection. The proxy forwards to its own
// localhost, so no inbound firewall rule is needed. Unreadable pages -> 0xEE.
static BYTE g_body[0x6400];
static void SendRegion(DWORD start, DWORD len)
{
    DWORD o;
    if (len > sizeof(g_body)) len = sizeof(g_body);
    for (o = 0; o < len; o += 4096) {
        DWORD c = (len - o > 4096) ? 4096 : (len - o);
        __try { memcpy(g_body + o, (const void *)(start + o), c); }
        __except (EXCEPTION_EXECUTE_HANDLER) { memset(g_body + o, 0xEE, c); }
    }

    HINTERNET hs = XHttpOpen("netprobe/1.0", XHTTP_ACCESS_TYPE_NAMED_PROXY, kProxy, NULL, XHTTP_FLAG_ASYNC);
    if (hs == NULL) { Log("send: Open err=%d", GetLastError()); return; }
    // POST to a normal host so the proxy accepts and forwards it; we read the
    // body off the wire from the console->proxy capture, not from the upstream.
    HINTERNET hc = XHttpConnect(hs, "www.google.com", 80, 0);
    HINTERNET hr = (hc != NULL) ? XHttpOpenRequest(hc, "POST", "/memdump", NULL, NULL, NULL, 0) : NULL;
    if (hr == NULL) {
        Log("send: Connect/Open err=%d", GetLastError());
        if (hc != NULL) XHttpCloseHandle(hc);
        XHttpCloseHandle(hs);
        return;
    }
    XHttpSetStatusCallback(hr, HttpCb, XHTTP_CALLBACK_FLAG_ALL_COMPLETIONS, 0);
    g_sendDone = 0; g_headersDone = 0; g_reqError = 0; g_reqApi = 0; g_reqErr = 0;
    if (!XHttpSendRequest(hr, NULL, 0, g_body, len, len, 0))
        Log("send: SendRequest err=%d", GetLastError());
    else if (!PumpUntil(hs, &g_sendDone, 20000))
        Log("send: pump FAIL api=%ld err=%ld", g_reqApi, g_reqErr);
    else
        Log("send: POSTed %u bytes from %08X", len, start);

    XHttpCloseHandle(hr);
    XHttpCloseHandle(hc);
    XHttpCloseHandle(hs);
}

void __cdecl main()
{
    // Fresh log each launch (headless runs pull this file afterwards).
    {
        HANDLE h = CreateFileA("\\Device\\Harddisk0\\Partition1\\netprobe.log",
                               GENERIC_WRITE, FILE_SHARE_READ, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }

    // Bypass security so the stack does not XNet-encrypt traffic to untrusted
    // (non-Live) hosts, which otherwise get dropped. launch.ini sockpatch=true
    // is what makes this flag effective on a retail console.
    XNetStartupParams xp;
    memset(&xp, 0, sizeof(xp));
    xp.cfgSizeOfStruct = sizeof(xp);
    xp.cfgFlags = XNET_STARTUP_BYPASS_SECURITY;
    INT e = XNetStartup(&xp);
    WSADATA wsd;
    int w = WSAStartup(MAKEWORD(2, 2), &wsd);
    BOOL hx = XHttpStartup(0, NULL);   // required before any XHttp* call
    Log("title start: XNetStartup=%d WSAStartup=%d XHttpStartup=%d", e, w, hx);

    (void)&SendRegion; (void)&PatchCertValidator; (void)&DoProbe;

    // LOOP-PROBER: one Aurora launch, then fire the HTTPS probe through the RSA
    // proxy every 6s forever, so the PC can patch candidate xam functions via
    // xbdm setmem between probes and watch the capture for the handshake
    // completing - fast bisection, no reboot. The title patches nothing itself.
    // Exit by closing the title from the console.
    {
        int round;
        for (round = 0; ; round++) {
            Log("https round %d", round);
            DoXHttp(kHost, 443, TRUE, kProxy);
            Sleep(6000);
        }
    }

    // Do NOT WSACleanup/XNetCleanup: on this setup the network stack is shared
    // with xam and the xbdm debug plugin, so tearing it down on exit kills
    // network debugging (xbdm) until a reboot. Leave it up for the dashboard.
    Log("title done, exiting to dash (leaving net stack up)");
}
