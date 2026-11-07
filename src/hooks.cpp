// hooks.cpp: resolution, installation and the hook bodies.
// Every hook is transparent when no rule matches: it calls the trampoline unchanged.

#include "netdll.h"

static void *g_target[FN_COUNT];     // real addresses inside xam.xex
static BOOL  g_installed;
static BOOL  g_resolved;
static int   g_hookCount;

int XepHookCount(void)
{
    return g_hookCount;
}

// rewrite map
// Remembered per socket so recvfrom can undo the substitution; titles match
// replies against what they sent and would otherwise drop the proxied reply.

#define MAP_SLOTS 64

struct MapEntry {
    DWORD socket;
    DWORD origAddr;
    WORD  origPort;
    DWORD newAddr;
    WORD  newPort;
    DWORD stamp;        // GetTickCount of last use, 0 = free
};

static MapEntry        g_map[MAP_SLOTS];
static CRITICAL_SECTION g_mapLock;
static BOOL            g_mapReady;

void XepMapRemember(DWORD s, DWORD origAddr, WORD origPort, DWORD newAddr, WORD newPort)
{
    int i;
    int freeSlot = -1;
    int oldest = 0;
    int victim;

    if (!g_mapReady)
        return;

    EnterCriticalSection(&g_mapLock);

    for (i = 0; i < MAP_SLOTS; i++) {
        if (g_map[i].stamp != 0 && g_map[i].socket == s &&
            g_map[i].newAddr == newAddr && g_map[i].newPort == newPort &&
            g_map[i].origAddr == origAddr && g_map[i].origPort == origPort) {
            g_map[i].stamp = GetTickCount() | 1;
            LeaveCriticalSection(&g_mapLock);
            return;
        }
        if (g_map[i].stamp == 0 && freeSlot < 0)
            freeSlot = i;
        if (g_map[i].stamp < g_map[oldest].stamp)
            oldest = i;
    }

    victim = (freeSlot >= 0) ? freeSlot : oldest;
    g_map[victim].socket   = s;
    g_map[victim].origAddr = origAddr;
    g_map[victim].origPort = origPort;
    g_map[victim].newAddr  = newAddr;
    g_map[victim].newPort  = newPort;
    g_map[victim].stamp    = GetTickCount() | 1;

    LeaveCriticalSection(&g_mapLock);
}

BOOL XepMapReverse(DWORD s, DWORD newAddr, WORD newPort, DWORD *origAddr, WORD *origPort)
{
    int  i;
    int  best = -1;
    BOOL found = FALSE;

    if (!g_mapReady)
        return FALSE;

    EnterCriticalSection(&g_mapLock);

    // Most recently used wins: destinations can share one proxy endpoint.
    for (i = 0; i < MAP_SLOTS; i++) {
        if (g_map[i].stamp == 0 || g_map[i].socket != s)
            continue;
        if (g_map[i].newAddr != newAddr || g_map[i].newPort != newPort)
            continue;
        if (best < 0 || g_map[i].stamp > g_map[best].stamp)
            best = i;
    }
    if (best >= 0) {
        *origAddr = g_map[best].origAddr;
        *origPort = g_map[best].origPort;
        g_map[best].stamp = GetTickCount() | 1;
        found = TRUE;
    }

    LeaveCriticalSection(&g_mapLock);
    return found;
}

void XepMapForget(DWORD s)
{
    int i;

    if (!g_mapReady)
        return;

    EnterCriticalSection(&g_mapLock);
    for (i = 0; i < MAP_SLOTS; i++)
        if (g_map[i].socket == s)
            g_map[i].stamp = 0;
    LeaveCriticalSection(&g_mapLock);
}

// spoofed DNS results
// Ours, tagged with a magic word in front so XNetDnsRelease can tell it from xam's.

#define FAKE_MAGIC  0x584E5031u     // 'XNP1'
#define FAKE_SLOTS  16

struct FakeDns {
    DWORD magic;
    XNDNS dns;                  // the SDK's own, with room for 8 addresses
    BOOL  inUse;
};

static FakeDns          g_fake[FAKE_SLOTS];
static CRITICAL_SECTION g_fakeLock;
static BOOL             g_fakeReady;

C_ASSERT(offsetof(FakeDns, dns) == sizeof(DWORD));

static XNDNS *FakeDnsAlloc(DWORD addr)
{
    int i;
    XNDNS *result = NULL;

    if (!g_fakeReady)
        return NULL;

    EnterCriticalSection(&g_fakeLock);
    for (i = 0; i < FAKE_SLOTS; i++) {
        if (!g_fake[i].inUse) {
            g_fake[i].inUse        = TRUE;
            g_fake[i].magic        = FAKE_MAGIC;
            memset(&g_fake[i].dns, 0, sizeof(g_fake[i].dns));
            g_fake[i].dns.iStatus = 0;
            g_fake[i].dns.cina    = 1;
            g_fake[i].dns.aina[0].s_addr = addr;
            result = &g_fake[i].dns;
            break;
        }
    }
    LeaveCriticalSection(&g_fakeLock);
    return result;
}

// Scans our own slots rather than stepping back from the caller's pointer,
// which would read a header that is not there on xam's allocations.
static BOOL FakeDnsFree(XNDNS *dns)
{
    int  i;
    BOOL freed = FALSE;

    if (!g_fakeReady || dns == NULL)
        return FALSE;

    EnterCriticalSection(&g_fakeLock);
    for (i = 0; i < FAKE_SLOTS; i++) {
        if (&g_fake[i].dns == dns && g_fake[i].magic == FAKE_MAGIC) {
            g_fake[i].magic = 0;
            g_fake[i].inUse = FALSE;
            freed = TRUE;
            break;
        }
    }
    LeaveCriticalSection(&g_fakeLock);
    return freed;
}

// helpers

// xbdm's own traffic is never redirected, and never logged either: it carries
// the debug channel and Neighborhood's file transfers, the very means of fixing
// a bad catch-all rule. Logging it is a feedback loop - every drained log line
// goes out through OutputDebugString, which xbdm transmits over its own sockets,
// which would log again. So every hook asks Active() before LOG_TRACE, not after.
static BOOL Active(DWORD caller)
{
    XepConfig *c = g_cfg;

    if (caller == XNCALLER_XBDM)
        return FALSE;
    return c != NULL && c->enabled;
}

// Private, loopback, link-local, multicast and broadcast: what forward_lan = 0
// keeps off the proxy. Addresses are network order, i.e. 192.168.x.x = 0xC0A8xxxx.
static BOOL IsLocalAddr(DWORD a)
{
    return (a & 0xFF000000u) == 0x0A000000u ||     // 10.0.0.0/8
           (a & 0xFFF00000u) == 0xAC100000u ||     // 172.16.0.0/12
           (a & 0xFFFF0000u) == 0xC0A80000u ||     // 192.168.0.0/16
           (a & 0xFF000000u) == 0x7F000000u ||     // 127.0.0.0/8
           (a & 0xFFFF0000u) == 0xA9FE0000u ||     // 169.254.0.0/16
           (a & 0xF0000000u) == 0xE0000000u ||     // 224.0.0.0/4 multicast
           a == 0xFFFFFFFFu || a == 0;             // broadcast, unspecified
}

// TRUE when forward_lan = 0 and this destination is on the local network.
static BOOL KeepLocal(DWORD addr)
{
    XepConfig *c = g_cfg;
    return c != NULL && !c->forwardLan && IsLocalAddr(addr);
}

static const SOCKADDR_IN *AsInet(const SOCKADDR *sa, int len)
{
    if (sa == NULL || len < (int)sizeof(SOCKADDR_IN))
        return NULL;
    if (((const SOCKADDR_IN *)sa)->sin_family != AF_INET)
        return NULL;
    return (const SOCKADDR_IN *)sa;
}

// Applies a rule to a copy of the destination; -1 when nothing matched.
// stream = TRUE for connect(). Tunnel modes carry TCP only, so a datagram that
// matches one goes out unchanged: no rewrite is logged or remembered for it.
static int ApplyRule(const SOCKADDR_IN *in, SOCKADDR_IN *out, const char *what, DWORD s,
                     BOOL stream)
{
    const XepRedirectRule *r;
    char from[16], to[16];

    if (KeepLocal(in->sin_addr.s_addr))
        return -1;                      // forward_lan = 0: no rule applies

    r = XepMatchRedirect(in->sin_addr.s_addr, in->sin_port);
    if (r == NULL)
        return -1;

    *out = *in;
    if (r->dstAddr != 0)
        out->sin_addr.s_addr = r->dstAddr;
    if (r->dstPort != 0)
        out->sin_port = r->dstPort;

    // A socks5/http rule with no target of its own means "use [proxy]".
    if (XEP_MODE_TUNNELS(r->mode) && r->dstAddr == 0) {
        XepConfig *c = g_cfg;
        if (c == NULL || c->proxyAddr == 0) {
            LOG_ERR("%s: proxy rule matched but no proxy host is configured", what);
            return -1;
        }
        out->sin_addr.s_addr = c->proxyAddr;
        if (r->dstPort == 0)
            out->sin_port = c->proxyPort;
    }

    if (r->mode == MODE_DROP) {
        XepFormatIp(in->sin_addr.s_addr, from, sizeof(from));
        LOG_INFO("%s: dropping %s:%u", what, from, in->sin_port);
        return MODE_DROP;
    }

    if (out->sin_addr.s_addr == in->sin_addr.s_addr && out->sin_port == in->sin_port)
        return r->mode;                 // rule matched but changes nothing

    if (XEP_MODE_TUNNELS(r->mode) && !stream)
        return r->mode;                 // caller passes the datagram through

    XepFormatIp(in->sin_addr.s_addr, from, sizeof(from));
    XepFormatIp(out->sin_addr.s_addr, to, sizeof(to));
    LOG_TRACE("%s: %s:%u -> %s:%u", what, from, in->sin_port, to, out->sin_port);

    // The reverse map is for recvfrom; a tunnelled TCP socket never needs it.
    if (!XEP_MODE_TUNNELS(r->mode))
        XepMapRemember(s, in->sin_addr.s_addr, in->sin_port, out->sin_addr.s_addr, out->sin_port);
    return r->mode;
}

// hooks

static int Hook_XNetStartup(DWORD caller, const XNetStartupParams *p)
{
    PFN_XNetStartup orig = (PFN_XNetStartup)g_orig[FN_XNetStartup];
    XepConfig *c = g_cfg;
    XNetStartupParams local;
    BYTE  want;
    size_t n;
    int   rc;

    if (!Active(caller))
        return orig(caller, p);

    LOG_TRACE("enter XNetStartup(caller=%u)", caller);

    if (!c->patchStartup || p == NULL)
        return orig(caller, p);

    want = (BYTE)((p->cfgFlags | c->startupForceFlags) & (BYTE)~c->startupClearFlags);

    // When the caller already asked for all we would force, pass its own struct
    // through untouched: an identical stack copy can only differ in subtle ways.
    if (want == p->cfgFlags && c->startupMaxDgram < 0 && c->startupMaxStream < 0) {
        LOG_INFO("XNetStartup: caller=%u size=%u flags %02X already as wanted, "
                 "passed through untouched", caller, p->cfgSizeOfStruct, p->cfgFlags);
        return orig(caller, p);
    }

    n = p->cfgSizeOfStruct;
    if (n == 0 || n > sizeof(local))
        n = sizeof(local);

    memset(&local, 0, sizeof(local));
    memcpy(&local, p, n);

    // Keep the caller's size: xam reads this field to decide how much of the
    // struct exists, so changing it is not ours to do.
    local.cfgSizeOfStruct = (BYTE)n;
    local.cfgFlags        = want;
    if (c->startupMaxDgram >= 0)
        local.cfgSockMaxDgramSockets = (BYTE)c->startupMaxDgram;
    if (c->startupMaxStream >= 0)
        local.cfgSockMaxStreamSockets = (BYTE)c->startupMaxStream;

    rc = orig(caller, &local);
    LOG_INFO("XNetStartup: caller=%u size=%u flags %02X -> %02X, rc=%d",
             caller, p->cfgSizeOfStruct, p->cfgFlags, local.cfgFlags, rc);
    return rc;
}

static int Hook_XNetDnsLookup(DWORD caller, const char *host, HANDLE hEvent, XNDNS **ppDns)
{
    PFN_XNetDnsLookup orig = (PFN_XNetDnsLookup)g_orig[FN_XNetDnsLookup];
    DWORD  addr = 0;
    XNDNS *fake;
    char   ip[16];

    if (!Active(caller))
        return orig(caller, host, hEvent, ppDns);

    LOG_TRACE("enter XNetDnsLookup(%s)", host != NULL ? host : "(null)");

    if (host == NULL || ppDns == NULL)
        return orig(caller, host, hEvent, ppDns);

    if (!XepMatchDns(host, &addr)) {
        LOG_TRACE("dns: %s -> real resolver", host);
        return orig(caller, host, hEvent, ppDns);
    }

    fake = FakeDnsAlloc(addr);
    if (fake == NULL) {
        LOG_ERR("dns: no spoof slot left for %s, falling through", host);
        return orig(caller, host, hEvent, ppDns);
    }

    *ppDns = fake;

    // Complete on return, so polling and event-waiting titles both proceed.
    if (hEvent != NULL) {
        PFN_WSASetEvent setEvent = (PFN_WSASetEvent)g_orig[FN_WSASetEvent];
        if (setEvent != NULL)
            setEvent(caller, hEvent);
        else
            SetEvent(hEvent);
    }

    XepFormatIp(addr, ip, sizeof(ip));
    LOG_INFO("dns: %s -> %s (spoofed)", host, ip);
    return 0;
}

static int Hook_XNetDnsRelease(DWORD caller, XNDNS *pDns)
{
    PFN_XNetDnsRelease orig = (PFN_XNetDnsRelease)g_orig[FN_XNetDnsRelease];
    // Free ours whoever asks; only the log line depends on the caller.
    if (Active(caller))
        LOG_TRACE("enter XNetDnsRelease(%08X)", (DWORD)pDns);

    if (FakeDnsFree(pDns))
        return 0;
    return orig(caller, pDns);
}

static int Hook_connect(DWORD caller, SOCKET s, const SOCKADDR *name, int namelen)
{
    PFN_connect orig = (PFN_connect)g_orig[FN_connect];
    const SOCKADDR_IN *in;
    SOCKADDR_IN target;
    int mode;
    int rc;

    if (!Active(caller))
        return orig(caller, s, name, namelen);

    LOG_TRACE("enter connect(s=%08X)", (DWORD)s);

    in = AsInet(name, namelen);
    if (in == NULL)
        return orig(caller, s, name, namelen);

    mode = ApplyRule(in, &target, "connect", s, TRUE);
    if (mode < 0)
        return orig(caller, s, name, namelen);
    if (mode == MODE_DROP)
        return SOCKET_ERROR;

    rc = orig(caller, s, (const SOCKADDR *)&target, (int)sizeof(target));

    if (XEP_MODE_TUNNELS(mode)) {
        BOOL ok;
        if (rc != 0) {
            // A non-blocking socket (XHttp uses them) reports "in progress".
            // Returning that would leave it heading for the proxy with no
            // tunnel, so the caller's first bytes would hit the proxy raw.
            // Finish the connect here instead and report it as done - a
            // non-blocking connect may legally succeed at once.
            PFN_WSAGetLastError lastErr = (PFN_WSAGetLastError)g_orig[FN_WSAGetLastError];
            char ip[16];
            int  wait = -1;

            if (lastErr != NULL && lastErr(caller) == WSAEWOULDBLOCK)
                wait = XepWaitSocket(caller, s, TRUE, g_cfg->socksTimeoutMs);
            if (wait != 1) {
                XepFormatIp(target.sin_addr.s_addr, ip, sizeof(ip));
                LOG_ERR("connect: proxy %s:%u unreachable (%s)", ip, target.sin_port,
                        wait == 0 ? "timed out" : "refused or failed");
                return SOCKET_ERROR;
            }
            LOG_TRACE("connect: non-blocking socket %08X reached the proxy", s);
            rc = 0;
        }
        ok = (mode == MODE_HTTP)
            ? XepHttpConnect(caller, s, in->sin_addr.s_addr, in->sin_port)
            : XepSocks5Connect(caller, s, in->sin_addr.s_addr, in->sin_port);
        if (!ok) {
            // Connected to the proxy but no tunnel: fail rather than let the title talk proxy protocol to a game server.
            LOG_ERR("connect: %s handshake failed on socket %08X",
                    mode == MODE_HTTP ? "HTTP CONNECT" : "SOCKS5", s);
            return SOCKET_ERROR;
        }
    }
    return rc;
}

static int Hook_sendto(DWORD caller, SOCKET s, const char *buf, int len, int flags,
                       const SOCKADDR *to, int tolen)
{
    PFN_sendto orig = (PFN_sendto)g_orig[FN_sendto];
    const SOCKADDR_IN *in;
    SOCKADDR_IN target;
    int mode;

    if (!Active(caller))
        return orig(caller, s, buf, len, flags, to, tolen);

    LOG_TRACE("enter sendto(s=%08X, len=%d)", (DWORD)s, len);

    in = AsInet(to, tolen);
    if (in == NULL)
        return orig(caller, s, buf, len, flags, to, tolen);

    mode = ApplyRule(in, &target, "sendto", s, FALSE);
    if (mode < 0)
        return orig(caller, s, buf, len, flags, to, tolen);
    if (mode == MODE_DROP)
        return len;                     // pretend it went out
    if (XEP_MODE_TUNNELS(mode)) {
        // Tunnels are TCP only (no SOCKS UDP ASSOCIATE, no UDP over CONNECT):
        // a bare datagram to the proxy port is worse than not redirecting.
        LOG_TRACE("sendto: proxy rule matched a datagram, passing through");
        return orig(caller, s, buf, len, flags, to, tolen);
    }

    if (g_cfg->logPackets)
        LOG_TRACE("sendto: %d bytes on socket %08X", len, s);

    return orig(caller, s, buf, len, flags, (const SOCKADDR *)&target, (int)sizeof(target));
}

static int Hook_WSASendTo(DWORD caller, SOCKET s, WSABUF *bufs, DWORD cbufs,
                          DWORD *sent, DWORD flags, const SOCKADDR *to, int tolen,
                          void *ov, void *cr)
{
    PFN_WSASendTo orig = (PFN_WSASendTo)g_orig[FN_WSASendTo];
    const SOCKADDR_IN *in;
    SOCKADDR_IN target;
    int mode;

    if (!Active(caller))
        return orig(caller, s, bufs, cbufs, sent, flags, to, tolen, ov, cr);

    LOG_TRACE("enter WSASendTo(s=%08X)", (DWORD)s);

    in = AsInet(to, tolen);
    if (in == NULL)
        return orig(caller, s, bufs, cbufs, sent, flags, to, tolen, ov, cr);

    mode = ApplyRule(in, &target, "WSASendTo", s, FALSE);
    if (mode < 0 || XEP_MODE_TUNNELS(mode))     // tunnels are TCP only, see sendto
        return orig(caller, s, bufs, cbufs, sent, flags, to, tolen, ov, cr);
    if (mode == MODE_DROP) {
        DWORD total = 0;
        DWORD i;
        for (i = 0; i < cbufs && bufs != NULL; i++)
            total += bufs[i].len;
        if (sent != NULL)
            *sent = total;
        return 0;
    }

    return orig(caller, s, bufs, cbufs, sent, flags,
                (const SOCKADDR *)&target, (int)sizeof(target), ov, cr);
}

static int Hook_recvfrom(DWORD caller, SOCKET s, char *buf, int len, int flags,
                         SOCKADDR *from, int *fromlen)
{
    PFN_recvfrom orig = (PFN_recvfrom)g_orig[FN_recvfrom];
    if (!Active(caller))
        return orig(caller, s, buf, len, flags, from, fromlen);

    LOG_TRACE("enter recvfrom(s=%08X)", (DWORD)s);
    int rc = orig(caller, s, buf, len, flags, from, fromlen);

    if (rc >= 0 && from != NULL && fromlen != NULL &&
        *fromlen >= (int)sizeof(SOCKADDR_IN)) {
        SOCKADDR_IN *in = (SOCKADDR_IN *)from;
        DWORD origAddr;
        WORD  origPort;

        if (in->sin_family == AF_INET &&
            XepMapReverse(s, in->sin_addr.s_addr, in->sin_port, &origAddr, &origPort)) {
            char a[16], b[16];
            XepFormatIp(in->sin_addr.s_addr, a, sizeof(a));
            XepFormatIp(origAddr, b, sizeof(b));
            LOG_TRACE("recvfrom: source %s:%u -> %s:%u", a, in->sin_port, b, origPort);
            in->sin_addr.s_addr = origAddr;
            in->sin_port = origPort;
        }
    }
    return rc;
}

static int Hook_WSARecvFrom(DWORD caller, SOCKET s, WSABUF *bufs, DWORD cbufs,
                            DWORD *recvd, DWORD *flags, SOCKADDR *from, int *fromlen,
                            void *ov, void *cr)
{
    PFN_WSARecvFrom orig = (PFN_WSARecvFrom)g_orig[FN_WSARecvFrom];
    if (!Active(caller))
        return orig(caller, s, bufs, cbufs, recvd, flags, from, fromlen, ov, cr);

    LOG_TRACE("enter WSARecvFrom(s=%08X)", (DWORD)s);
    int rc = orig(caller, s, bufs, cbufs, recvd, flags, from, fromlen, ov, cr);

    // Synchronous completion only: an overlapped receive writes the address
    // after this returns. See the README note on overlapped UDP.
    if (rc == 0 && ov == NULL && from != NULL && fromlen != NULL &&
        *fromlen >= (int)sizeof(SOCKADDR_IN)) {
        SOCKADDR_IN *in = (SOCKADDR_IN *)from;
        DWORD origAddr;
        WORD  origPort;

        if (in->sin_family == AF_INET &&
            XepMapReverse(s, in->sin_addr.s_addr, in->sin_port, &origAddr, &origPort)) {
            in->sin_addr.s_addr = origAddr;
            in->sin_port = origPort;
        }
    }
    return rc;
}

static int Hook_XNetXnAddrToInAddr(DWORD caller, const XNADDR *pxna,
                                   const XNKID *pxnkid, IN_ADDR *pina)
{
    PFN_XNetXnAddrToInAddr orig = (PFN_XNetXnAddrToInAddr)g_orig[FN_XNetXnAddrToInAddr];
    int rc = orig(caller, pxna, pxnkid, pina);

    if (rc == 0 || !Active(caller) || !g_cfg->mapXnAddrToIna || pxna == NULL || pina == NULL)
        return rc;

    // Registration failure is normal off Xbox Live. Hand back the peer's
    // plain address from the XNADDR and let the redirect rules route it.
    if (pxna->ina.s_addr != 0) {
        char ip[16];
        *pina = pxna->ina;
        XepFormatIp(pxna->ina.s_addr, ip, sizeof(ip));
        LOG_TRACE("XNetXnAddrToInAddr: rc=%d, using plain ina %s", rc, ip);
        return 0;
    }
    return rc;
}

static int Hook_XNetServerToInAddr(DWORD caller, IN_ADDR inaServer, DWORD dwServiceId,
                                   IN_ADDR *pina)
{
    PFN_XNetServerToInAddr orig = (PFN_XNetServerToInAddr)g_orig[FN_XNetServerToInAddr];
    int rc = orig(caller, inaServer, dwServiceId, pina);

    if (Active(caller) && pina != NULL) {
        char ip[16];
        XepFormatIp(rc == 0 ? pina->s_addr : inaServer.s_addr, ip, sizeof(ip));
        LOG_TRACE("XNetServerToInAddr: service %08X -> %s rc=%d", dwServiceId, ip, rc);
    }
    return rc;
}

static int Hook_XNetInAddrToXnAddr(DWORD caller, IN_ADDR ina, XNADDR *pxna, XNKID *pxnkid)
{
    PFN_XNetInAddrToXnAddr orig = (PFN_XNetInAddrToXnAddr)g_orig[FN_XNetInAddrToXnAddr];
    int rc = orig(caller, ina, pxna, pxnkid);

    if (Active(caller)) {
        char ip[16];
        XepFormatIp(ina.s_addr, ip, sizeof(ip));
        LOG_TRACE("XNetInAddrToXnAddr: %s rc=%d", ip, rc);
    }
    return rc;
}

static int Hook_XNetInAddrToServer(DWORD caller, IN_ADDR ina, IN_ADDR *pinaServer)
{
    PFN_XNetInAddrToServer orig = (PFN_XNetInAddrToServer)g_orig[FN_XNetInAddrToServer];
    int rc = orig(caller, ina, pinaServer);

    if (Active(caller)) {
        char ip[16];
        XepFormatIp(ina.s_addr, ip, sizeof(ip));
        LOG_TRACE("XNetInAddrToServer: %s rc=%d", ip, rc);
    }
    return rc;
}

static DWORD Hook_XNetGetConnectStatus(DWORD caller, IN_ADDR ina)
{
    PFN_XNetGetConnectStatus orig = (PFN_XNetGetConnectStatus)g_orig[FN_XNetGetConnectStatus];
    DWORD rc = orig(caller, ina);

    if (Active(caller) && g_cfg->forceConnectStatus && rc != XNET_CONNECT_STATUS_CONNECTED) {
        LOG_TRACE("XNetGetConnectStatus: %u -> CONNECTED (forced)", rc);
        return XNET_CONNECT_STATUS_CONNECTED;
    }
    return rc;
}

static int Hook_XNetQosLookup(DWORD caller, UINT cxna, const XNADDR **apxna,
                              const XNKID **apxnkid, const XNKEY **apxnkey,
                              UINT cina, const IN_ADDR *aina, const DWORD *adwServiceId,
                              UINT cProbes, DWORD dwBitsPerSec, DWORD dwFlags,
                              HANDLE hEvent, XNQOS **ppxnqos)
{
    PFN_XNetQosLookup orig = (PFN_XNetQosLookup)g_orig[FN_XNetQosLookup];

    if (Active(caller) && g_cfg->bypassQos) {
        LOG_TRACE("XNetQosLookup: failing fast (%u addrs, %u servers)", cxna, cina);
        return 10022;                   // WSAEINVAL, so the title stops waiting
    }
    return orig(caller, cxna, apxna, apxnkid, apxnkey, cina, aina, adwServiceId,
                cProbes, dwBitsPerSec, dwFlags, hEvent, ppxnqos);
}

static int Hook_XNetQosServiceLookup(DWORD caller, DWORD dwFlags, HANDLE hEvent,
                                     XNQOS **ppxnqos)
{
    PFN_XNetQosServiceLookup orig = (PFN_XNetQosServiceLookup)g_orig[FN_XNetQosServiceLookup];

    if (Active(caller) && g_cfg->bypassQos) {
        LOG_TRACE("XNetQosServiceLookup: failing fast");
        return 10022;
    }
    return orig(caller, dwFlags, hEvent, ppxnqos);
}

// NOTE: tls_ignore_cert_errors no longer uses XHTTP_OPTION_SECURITY_FEATURE (that
// option is Xbox-Live-specific and returns failure for general CA trust). The fix
// is the one-instruction xam handshake-state patch, XepApplyTlsFix() in patch.cpp.

static void *Hook_XHttpConnect(DWORD caller, void *hSession, const char *server,
                               WORD port, DWORD reserved)
{
    PFN_XHttpConnect orig = (PFN_XHttpConnect)g_orig[FN_XHttpConnect];
    const XepHttpRule *r;

    if (!Active(caller))
        return orig(caller, hSession, server, port, reserved);

    LOG_TRACE("enter XHttpConnect(%s:%u)", server != NULL ? server : "(null)", port);

    if (server == NULL)
        return orig(caller, hSession, server, port, reserved);

    // An IP literal on the LAN is kept local too. A hostname can't be judged
    // here (XepParseIp gives 0, which must not read as "local"); if it
    // resolves to a LAN address, the connect hook still keeps it.
    DWORD literal = XepParseIp(server);
    if (literal != 0 && KeepLocal(literal)) {
        LOG_TRACE("XHttpConnect: %s:%u is local, forward_lan = 0", server, port);
        return orig(caller, hSession, server, port, reserved);
    }

    r = XepMatchHttp(server);
    if (r == NULL) {
        LOG_TRACE("XHttpConnect: %s:%u (unchanged)", server, port);
        return orig(caller, hSession, server, port, reserved);
    }

    LOG_INFO("XHttpConnect: %s:%u -> %s:%u", server, port, r->dstHost,
             r->dstPort != 0 ? r->dstPort : port);
    return orig(caller, hSession, r->dstHost,
                r->dstPort != 0 ? r->dstPort : port, reserved);
}

// Trace-only hooks, off by default.

static int Hook_socket(DWORD caller, int af, int type, int proto)
{
    PFN_socket orig = (PFN_socket)g_orig[FN_socket];
    int s = orig(caller, af, type, proto);
    if (Active(caller))
        LOG_TRACE("socket: af=%d type=%d proto=%d -> %08X caller=%u", af, type, proto, s, caller);
    return s;
}

static int Hook_closesocket(DWORD caller, SOCKET s)
{
    PFN_closesocket orig = (PFN_closesocket)g_orig[FN_closesocket];
    XepMapForget(s);                    // any caller: a reused handle must not inherit a rewrite
    if (Active(caller))
        LOG_TRACE("closesocket: %08X", s);
    return orig(caller, s);
}

static int Hook_bind(DWORD caller, SOCKET s, const SOCKADDR *name, int namelen)
{
    PFN_bind orig = (PFN_bind)g_orig[FN_bind];
    const SOCKADDR_IN *in = AsInet(name, namelen);

    if (in != NULL && Active(caller)) {
        char ip[16];
        XepFormatIp(in->sin_addr.s_addr, ip, sizeof(ip));
        LOG_TRACE("bind: %08X to %s:%u", s, ip, in->sin_port);
    }
    return orig(caller, s, name, namelen);
}

static int Hook_setsockopt(DWORD caller, SOCKET s, int level, int optname,
                           const char *optval, int optlen)
{
    PFN_setsockopt orig = (PFN_setsockopt)g_orig[FN_setsockopt];
    if (Active(caller))
        LOG_TRACE("setsockopt: %08X level=%04X opt=%04X len=%d", s, level, optname, optlen);
    return orig(caller, s, level, optname, optval, optlen);
}

static int Hook_send(DWORD caller, SOCKET s, const char *buf, int len, int flags)
{
    PFN_send orig = (PFN_send)g_orig[FN_send];
    int rc = orig(caller, s, buf, len, flags);
    if (Active(caller) && g_cfg->logPackets)
        LOG_TRACE("send: %08X %d bytes -> %d", s, len, rc);
    return rc;
}

static int Hook_recv(DWORD caller, SOCKET s, char *buf, int len, int flags)
{
    PFN_recv orig = (PFN_recv)g_orig[FN_recv];
    int rc = orig(caller, s, buf, len, flags);
    if (Active(caller) && g_cfg->logPackets)
        LOG_TRACE("recv: %08X %d bytes -> %d", s, len, rc);
    return rc;
}

static int Hook_select(DWORD caller, int nfds, void *rd, void *wr, void *ex, const void *tv)
{
    PFN_select orig = (PFN_select)g_orig[FN_select];
    return orig(caller, nfds, rd, wr, ex, tv);
}

// install

// Indexed by XepFunc: same order as g_funcs, entry for entry. NULL means resolve but never patch.
static void *const g_detours[FN_COUNT] = {
    (void *)Hook_socket,
    (void *)Hook_closesocket,
    (void *)Hook_setsockopt,
    (void *)Hook_bind,
    (void *)Hook_connect,
    (void *)Hook_select,
    (void *)Hook_recv,
    (void *)Hook_recvfrom,
    (void *)Hook_WSARecvFrom,
    (void *)Hook_send,
    (void *)Hook_sendto,
    (void *)Hook_WSASendTo,
    NULL,                               // WSAGetLastError: resolved only
    NULL,                               // WSASetEvent: resolved only
    (void *)Hook_XNetStartup,
    (void *)Hook_XNetXnAddrToInAddr,
    (void *)Hook_XNetServerToInAddr,
    (void *)Hook_XNetInAddrToXnAddr,
    (void *)Hook_XNetInAddrToServer,
    (void *)Hook_XNetGetConnectStatus,
    (void *)Hook_XNetDnsLookup,
    (void *)Hook_XNetDnsRelease,
    (void *)Hook_XNetQosLookup,
    (void *)Hook_XNetQosServiceLookup,
    NULL,                               // XNetGetTitleXnAddr: resolved only
    (void *)Hook_XHttpConnect,
    NULL,                               // XHttpSetOption: called, never patched
};

// Resolve without patching. Safe to call more than once.
BOOL XepHooksResolve(void)
{
    XepConfig *c = g_cfg;
    HANDLE xam = NULL;
    int    i;
    int    resolved = 0;

    if (g_resolved)
        return TRUE;
    if (c == NULL)
        return FALSE;

    if (!g_mapReady) {
        InitializeCriticalSection(&g_mapLock);
        g_mapReady = TRUE;
    }
    if (!g_fakeReady) {
        InitializeCriticalSection(&g_fakeLock);
        g_fakeReady = TRUE;
    }

    if (XexGetModuleHandle("xam.xex", &xam) < 0 || xam == NULL) {
        LOG_ERR("hooks: xam.xex not found");
        return FALSE;
    }

    for (i = 0; i < FN_COUNT; i++) {
        void *fn = NULL;

        if (XexGetProcedureAddress(xam, c->ordinal[i], &fn) < 0 || fn == NULL) {
            LOG_ERR("hooks: %s%s (ordinal %u) did not resolve",
                    g_funcs[i].prefix, g_funcs[i].name, c->ordinal[i]);
            continue;
        }
        g_target[i] = fn;
        g_orig[i]   = fn;               // real address until a hook replaces it
        resolved++;
        LOG_TRACE("hooks: %s%s = %08X (ordinal %u)",
                  g_funcs[i].prefix, g_funcs[i].name, (DWORD)fn, c->ordinal[i]);
    }
    LOG_INFO("hooks: resolved %d/%d exports from xam.xex", resolved, FN_COUNT);

    g_resolved = (resolved > 0);
    return g_resolved;
}

BOOL XepHooksInstall(void)
{
    XepConfig *c = g_cfg;
    int    i;
    int    hooked = 0;

    if (g_installed) {
        LOG_INFO("hooks: already installed");
        return TRUE;
    }
    if (c == NULL)
        return FALSE;

    if (!XepHooksResolve())
        return FALSE;

    if (!XepPatchInit())
        return FALSE;

    for (i = 0; i < FN_COUNT; i++) {
        if (!g_funcs[i].hookable || !c->hookEnabled[i])
            continue;
        if (g_target[i] == NULL || g_detours[i] == NULL)
            continue;

        // Log before patching: if this one takes the console down, its name is
        // the last line in the log, not the previous success.
        LOG_INFO("hooks: patching %s%s at %08X",
                 g_funcs[i].prefix, g_funcs[i].name, (DWORD)g_target[i]);

        // Into the live slot directly: the detour goes live the moment XepHook
        // writes the jump, so the trampoline must be published before that write.
        if (XepHook(g_target[i], g_detours[i], &g_orig[i])) {
            hooked++;
        } else {
            LOG_ERR("hooks: %s%s left unhooked", g_funcs[i].prefix, g_funcs[i].name);
        }
    }

    LOG_INFO("hooks: %d installed", hooked);
    g_hookCount = hooked;
    g_installed = (hooked > 0);
    return g_installed;
}
