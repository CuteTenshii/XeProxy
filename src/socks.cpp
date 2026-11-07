// socks.cpp: SOCKS5 and HTTP CONNECT, run inside the hooked connect() once the
// socket is connected to the proxy. Blocking and non-blocking sockets both
// work: a would-block is waited out on select, bounded by socks_timeout_ms.

#include "netdll.h"

#define SOCKS_VER        0x05
#define SOCKS_NO_AUTH    0x00
#define SOCKS_USERPASS   0x02
#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_ATYP_IPV4  0x01

static BOOL SetTimeout(DWORD caller, SOCKET s, DWORD ms)
{
    PFN_setsockopt setsockopt_ = (PFN_setsockopt)g_orig[FN_setsockopt];
    DWORD value = ms;

    if (setsockopt_ == NULL)
        return FALSE;

    return setsockopt_(caller, s, SOL_SOCKET, SO_RCVTIMEO,
                       (const char *)&value, sizeof(value)) == 0;
}

static BOOL WouldBlock(DWORD caller)
{
    PFN_WSAGetLastError err = (PFN_WSAGetLastError)g_orig[FN_WSAGetLastError];
    return err != NULL && err(caller) == WSAEWOULDBLOCK;
}

// Waits up to ms for s to become readable (forWrite = FALSE) or writable /
// connected (forWrite = TRUE). 1 = ready, 0 = timed out, -1 = failed.
// fd_set is filled by hand and checked through fd_count: FD_ISSET needs
// __WSAFDIsSet from xnet.lib, which a xam plugin does not link.
int XepWaitSocket(DWORD caller, SOCKET s, BOOL forWrite, DWORD ms)
{
    PFN_select select_ = (PFN_select)g_orig[FN_select];
    fd_set   ready;
    fd_set   failed;
    timeval  tv;
    int      rc;

    if (select_ == NULL)
        return -1;

    ready.fd_count     = 1;
    ready.fd_array[0]  = s;
    failed.fd_count    = 1;
    failed.fd_array[0] = s;
    tv.tv_sec  = (long)(ms / 1000u);
    tv.tv_usec = (long)((ms % 1000u) * 1000u);

    rc = select_(caller, 0, forWrite ? NULL : &ready, forWrite ? &ready : NULL,
                 &failed, &tv);
    if (rc < 0)
        return -1;
    if (rc == 0)
        return 0;
    if (failed.fd_count != 0)
        return -1;                      // e.g. a non-blocking connect refused
    return ready.fd_count != 0 ? 1 : 0;
}

// Both loops work on blocking and non-blocking sockets alike: a would-block
// waits on select for the rest of the proxy timeout instead of failing.
static BOOL SendAll(DWORD caller, SOCKET s, const BYTE *p, int len)
{
    PFN_send send_ = (PFN_send)g_orig[FN_send];
    XepConfig *c = g_cfg;
    int sent = 0;

    if (send_ == NULL || c == NULL)
        return FALSE;

    while (sent < len) {
        int n = send_(caller, s, (const char *)p + sent, len - sent, 0);
        if (n < 0 && WouldBlock(caller)) {
            if (XepWaitSocket(caller, s, TRUE, c->socksTimeoutMs) != 1)
                return FALSE;
            continue;
        }
        if (n <= 0)
            return FALSE;
        sent += n;
    }
    return TRUE;
}

static BOOL RecvAll(DWORD caller, SOCKET s, BYTE *p, int len)
{
    PFN_recv recv_ = (PFN_recv)g_orig[FN_recv];
    XepConfig *c = g_cfg;
    int got = 0;

    if (recv_ == NULL || c == NULL)
        return FALSE;

    while (got < len) {
        int n = recv_(caller, s, (char *)p + got, len - got, 0);
        if (n < 0 && WouldBlock(caller)) {
            if (XepWaitSocket(caller, s, FALSE, c->socksTimeoutMs) != 1)
                return FALSE;
            continue;
        }
        if (n <= 0)
            return FALSE;
        got += n;
    }
    return TRUE;
}

BOOL XepSocks5Connect(DWORD caller, SOCKET s, DWORD dstAddr, WORD dstPort)
{
    XepConfig *c = g_cfg;
    BYTE  buf[300];
    int   n;
    BOOL  wantAuth;
    char  ip[16];

    if (c == NULL)
        return FALSE;
    if (g_orig[FN_send] == NULL || g_orig[FN_recv] == NULL) {
        LOG_ERR("socks5: send/recv not resolved");
        return FALSE;
    }

    wantAuth = (c->socksUser[0] != '\0');
    SetTimeout(caller, s, c->socksTimeoutMs);

    // Greeting: version, method count, methods.
    n = 0;
    buf[n++] = SOCKS_VER;
    buf[n++] = (BYTE)(wantAuth ? 2 : 1);
    buf[n++] = SOCKS_NO_AUTH;
    if (wantAuth)
        buf[n++] = SOCKS_USERPASS;

    if (!SendAll(caller, s, buf, n) || !RecvAll(caller, s, buf, 2)) {
        LOG_ERR("socks5: greeting failed (non-blocking socket, or no proxy)");
        SetTimeout(caller, s, 0);
        return FALSE;
    }
    if (buf[0] != SOCKS_VER) {
        LOG_ERR("socks5: bad version %02X in method reply", buf[0]);
        SetTimeout(caller, s, 0);
        return FALSE;
    }

    if (buf[1] == SOCKS_USERPASS) {
        size_t lu = strlen(c->socksUser);
        size_t lp = strlen(c->socksPass);

        if (!wantAuth || lu > 255 || lp > 255) {
            LOG_ERR("socks5: proxy wants user/pass and none is configured");
            SetTimeout(caller, s, 0);
            return FALSE;
        }
        n = 0;
        buf[n++] = 0x01;                            // user/pass subnegotiation
        buf[n++] = (BYTE)lu;
        memcpy(buf + n, c->socksUser, lu); n += (int)lu;
        buf[n++] = (BYTE)lp;
        memcpy(buf + n, c->socksPass, lp); n += (int)lp;

        if (!SendAll(caller, s, buf, n) || !RecvAll(caller, s, buf, 2) || buf[1] != 0) {
            LOG_ERR("socks5: authentication rejected");
            SetTimeout(caller, s, 0);
            return FALSE;
        }
    } else if (buf[1] != SOCKS_NO_AUTH) {
        LOG_ERR("socks5: proxy chose unsupported method %02X", buf[1]);
        SetTimeout(caller, s, 0);
        return FALSE;
    }

    // CONNECT request. Address and port are already network order.
    n = 0;
    buf[n++] = SOCKS_VER;
    buf[n++] = SOCKS_CMD_CONNECT;
    buf[n++] = 0x00;
    buf[n++] = SOCKS_ATYP_IPV4;
    buf[n++] = (BYTE)(dstAddr >> 24);
    buf[n++] = (BYTE)(dstAddr >> 16);
    buf[n++] = (BYTE)(dstAddr >> 8);
    buf[n++] = (BYTE)dstAddr;
    buf[n++] = (BYTE)(dstPort >> 8);
    buf[n++] = (BYTE)dstPort;

    if (!SendAll(caller, s, buf, n) || !RecvAll(caller, s, buf, 4)) {
        LOG_ERR("socks5: CONNECT request failed");
        SetTimeout(caller, s, 0);
        return FALSE;
    }
    if (buf[1] != 0x00) {
        XepFormatIp(dstAddr, ip, sizeof(ip));
        LOG_ERR("socks5: proxy refused %s:%u, reply=%02X", ip, dstPort, buf[1]);
        SetTimeout(caller, s, 0);
        return FALSE;
    }

    // Drain the proxy's bound address; its length depends on ATYP.
    switch (buf[3]) {
    case 0x01: n = 4 + 2; break;                        // IPv4
    case 0x04: n = 16 + 2; break;                       // IPv6
    case 0x03:                                          // domain name
        if (!RecvAll(caller, s, buf, 1)) {
            SetTimeout(caller, s, 0);
            return FALSE;
        }
        n = buf[0] + 2;
        break;
    default:
        LOG_ERR("socks5: unknown ATYP %02X in reply", buf[3]);
        SetTimeout(caller, s, 0);
        return FALSE;
    }
    if (!RecvAll(caller, s, buf, n)) {
        SetTimeout(caller, s, 0);
        return FALSE;
    }

    SetTimeout(caller, s, 0);

    XepFormatIp(dstAddr, ip, sizeof(ip));
    LOG_INFO("socks5: tunnel established to %s:%u on socket %08X", ip, dstPort, s);
    return TRUE;
}

// HTTP CONNECT, for a plain HTTP proxy (mitmproxy's default "regular" mode).
// The reply is read a byte at a time up to the blank line that ends its
// headers, so not one byte of the tunnelled stream is consumed here.
BOOL XepHttpConnect(DWORD caller, SOCKET s, DWORD dstAddr, WORD dstPort)
{
    XepConfig *c = g_cfg;
    char  req[128];
    char  rep[512];
    char  ip[16];
    int   n;
    int   got = 0;

    if (c == NULL)
        return FALSE;
    if (g_orig[FN_send] == NULL || g_orig[FN_recv] == NULL) {
        LOG_ERR("http: send/recv not resolved");
        return FALSE;
    }

    XepFormatIp(dstAddr, ip, sizeof(ip));
    n = _snprintf(req, sizeof(req),
                  "CONNECT %s:%u HTTP/1.1\r\nHost: %s:%u\r\n\r\n",
                  ip, dstPort, ip, dstPort);
    if (n <= 0 || n >= (int)sizeof(req))
        return FALSE;

    SetTimeout(caller, s, c->socksTimeoutMs);

    if (!SendAll(caller, s, (const BYTE *)req, n)) {
        LOG_ERR("http: CONNECT %s:%u not sent", ip, dstPort);
        SetTimeout(caller, s, 0);
        return FALSE;
    }

    // Until "\r\n\r\n". A reply longer than the buffer is not a CONNECT reply.
    while (got < (int)sizeof(rep) - 1) {
        if (!RecvAll(caller, s, (BYTE *)rep + got, 1)) {
            LOG_ERR("http: no reply to CONNECT %s:%u (non-blocking socket, or no proxy)",
                    ip, dstPort);
            SetTimeout(caller, s, 0);
            return FALSE;
        }
        got++;
        if (got >= 4 && memcmp(rep + got - 4, "\r\n\r\n", 4) == 0)
            break;
    }
    rep[got] = '\0';
    SetTimeout(caller, s, 0);

    if (got < 4 || memcmp(rep + got - 4, "\r\n\r\n", 4) != 0) {
        LOG_ERR("http: CONNECT %s:%u reply too long", ip, dstPort);
        return FALSE;
    }

    // "HTTP/1.x 200 ..."
    if (strncmp(rep, "HTTP/1.", 7) != 0 || strncmp(rep + 8, " 200", 4) != 0) {
        char *eol = strchr(rep, '\r');
        if (eol != NULL)
            *eol = '\0';
        LOG_ERR("http: proxy refused %s:%u: %s", ip, dstPort, rep);
        return FALSE;
    }

    LOG_INFO("http: tunnel established to %s:%u on socket %08X", ip, dstPort, s);
    return TRUE;
}
