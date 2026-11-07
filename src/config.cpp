// config.cpp: xeproxy.ini discovery, parsing and hot reload.

#include "xep.h"

// Ordinals from Xenia xam_table and xkelib xamext.def; overridable from [ordinals].

const XepFuncInfo g_funcs[FN_COUNT] = {
    { "NetDll_", "socket",                   3, TRUE  },
    { "NetDll_", "closesocket",              4, TRUE  },
    { "NetDll_", "setsockopt",               7, TRUE  },
    { "NetDll_", "bind",                    11, TRUE  },
    { "NetDll_", "connect",                 12, TRUE  },
    { "NetDll_", "select",                  15, TRUE  },
    { "NetDll_", "recv",                    18, TRUE  },
    { "NetDll_", "recvfrom",                20, TRUE  },
    { "NetDll_", "WSARecvFrom",             21, TRUE  },
    { "NetDll_", "send",                    22, TRUE  },
    { "NetDll_", "sendto",                  24, TRUE  },
    { "NetDll_", "WSASendTo",               25, TRUE  },
    { "NetDll_", "WSAGetLastError",         27, FALSE },
    { "NetDll_", "WSASetEvent",             31, FALSE },
    { "NetDll_", "XNetStartup",             51, TRUE  },
    { "NetDll_", "XNetXnAddrToInAddr",      57, TRUE  },
    { "NetDll_", "XNetServerToInAddr",      58, TRUE  },
    { "NetDll_", "XNetInAddrToXnAddr",      60, TRUE  },
    { "NetDll_", "XNetInAddrToServer",      61, TRUE  },
    { "NetDll_", "XNetGetConnectStatus",    66, TRUE  },
    { "NetDll_", "XNetDnsLookup",           67, TRUE  },
    { "NetDll_", "XNetDnsRelease",          68, TRUE  },
    { "NetDll_", "XNetQosLookup",           70, TRUE  },
    { "NetDll_", "XNetQosServiceLookup",    71, TRUE  },
    { "NetDll_", "XNetGetTitleXnAddr",      73, FALSE },
    { "NetDll_", "XHttpConnect",           205, TRUE  },
    { "NetDll_", "XHttpSetOption",         215, FALSE },
};

void *g_orig[FN_COUNT];

static XepConfig g_buffers[2];
static int       g_live = -1;
XepConfig *volatile g_cfg;

static char      g_path[XEP_MAX_PATH];
static DWORD     g_lastSize;
static FILETIME  g_lastWrite;

#define INI_MAX_BYTES XEP_INI_MAX_BYTES
static char g_text[INI_MAX_BYTES + 1];

static const char *const kSearchPaths[] = {
    "Usb0:\\xeproxy.ini",
    "Usb1:\\xeproxy.ini",
    "Usb2:\\xeproxy.ini",
    "Hdd:\\xeproxy.ini",
    "Hdd:\\plugins\\xeproxy.ini",
    "Flash:\\xeproxy.ini",
    "Game:\\xeproxy.ini",
};

const char *XepConfigPath(void)
{
    return g_path[0] != '\0' ? g_path : "(none)";
}

static char *Trim(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t')
        s++;
    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        end--;
    *end = '\0';
    return s;
}

static BOOL ParseU32(const char *s, DWORD *out)
{
    DWORD v = 0;
    BOOL  any = FALSE;
    BOOL  neg = FALSE;

    if (s == NULL)
        return FALSE;
    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == '-') { neg = TRUE; s++; }

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s += 2;
        for (; *s != '\0' && *s != ' ' && *s != '\t'; s++) {
            DWORD d;
            if (*s >= '0' && *s <= '9')      d = (DWORD)(*s - '0');
            else if (*s >= 'a' && *s <= 'f') d = (DWORD)(*s - 'a' + 10);
            else if (*s >= 'A' && *s <= 'F') d = (DWORD)(*s - 'A' + 10);
            else return FALSE;
            v = (v << 4) | d;
            any = TRUE;
        }
    } else {
        for (; *s != '\0' && *s != ' ' && *s != '\t'; s++) {
            if (*s < '0' || *s > '9')
                return FALSE;
            v = v * 10 + (DWORD)(*s - '0');
            any = TRUE;
        }
    }

    while (*s == ' ' || *s == '\t')
        s++;
    if (!any || *s != '\0')
        return FALSE;

    *out = neg ? (DWORD)(-(LONG)v) : v;
    return TRUE;
}

static BOOL ParseBool(const char *s, BOOL *out)
{
    DWORD v;

    if (ParseU32(s, &v)) {
        *out = (v != 0);
        return TRUE;
    }
    if (XepHostMatch("true", s) || XepHostMatch("yes", s) || XepHostMatch("on", s)) {
        *out = TRUE;
        return TRUE;
    }
    if (XepHostMatch("false", s) || XepHostMatch("no", s) || XepHostMatch("off", s)) {
        *out = FALSE;
        return TRUE;
    }
    return FALSE;
}

static BOOL ParseMode(const char *s, XepMode *out)
{
    if (XepHostMatch("redirect", s) || XepHostMatch("nat", s)) { *out = MODE_REDIRECT; return TRUE; }
    if (XepHostMatch("socks5", s)   || XepHostMatch("socks", s)) { *out = MODE_SOCKS5; return TRUE; }
    if (XepHostMatch("drop", s)     || XepHostMatch("block", s)) { *out = MODE_DROP;   return TRUE; }
    if (XepHostMatch("http", s)     || XepHostMatch("connect", s)) { *out = MODE_HTTP; return TRUE; }
    return FALSE;
}

static int FindFunc(const char *name)
{
    int i;
    for (i = 0; i < FN_COUNT; i++)
        if (XepHostMatch(g_funcs[i].name, name))
            return i;
    return -1;
}

static void ApplyDefaults(XepConfig *c)
{
    int i;

    memset(c, 0, sizeof(*c));

    c->enabled         = TRUE;
    XepStrCopy(c->logPath, sizeof(c->logPath), "Hdd:\\xeproxy.log");
    c->logLevel        = 2;
    c->logPackets      = FALSE;
    c->reloadSeconds   = 0;
    c->waitForConfigMs = 60000;

    c->patchStartup      = TRUE;
    c->startupForceFlags = XNET_STARTUP_BYPASS_SECURITY;
    c->startupClearFlags = 0;
    c->startupMaxDgram   = -1;
    c->startupMaxStream  = -1;

    c->proxyMode     = MODE_REDIRECT;
    c->socksTimeoutMs = 5000;
    c->forwardLan    = TRUE;

    c->dumpWords   = 16;

    c->mapXnAddrToIna = TRUE;

    for (i = 0; i < FN_COUNT; i++)
        c->ordinal[i] = g_funcs[i].ordinal;

    c->hookEnabled[FN_XNetStartup]   = TRUE;
    c->hookEnabled[FN_XNetDnsLookup] = TRUE;
    c->hookEnabled[FN_XNetDnsRelease]= TRUE;
    c->hookEnabled[FN_connect]       = TRUE;
    c->hookEnabled[FN_sendto]        = TRUE;
    c->hookEnabled[FN_WSASendTo]     = TRUE;
    c->hookEnabled[FN_recvfrom]      = TRUE;
    c->hookEnabled[FN_WSARecvFrom]   = TRUE;
    c->hookEnabled[FN_XHttpConnect]  = TRUE;
}

static BOOL ParseRedirectTarget(const XepConfig *c, char *value, XepRedirectRule *r)
{
    char *comma = strchr(value, ',');
    char *colon;

    r->mode = c->proxyMode;

    if (comma != NULL) {
        *comma = '\0';
        if (!ParseMode(Trim(comma + 1), &r->mode))
            return FALSE;
    }
    value = Trim(value);

    if (XepHostMatch("drop", value) || XepHostMatch("block", value)) {
        r->mode    = MODE_DROP;
        r->dstAddr = 0;
        r->dstPort = 0;
        return TRUE;
    }

    if (XepHostMatch("passthrough", value) || XepHostMatch("keep", value) ||
        XepHostMatch("direct", value)) {
        r->mode    = MODE_REDIRECT;
        r->dstAddr = 0;
        r->dstPort = 0;
        return TRUE;
    }

    colon = strchr(value, ':');
    if (colon != NULL) {
        DWORD port;
        *colon = '\0';
        if (!ParseU32(colon + 1, &port) || port > 65535)
            return FALSE;
        r->dstPort = (WORD)port;
    } else {
        r->dstPort = 0;
    }

    value = Trim(value);
    if (value[0] == '\0') {
        r->dstAddr = 0;                 // keep address, change port
    } else if (XepHostMatch("proxy", value)) {
        r->dstAddr = c->proxyAddr;
        if (r->dstPort == 0)
            r->dstPort = c->proxyPort;
    } else {
        r->dstAddr = XepParseIp(value);
        if (r->dstAddr == 0)
            return FALSE;
    }
    return TRUE;
}

static BOOL ParseRedirectMatch(char *key, XepRedirectRule *r)
{
    char *slash;
    char *colon;

    key = Trim(key);

    colon = strrchr(key, ':');
    if (colon != NULL) {
        DWORD port;
        *colon = '\0';
        if (!ParseU32(colon + 1, &port) || port > 65535)
            return FALSE;
        r->port = (WORD)port;
    } else {
        r->port = 0;
    }

    key = Trim(key);
    if (key[0] == '\0' || (key[0] == '*' && key[1] == '\0')) {
        r->net  = 0;
        r->mask = 0;
        return TRUE;
    }

    slash = strchr(key, '/');
    if (slash != NULL) {
        DWORD bits;
        *slash = '\0';
        if (!ParseU32(slash + 1, &bits) || bits > 32)
            return FALSE;
        r->mask = (bits == 0) ? 0 : (0xFFFFFFFFu << (32 - bits));
    } else {
        r->mask = 0xFFFFFFFFu;
    }

    key    = Trim(key);
    r->net = XepParseIp(key);
    if (r->net == 0 && r->mask != 0 && strcmp(key, "0.0.0.0") != 0)
        return FALSE;
    r->net &= r->mask;
    return TRUE;
}

enum Section {
    SEC_NONE = 0, SEC_GENERAL, SEC_STARTUP, SEC_PROXY,
    SEC_DNS, SEC_REDIRECT, SEC_XHTTP, SEC_HOOKS, SEC_ORDINALS, SEC_UNKNOWN
};

static Section SectionFromName(const char *name)
{
    if (XepHostMatch("general",     name)) return SEC_GENERAL;
    if (XepHostMatch("xnetstartup", name)) return SEC_STARTUP;
    if (XepHostMatch("proxy",       name)) return SEC_PROXY;
    if (XepHostMatch("dns",         name)) return SEC_DNS;
    if (XepHostMatch("redirect",    name)) return SEC_REDIRECT;
    if (XepHostMatch("xhttp",       name)) return SEC_XHTTP;
    if (XepHostMatch("hooks",       name)) return SEC_HOOKS;
    if (XepHostMatch("ordinals",    name)) return SEC_ORDINALS;
    return SEC_UNKNOWN;
}

static void ParseScalarLine(XepConfig *c, Section sec, char *key, char *value)
{
    DWORD u;
    BOOL  b;

    if (sec == SEC_GENERAL) {
        if      (XepHostMatch("enabled", key)   && ParseBool(value, &b)) c->enabled = b;
        else if (XepHostMatch("log", key)) {
            XepStrCopy(c->logPath, sizeof(c->logPath), value);
            c->logPathExplicit = (value[0] != '\0');
        }
        else if (XepHostMatch("log_level", key) && ParseU32(value, &u)) c->logLevel = (int)u;
        else if (XepHostMatch("log_packets", key) && ParseBool(value, &b)) c->logPackets = b;
        else if (XepHostMatch("config_reload_seconds", key) && ParseU32(value, &u)) c->reloadSeconds = u;
        else if (XepHostMatch("wait_for_config_ms", key) && ParseU32(value, &u)) c->waitForConfigMs = u;
        else if (XepHostMatch("force_connect_status", key) && ParseBool(value, &b)) c->forceConnectStatus = b;
        else if (XepHostMatch("bypass_qos", key) && ParseBool(value, &b)) c->bypassQos = b;
        else if (XepHostMatch("map_xnaddr_to_ina", key) && ParseBool(value, &b)) c->mapXnAddrToIna = b;
        else if (XepHostMatch("dump_at", key) && ParseU32(value, &u)) c->dumpAt = u;
        else if (XepHostMatch("trace_live", key) && ParseBool(value, &b)) c->traceLive = b;
        else if (XepHostMatch("tls_ignore_cert_errors", key) && ParseBool(value, &b)) c->tlsIgnoreCert = b;
        else if (XepHostMatch("dump_words", key) && ParseU32(value, &u)) c->dumpWords = u;
        return;
    }

    if (sec == SEC_STARTUP) {
        if      (XepHostMatch("patch", key) && ParseBool(value, &b)) c->patchStartup = b;
        else if (XepHostMatch("force_flags", key) && ParseU32(value, &u)) c->startupForceFlags = (BYTE)u;
        else if (XepHostMatch("clear_flags", key) && ParseU32(value, &u)) c->startupClearFlags = (BYTE)u;
        else if (XepHostMatch("max_dgram_sockets", key) && ParseU32(value, &u)) c->startupMaxDgram = (int)u;
        else if (XepHostMatch("max_stream_sockets", key) && ParseU32(value, &u)) c->startupMaxStream = (int)u;
        return;
    }

    if (sec == SEC_PROXY) {
        if      (XepHostMatch("host", key)) c->proxyAddr = XepParseIp(value);
        else if (XepHostMatch("port", key) && ParseU32(value, &u) && u <= 65535) c->proxyPort = (WORD)u;
        else if (XepHostMatch("mode", key)) ParseMode(value, &c->proxyMode);
        else if (XepHostMatch("socks_user", key)) XepStrCopy(c->socksUser, sizeof(c->socksUser), value);
        else if (XepHostMatch("socks_pass", key)) XepStrCopy(c->socksPass, sizeof(c->socksPass), value);
        else if (XepHostMatch("socks_timeout_ms", key) && ParseU32(value, &u)) c->socksTimeoutMs = u;
        else if (XepHostMatch("forward_lan", key) && ParseBool(value, &b)) c->forwardLan = b;
        return;
    }

    if (sec == SEC_HOOKS) {
        int fn = FindFunc(key);
        if (fn >= 0 && ParseBool(value, &b)) {
            if (b && !g_funcs[fn].hookable)
                LOG_ERR("config: %s cannot be hooked, ignoring", key);
            else
                c->hookEnabled[fn] = b;
        } else if (fn < 0) {
            LOG_ERR("config: [hooks] unknown function '%s'", key);
        }
        return;
    }

    if (sec == SEC_ORDINALS) {
        int fn = FindFunc(key);
        if (fn >= 0 && ParseU32(value, &u))
            c->ordinal[fn] = u;
        else if (fn < 0)
            LOG_ERR("config: [ordinals] unknown function '%s'", key);
        return;
    }
}

static void ParseRuleLine(XepConfig *c, Section sec, char *key, char *value)
{
    if (sec == SEC_DNS) {
        XepDnsRule *r;

        if (c->dnsCount >= XEP_MAX_DNS_RULES) {
            LOG_ERR("config: more than %d [dns] rules, '%s' ignored", XEP_MAX_DNS_RULES, key);
            return;
        }
        r = &c->dns[c->dnsCount];
        XepStrCopy(r->pattern, sizeof(r->pattern), key);

        if (value[0] == '\0' || XepHostMatch("passthrough", value) || XepHostMatch("real", value))
            r->addr = 0;
        else if (XepHostMatch("proxy", value))
            r->addr = c->proxyAddr;
        else {
            r->addr = XepParseIp(value);
            if (r->addr == 0) {
                LOG_ERR("config: [dns] '%s' has a bad address '%s'", key, value);
                return;
            }
        }
        c->dnsCount++;
        return;
    }

    if (sec == SEC_REDIRECT) {
        XepRedirectRule r;

        if (c->redirectCount >= XEP_MAX_REDIRECT_RULES) {
            LOG_ERR("config: more than %d [redirect] rules, '%s' ignored",
                    XEP_MAX_REDIRECT_RULES, key);
            return;
        }
        memset(&r, 0, sizeof(r));
        if (!ParseRedirectMatch(key, &r)) {
            LOG_ERR("config: [redirect] bad match '%s'", key);
            return;
        }
        if (!ParseRedirectTarget(c, value, &r)) {
            LOG_ERR("config: [redirect] bad target '%s'", value);
            return;
        }
        c->redirect[c->redirectCount++] = r;
        return;
    }

    if (sec == SEC_XHTTP) {
        XepHttpRule *r;
        char *colon;

        if (c->httpCount >= XEP_MAX_HTTP_RULES) {
            LOG_ERR("config: more than %d [xhttp] rules, '%s' ignored", XEP_MAX_HTTP_RULES, key);
            return;
        }
        r = &c->http[c->httpCount];
        memset(r, 0, sizeof(*r));
        XepStrCopy(r->host, sizeof(r->host), key);

        colon = strrchr(value, ':');
        if (colon != NULL) {
            DWORD port;
            *colon = '\0';
            if (ParseU32(colon + 1, &port) && port <= 65535)
                r->dstPort = (WORD)port;
        }
        value = Trim(value);
        if (XepHostMatch("proxy", value)) {
            char ip[16];
            XepFormatIp(c->proxyAddr, ip, sizeof(ip));
            XepStrCopy(r->dstHost, sizeof(r->dstHost), ip);
            if (r->dstPort == 0)
                r->dstPort = c->proxyPort;
        } else {
            XepStrCopy(r->dstHost, sizeof(r->dstHost), value);
        }
        if (r->dstHost[0] == '\0') {
            LOG_ERR("config: [xhttp] '%s' has no target", key);
            return;
        }
        c->httpCount++;
        return;
    }
}

// Two passes: scalars first, then rules, so a rule may reference [proxy]
// wherever that section sits in the file.
static void ParseText(XepConfig *c, char *text, int pass)
{
    char   *line = text;
    Section sec  = SEC_NONE;

    while (line != NULL && *line != '\0') {
        char *next = strchr(line, '\n');
        char *key;
        char *value;
        char *cut;

        if (next != NULL)
            *next++ = '\0';

        // ';' and '#' only at line start or after whitespace.
        for (cut = line; *cut != '\0'; cut++) {
            if ((*cut == ';' || *cut == '#') &&
                (cut == line || cut[-1] == ' ' || cut[-1] == '\t')) {
                *cut = '\0';
                break;
            }
        }

        key = Trim(line);

        if (key[0] == '[') {
            char *close = strchr(key, ']');
            if (close != NULL) {
                *close = '\0';
                sec = SectionFromName(Trim(key + 1));
                if (sec == SEC_UNKNOWN && pass == 1)
                    LOG_ERR("config: unknown section '[%s]'", key + 1);
            }
            line = next;
            continue;
        }

        if (key[0] == '\0') {
            line = next;
            continue;
        }

        value = strchr(key, '=');
        if (value == NULL) {
            if (pass == 1)
                LOG_ERR("config: ignoring line without '=': %s", key);
            line = next;
            continue;
        }
        *value++ = '\0';
        key   = Trim(key);
        value = Trim(value);

        if (pass == 1)
            ParseScalarLine(c, sec, key, value);
        else
            ParseRuleLine(c, sec, key, value);

        line = next;
    }
}

// file loading

static BOOL ReadWhole(const char *path, DWORD *sizeOut, FILETIME *writeOut)
{
    HANDLE      h;
    DWORD       size;
    DWORD       read = 0;
    BOOL        ok;
    const char *how = "none";

    h = XepOpen(path, FALSE, &how);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;

    LOG_INFO("config: opened %s via %s", path, how);

    size = GetFileSize(h, NULL);
    if (size == INVALID_FILE_SIZE || size > INI_MAX_BYTES) {
        LOG_ERR("config: %s is %u bytes, limit is %u", path, size, INI_MAX_BYTES);
        CloseHandle(h);
        return FALSE;
    }

    if (writeOut != NULL)
        GetFileTime(h, NULL, NULL, writeOut);

    ok = ReadFile(h, g_text, size, &read, NULL) && read == size;
    CloseHandle(h);

    if (!ok)
        return FALSE;

    g_text[read] = '\0';
    if (sizeOut != NULL)
        *sizeOut = read;
    return TRUE;
}

static BOOL ParseInto(int slot)
{
    XepConfig *c = &g_buffers[slot];
    static char work[INI_MAX_BYTES + 1];

    ApplyDefaults(c);

    memcpy(work, g_text, strlen(g_text) + 1);
    ParseText(c, work, 1);

    memcpy(work, g_text, strlen(g_text) + 1);
    ParseText(c, work, 2);

    return TRUE;
}

// With no explicit [general] log, the log goes next to the ini.
static void DeriveLogPath(XepConfig *c, const char *iniPath)
{
    const char *slash;
    size_t      n;

    if (c->logPathExplicit || iniPath == NULL || iniPath[0] == '\0')
        return;

    slash = strrchr(iniPath, '\\');
    n = (slash != NULL) ? (size_t)(slash - iniPath) + 1 : 0;
    if (n == 0 || n >= sizeof(c->logPath) - 16)
        return;

    memcpy(c->logPath, iniPath, n);
    c->logPath[n] = '\0';
    XepStrCopy(c->logPath + n, sizeof(c->logPath) - n, "xeproxy.log");
}

static void Publish(int slot)
{
    // Logging is coupled to hot reload: a set-and-forget config (reload off)
    // installs silently.
    if (g_buffers[slot].reloadSeconds == 0)
        g_buffers[slot].logLevel = 0;

    g_live = slot;
    g_cfg  = &g_buffers[slot];
}

void XepConfigLogSummary(void)
{
    XepConfig *c = g_cfg;
    char ip[16];
    int  i;

    if (c == NULL)
        return;

    XepFormatIp(c->proxyAddr, ip, sizeof(ip));
    LOG_INFO("config: %s", XepConfigPath());
    LOG_INFO("config: enabled=%d log_level=%d reload=%us proxy=%s:%u mode=%d forward_lan=%d",
             c->enabled, c->logLevel, c->reloadSeconds, ip, c->proxyPort, (int)c->proxyMode,
             c->forwardLan);
    LOG_INFO("config: log=%s", c->logPath);
    LOG_INFO("config: startup patch=%d force=%02X clear=%02X",
             c->patchStartup, c->startupForceFlags, c->startupClearFlags);
    LOG_INFO("config: %d dns, %d redirect, %d xhttp rules",
             c->dnsCount, c->redirectCount, c->httpCount);

    for (i = 0; i < c->dnsCount; i++) {
        XepFormatIp(c->dns[i].addr, ip, sizeof(ip));
        LOG_INFO("  dns   %-32s -> %s", c->dns[i].pattern,
                 c->dns[i].addr != 0 ? ip : "(real resolver)");
    }
    for (i = 0; i < c->redirectCount; i++) {
        char net[16];
        XepFormatIp(c->redirect[i].net, net, sizeof(net));
        XepFormatIp(c->redirect[i].dstAddr, ip, sizeof(ip));
        LOG_INFO("  route %s/%08X:%u -> %s:%u mode=%d", net, c->redirect[i].mask,
                 c->redirect[i].port, ip, c->redirect[i].dstPort, (int)c->redirect[i].mode);
    }
    for (i = 0; i < c->httpCount; i++)
        LOG_INFO("  http  %-32s -> %s:%u", c->http[i].host,
                 c->http[i].dstHost, c->http[i].dstPort);
}

BOOL XepConfigInit(void)
{
    size_t i;

    // Defaults live immediately, so a missing ini still logs.
    if (g_cfg == NULL) {
        ApplyDefaults(&g_buffers[0]);
        Publish(0);
    }

    for (i = 0; i < sizeof(kSearchPaths) / sizeof(kSearchPaths[0]); i++) {
        if (ReadWhole(kSearchPaths[i], &g_lastSize, &g_lastWrite)) {
            XepStrCopy(g_path, sizeof(g_path), kSearchPaths[i]);
            ParseInto(1);
            DeriveLogPath(&g_buffers[1], g_path);
            Publish(1);
            return TRUE;
        }
    }

    g_path[0] = '\0';
    return FALSE;
}

BOOL XepConfigReload(void)
{
    HANDLE   h;
    DWORD    size;
    FILETIME write;
    int      slot;

    if (g_path[0] == '\0')
        return XepConfigInit();

    h = XepOpen(g_path, FALSE, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    size = GetFileSize(h, NULL);
    memset(&write, 0, sizeof(write));
    GetFileTime(h, NULL, NULL, &write);
    CloseHandle(h);

    if (size == g_lastSize &&
        write.dwLowDateTime == g_lastWrite.dwLowDateTime &&
        write.dwHighDateTime == g_lastWrite.dwHighDateTime)
        return FALSE;

    if (!ReadWhole(g_path, &g_lastSize, &g_lastWrite))
        return FALSE;

    slot = (g_live == 0) ? 1 : 0;
    ParseInto(slot);
    DeriveLogPath(&g_buffers[slot], g_path);
    Publish(slot);

    LOG_INFO("config: reloaded");
    XepConfigLogSummary();
    return TRUE;
}

// matching

BOOL XepMatchDns(const char *host, DWORD *addrOut)
{
    XepConfig *c = g_cfg;
    int i;

    if (c == NULL || host == NULL)
        return FALSE;

    for (i = 0; i < c->dnsCount; i++) {
        if (XepHostMatch(c->dns[i].pattern, host)) {
            if (c->dns[i].addr == 0)
                return FALSE;           // explicit passthrough
            *addrOut = c->dns[i].addr;
            return TRUE;
        }
    }
    return FALSE;
}

// First match wins, so put specific rules above general ones in the ini.
const XepRedirectRule *XepMatchRedirect(DWORD addr, WORD port)
{
    XepConfig *c = g_cfg;
    int i;

    if (c == NULL)
        return NULL;

    for (i = 0; i < c->redirectCount; i++) {
        const XepRedirectRule *r = &c->redirect[i];

        if (r->port != 0 && r->port != port)
            continue;
        if ((addr & r->mask) != r->net)
            continue;
        return r;
    }
    return NULL;
}

const XepHttpRule *XepMatchHttp(const char *host)
{
    XepConfig *c = g_cfg;
    int i;

    if (c == NULL || host == NULL)
        return NULL;

    for (i = 0; i < c->httpCount; i++)
        if (XepHostMatch(c->http[i].host, host))
            return &c->http[i];
    return NULL;
}
