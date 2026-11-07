// xep.h: shared declarations for XeProxy.xex, a DashLaunch plugin that hooks
// xam.xex's NetDll_* exports, driven by xeproxy.ini.
// Xenon is big-endian, so network order == host order: htons/htonl are identities
// and addresses are never byte-swapped here.

#ifndef XEP_H
#define XEP_H

#include <xtl.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

// kernel

typedef LONG NTSTATUS;

typedef struct _OBJECT_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} OBJECT_STRING, *POBJECT_STRING;

extern "C" {
    NTSTATUS ExCreateThread(PHANDLE, DWORD, LPDWORD, PVOID, LPTHREAD_START_ROUTINE, LPVOID, DWORD);
    NTSTATUS XexGetModuleHandle(PCHAR, PHANDLE);
    NTSTATUS XexGetProcedureAddress(HANDLE, DWORD, PVOID *);

}

// net structs
// All from the XDK's winsockx.h; do not redeclare (XNDNS.cina is a UINT, not the
// WORD often written). Sizes pinned so a header change fails the build.
C_ASSERT(sizeof(SOCKADDR_IN) == 16);
C_ASSERT(sizeof(XNetStartupParams) == 13);
C_ASSERT(sizeof(XNADDR) == 36);
C_ASSERT(offsetof(XNDNS, aina) == 8);

// First argument of every NetDll_ export. Not in any public header.
#define XNCALLER_TITLE   1
#define XNCALLER_SYSAPP  2
#define XNCALLER_XBDM    3

// hook table

enum XepFunc {
    FN_socket = 0,
    FN_closesocket,
    FN_setsockopt,
    FN_bind,
    FN_connect,
    FN_select,
    FN_recv,
    FN_recvfrom,
    FN_WSARecvFrom,
    FN_send,
    FN_sendto,
    FN_WSASendTo,
    FN_WSAGetLastError,
    FN_WSASetEvent,
    FN_XNetStartup,
    FN_XNetXnAddrToInAddr,
    FN_XNetServerToInAddr,
    FN_XNetInAddrToXnAddr,
    FN_XNetInAddrToServer,
    FN_XNetGetConnectStatus,
    FN_XNetDnsLookup,
    FN_XNetDnsRelease,
    FN_XNetQosLookup,
    FN_XNetQosServiceLookup,
    FN_XNetGetTitleXnAddr,
    FN_XHttpConnect,
    FN_XHttpSetOption,
    FN_COUNT
};

struct XepFuncInfo {
    const char *prefix;     // "NetDll_" or "", for the log only
    const char *name;       // ini key under [hooks] and [ordinals]
    DWORD       ordinal;    // default xam.xex export ordinal
    BOOL        hookable;   // FALSE = resolved for our own use, never patched
};

extern const XepFuncInfo g_funcs[FN_COUNT];

// Resolved originals; for a hooked function, the trampoline.
extern void *g_orig[FN_COUNT];

// config

#define XEP_MAX_DNS_RULES       32
#define XEP_MAX_REDIRECT_RULES  32
#define XEP_MAX_HTTP_RULES      16
#define XEP_MAX_HOST            128
#define XEP_MAX_PATH            260

// Two static buffers this size. An oversized file is refused in a way that
// reads downstream as "no ini found", so the headroom is deliberate.
#define XEP_INI_MAX_BYTES       16384

enum XepMode { MODE_REDIRECT = 0, MODE_SOCKS5 = 1, MODE_DROP = 2, MODE_HTTP = 3 };

// Modes that tunnel through the proxy at connect() time: TCP only.
#define XEP_MODE_TUNNELS(m) ((m) == MODE_SOCKS5 || (m) == MODE_HTTP)

struct XepDnsRule {
    char  pattern[XEP_MAX_HOST];    // "*", "*.xboxlive.com", or an exact name
    DWORD addr;                     // 0 = let the real resolver answer
};

struct XepRedirectRule {
    DWORD   net;        // matches when (addr & mask) == net
    DWORD   mask;
    WORD    port;       // 0 = any port
    DWORD   dstAddr;    // 0 = keep the original address
    WORD    dstPort;    // 0 = keep the original port
    XepMode mode;
};

struct XepHttpRule {
    char host[XEP_MAX_HOST];
    char dstHost[XEP_MAX_HOST];
    WORD dstPort;       // 0 = keep the original port
};

struct XepConfig {
    BOOL  enabled;
    char  logPath[XEP_MAX_PATH];
    BOOL  logPathExplicit;       // FALSE = derived from where the ini was found
    int   logLevel;              // 0 off, 1 error, 2 info, 3 trace
    BOOL  logPackets;
    DWORD reloadSeconds;         // 0 = no hot reload
    DWORD waitForConfigMs;

    // [xnetstartup]
    BOOL  patchStartup;
    BYTE  startupForceFlags;
    BYTE  startupClearFlags;
    int   startupMaxDgram;       // -1 = leave alone
    int   startupMaxStream;

    // [proxy]
    DWORD   proxyAddr;
    WORD    proxyPort;
    XepMode proxyMode;
    char    socksUser[64];
    char    socksPass[64];
    DWORD   socksTimeoutMs;
    BOOL    forwardLan;          // FALSE = local destinations are never redirected

    DWORD dumpAt;                // log the code at this address, 0 = off
    BOOL  traceLive;             // hook lines go to OutputDebugString too
    BOOL  tlsIgnoreCert;         // apply the xam TLS handshake fix for proxy MITM
    DWORD dumpWords;

    BOOL  forceConnectStatus;    // XNetGetConnectStatus -> CONNECTED
    BOOL  bypassQos;             // fail QoS lookups fast instead of timing out
    BOOL  mapXnAddrToIna;        // XNetXnAddrToInAddr -> the peer's real ina

    BOOL  hookEnabled[FN_COUNT];
    DWORD ordinal[FN_COUNT];

    XepDnsRule      dns[XEP_MAX_DNS_RULES];
    int             dnsCount;
    XepRedirectRule redirect[XEP_MAX_REDIRECT_RULES];
    int             redirectCount;
    XepHttpRule     http[XEP_MAX_HTTP_RULES];
    int             httpCount;
};

// Live config. A reload parses into a spare buffer and flips this, so a hook
// mid-flight finishes against a coherent snapshot.
extern XepConfig *volatile g_cfg;

BOOL        XepConfigInit(void);        // find and parse; FALSE if no file
BOOL        XepConfigReload(void);      // re-parse when mtime or size changed
const char *XepConfigPath(void);
void        XepConfigLogSummary(void);

// Writes the reference config where a console has not got one. What it
// writes has enabled = 0. Worker thread only, like all file I/O here.
BOOL XepWriteDefaultConfig(char *pathOut, size_t cch);

// log

// Opens path, or the first writable fallback device.
void        XepLogOpen(const char *path);
void        XepLog(int level, const char *fmt, ...);
void        XepLogClose(void);
const char *XepLogPath(void);       // what actually opened, "(none)" if nothing
const char *XepLogDevice(void);     // just the "Usb0:" part of it

// Only the worker thread writes the file. File I/O from hook context (a xam or
// title thread inside a half-finished network call) hangs or faults the console,
// so those lines are queued and XepLogDrain writes them.
void XepLogSetWorkerThread(void);
void XepLogDrain(void);

#define LOG_ERR    XepLogErr
#define LOG_INFO   XepLogInfo
#define LOG_TRACE  XepLogTrace

void XepLogErr(const char *fmt, ...);
void XepLogInfo(const char *fmt, ...);
void XepLogTrace(const char *fmt, ...);

// patch

BOOL XepPatchInit(void);

// Logs count instruction words from addr. Read-only and SEH-guarded, for
// identifying what a faulting address belongs to.
void XepDumpCode(DWORD addr, DWORD count);

// On success *origOut gets a trampoline that runs the original. Fails
// without touching target if the prologue cannot be relocated.
BOOL XepHook(void *target, void *detour, void **origOut);

// Applies the one-instruction xam TLS handshake-state fix for proxy MITM.
// Gated by tls_ignore_cert_errors. Refused unless the live bytes match.
BOOL XepApplyTlsFix(void);

// hooks

// Resolve exports without patching; call before XepHooksInstall.
BOOL XepHooksResolve(void);
BOOL XepHooksInstall(void);
int  XepHookCount(void);

// Rewrite bookkeeping, so a reply from the proxy can be handed back as if it
// came from the address the title asked for. Keyed on socket too, so two
// sockets pointed at one proxy do not alias.
void XepMapRemember(DWORD s, DWORD origAddr, WORD origPort, DWORD newAddr, WORD newPort);
BOOL XepMapReverse(DWORD s, DWORD newAddr, WORD newPort, DWORD *origAddr, WORD *origPort);
void XepMapForget(DWORD s);

const XepRedirectRule *XepMatchRedirect(DWORD addr, WORD port);
BOOL                   XepMatchDns(const char *host, DWORD *addrOut);
const XepHttpRule     *XepMatchHttp(const char *host);
BOOL                   XepHostMatch(const char *pattern, const char *host);

// socks

// SOCKS5 CONNECT over a connected socket. TCP only.
BOOL XepSocks5Connect(DWORD caller, SOCKET s, DWORD dstAddr, WORD dstPort);
// HTTP CONNECT over a connected socket, for a plain HTTP proxy. TCP only.
BOOL XepHttpConnect(DWORD caller, SOCKET s, DWORD dstAddr, WORD dstPort);
// select() on one socket: 1 ready, 0 timeout, -1 failed (connect refused etc.).
int  XepWaitSocket(DWORD caller, SOCKET s, BOOL forWrite, DWORD ms);

// helpers

// Opens "Hdd:\x.ini" by whatever this console supports, falling back from
// drive-letter links to the kernel's \Device\ namespace. *howOut names what
// worked.
HANDLE XepOpen(const char *logical, BOOL forWrite, const char **howOut);

void  XepFormatIp(DWORD addr, char *out, size_t cch);   // out >= 16 bytes
DWORD XepParseIp(const char *s);                        // 0 when unparseable
void  XepStrCopy(char *dst, size_t cch, const char *src);

#endif // XEP_H
