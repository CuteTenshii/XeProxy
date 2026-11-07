// log.cpp: append-only text log, flushed per line so a hard lock still leaves
// the line that caused it on disk.

#include "xep.h"
#include <stdarg.h>

static HANDLE           g_log = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_logLock;
static BOOL             g_lockReady;
static int              g_dropped;
static char             g_logPath[XEP_MAX_PATH];
static char             g_logDevice[32];

// Hooks run on xam/title threads inside half-finished network calls, where
// writing or flushing a file deadlocks or faults the console. So hook-context
// lines go in this ring and only the worker writes them.
#define RING_LINES 128
#define RING_WIDTH 192

static char  g_ring[RING_LINES][RING_WIDTH];
static LONG  g_ringSeq;             // lines ever produced, the slot ticket
static LONG  g_ringDrained;         // how many the worker has written out
static DWORD g_workerTid;

void XepLogSetWorkerThread(void)
{
    g_workerTid = GetCurrentThreadId();
}

static BOOL OnWorker(void)
{
    return g_workerTid != 0 && GetCurrentThreadId() == g_workerTid;
}

// Tried in order when the configured path will not open.
static const char *const kLogFallbacks[] = {
    "Usb0:\\xeproxy.log",
    "Usb1:\\xeproxy.log",
    "Usb2:\\xeproxy.log",
    "Hdd:\\xeproxy.log",
    "Flash:\\xeproxy.log",
};

const char *XepLogPath(void)
{
    return g_logPath[0] != '\0' ? g_logPath : "(none)";
}

// "Usb0:\\xeproxy.log" -> "Usb0:", for the toast.
const char *XepLogDevice(void)
{
    const char *colon;
    size_t      n;

    if (g_logDevice[0] != '\0')
        return g_logDevice;

    colon = strchr(XepLogPath(), ':');
    if (colon == NULL)
        return XepLogPath();

    n = (size_t)(colon - XepLogPath()) + 1;
    if (n >= sizeof(g_logDevice))
        n = sizeof(g_logDevice) - 1;
    memcpy(g_logDevice, XepLogPath(), n);
    g_logDevice[n] = '\0';
    return g_logDevice;
}

// Reported by the caller after the lock is released; logging in here would
// re-enter it.
static const char *g_logHow = "none";

static HANDLE TryOpen(const char *path)
{
    HANDLE h;

    if (path == NULL || path[0] == '\0')
        return INVALID_HANDLE_VALUE;

    h = XepOpen(path, TRUE, &g_logHow);
    if (h != INVALID_HANDLE_VALUE)
        SetFilePointer(h, 0, NULL, FILE_END);
    return h;
}

static int LogLevel(void)
{
    XepConfig *cfg = g_cfg;
    return (cfg != NULL) ? cfg->logLevel : 2;   // chatty until the ini is read
}

void XepLogOpen(const char *path)
{
    if (!g_lockReady) {
        InitializeCriticalSection(&g_logLock);
        g_lockReady = TRUE;
    }

    EnterCriticalSection(&g_logLock);

    if (g_log != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log);
        g_log = INVALID_HANDLE_VALUE;
    }

    g_logPath[0]   = '\0';
    g_logDevice[0] = '\0';

    g_log = TryOpen(path);
    if (g_log != INVALID_HANDLE_VALUE) {
        XepStrCopy(g_logPath, sizeof(g_logPath), path);
    } else {
        size_t i;
        for (i = 0; i < sizeof(kLogFallbacks) / sizeof(kLogFallbacks[0]); i++) {
            g_log = TryOpen(kLogFallbacks[i]);
            if (g_log != INVALID_HANDLE_VALUE) {
                XepStrCopy(g_logPath, sizeof(g_logPath), kLogFallbacks[i]);
                break;
            }
        }
    }

    LeaveCriticalSection(&g_logLock);

    // Outside the lock (logging re-enters it); goes to OutputDebugString either way.
    if (g_log == INVALID_HANDLE_VALUE) {
        LOG_ERR("log: no writable log device; tried %s and every fallback",
                (path != NULL && path[0] != '\0') ? path : "(nothing)");
    } else {
        LOG_INFO("log: writing to %s (opened via %s)", g_logPath, g_logHow);
        if (path != NULL && path[0] != '\0' && strcmp(g_logPath, path) != 0)
            LOG_ERR("log: %s would not open, using %s instead", path, g_logPath);
    }
}

void XepLogClose(void)
{
    if (!g_lockReady)
        return;

    EnterCriticalSection(&g_logLock);
    if (g_log != INVALID_HANDLE_VALUE) {
        CloseHandle(g_log);
        g_log = INVALID_HANDLE_VALUE;
    }
    LeaveCriticalSection(&g_logLock);
}

static void WriteLine(int level, const char *fmt, va_list args);

// The lock exists to keep the worker's writes and XepLogOpen apart. A hook
// thread must never wait on it, so it is taken here and only on the worker.
static void Emit(int level, const char *fmt, va_list args)
{
    if (!OnWorker()) {
        WriteLine(level, fmt, args);
        return;
    }
    if (!g_lockReady) {
        WriteLine(level, fmt, args);
        return;
    }
    EnterCriticalSection(&g_logLock);
    WriteLine(level, fmt, args);
    LeaveCriticalSection(&g_logLock);
}

static void WriteLine(int level, const char *fmt, va_list args)
{
    char  line[512];
    int   n;
    DWORD written;
    DWORD ticks = GetTickCount();
    char  tag;

    switch (level) {
    case 1:  tag = 'E'; break;
    case 3:  tag = 'T'; break;
    default: tag = 'I'; break;
    }

    n = _snprintf(line, sizeof(line) - 3, "[%6u.%03u %c] ",
                  ticks / 1000u, ticks % 1000u, tag);
    if (n < 0)
        return;

    {
        int m = _vsnprintf(line + n, sizeof(line) - 3 - (size_t)n, fmt, args);
        if (m < 0)
            m = (int)(sizeof(line) - 3 - (size_t)n);    // truncated
        n += m;
    }

    line[n++] = '\r';
    line[n++] = '\n';
    line[n]   = '\0';

    // Hook context: claim a slot, copy, leave. No lock, no handle, no
    // OutputDebugString (with xbdm loaded it transmits over the network and
    // re-enters the hooks we installed); the worker emits these lines later.
    // The interlocked ticket is the only sync, so two threads never share a
    // slot. A producer lapping the worker overwrites an undrained line (the
    // drain counts it) or the worker reads one torn: the price of never blocking.
    if (!OnWorker()) {
        LONG ticket = InterlockedIncrement(&g_ringSeq) - 1;
        XepConfig *cfg = g_cfg;

        XepStrCopy(g_ring[(DWORD)ticket % RING_LINES], RING_WIDTH, line);

        // A wedged console loses whatever the worker never drained. trace_live
        // emits immediately instead, accepting that OutputDebugString runs the
        // network stack through xbdm from inside a hook.
        if (cfg != NULL && cfg->traceLive)
            OutputDebugString(line);
        return;
    }

    OutputDebugString(line);

    if (g_log != INVALID_HANDLE_VALUE) {
        if (WriteFile(g_log, line, (DWORD)n, &written, NULL))
            FlushFileBuffers(g_log);
    } else {
        g_dropped++;
    }
}

// Writes out everything the hooks queued. Worker thread only. Producers never
// take g_logLock, so holding it across these writes cannot stall a hook.
void XepLogDrain(void)
{
    LONG seq;
    LONG from;
    LONG lost = 0;

    if (!g_lockReady || !OnWorker())
        return;

    seq  = g_ringSeq;
    from = g_ringDrained;

    if (seq - from > RING_LINES) {
        lost = seq - from - RING_LINES;
        from = seq - RING_LINES;
    }
    if (from == seq)
        return;

    EnterCriticalSection(&g_logLock);

    for (; from < seq; from++) {
        const char *line = g_ring[(DWORD)from % RING_LINES];
        DWORD       written;
        DWORD       len = (DWORD)strlen(line);

        if (len == 0)
            continue;

        OutputDebugString(line);
        if (g_log != INVALID_HANDLE_VALUE)
            WriteFile(g_log, line, len, &written, NULL);
    }
    if (g_log != INVALID_HANDLE_VALUE)
        FlushFileBuffers(g_log);

    g_ringDrained = seq;

    LeaveCriticalSection(&g_logLock);

    if (lost != 0)
        LOG_ERR("log: %d hook-context lines lost before the drain caught up",
                (int)lost);
}

void XepLog(int level, const char *fmt, ...)
{
    va_list args;

    if (level > LogLevel())
        return;

    va_start(args, fmt);
    Emit(level, fmt, args);
    va_end(args);
}

// Wrappers: the XDK compiler has no variadic macros in C++ mode.

void XepLogErr(const char *fmt, ...)
{
    va_list args;

    if (LogLevel() < 1)
        return;

    va_start(args, fmt);
    Emit(1, fmt, args);
    va_end(args);
}

void XepLogInfo(const char *fmt, ...)
{
    va_list args;

    if (LogLevel() < 2)
        return;

    va_start(args, fmt);
    Emit(2, fmt, args);
    va_end(args);
}

void XepLogTrace(const char *fmt, ...)
{
    va_list args;

    if (LogLevel() < 3)
        return;

    va_start(args, fmt);
    Emit(3, fmt, args);
    va_end(args);
}
