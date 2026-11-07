// main.cpp: entry point. DllMain runs very early on DashLaunch's thread, so it
// only starts the worker; the worker waits for a filesystem, reads the ini,
// installs hooks and stays resident watching for edits.

#include "xep.h"

#define XEP_VERSION "1.0"

static char g_openedLog[XEP_MAX_PATH];

static void OpenLogIfChanged(void)
{
    XepConfig *c = g_cfg;

    if (c == NULL)
        return;
    if (strcmp(g_openedLog, c->logPath) == 0)
        return;

    XepStrCopy(g_openedLog, sizeof(g_openedLog), c->logPath);
    XepLogOpen(g_openedLog);
}

static void WorkerBody(void)
{
    DWORD deadline;
    DWORD ticks;
    BOOL  wroteDefault = FALSE;

    // Only this thread may touch the log file; hooks queue and we drain.
    XepLogSetWorkerThread();

    XepConfigInit();

    // A plugin can load before the drives are mounted; wait for the ini.
    deadline = GetTickCount() + g_cfg->waitForConfigMs;
    while (strcmp(XepConfigPath(), "(none)") == 0) {
        if ((int)(GetTickCount() - deadline) >= 0)
            break;
        Sleep(1000);
        XepConfigInit();
    }

    // Nothing anywhere: write the inert reference config so there is a file to
    // edit; this boot then stops at the enabled check below.
    if (strcmp(XepConfigPath(), "(none)") == 0) {
        char written[XEP_MAX_PATH];

        if (XepWriteDefaultConfig(written, sizeof(written))) {
            wroteDefault = TRUE;
            XepConfigInit();
        }
    }

    // Logging is coupled to hot reload (config forces log_level 0 when reload is
    // off), so a set-and-forget config installs silently. Open the log only when
    // it will be written to.
    if (g_cfg->logLevel > 0) {
        XepStrCopy(g_openedLog, sizeof(g_openedLog), g_cfg->logPath);
        XepLogOpen(g_openedLog);
        LOG_INFO("XeProxy %s starting, image at ~%08X",
                 XEP_VERSION, (DWORD)(void *)&WorkerBody & 0xFFFF0000u);
        XepConfigLogSummary();
    }

    if (!XepHooksResolve()) {
        LOG_ERR("could not resolve xam exports, not patching anything");
        return;
    }

    if (!g_cfg->enabled) {
        if (wroteDefault)
            LOG_INFO("wrote %s, set enabled = 1 and reboot", XepConfigPath());
        else
            LOG_INFO("disabled by config, no hooks installed");
        return;
    }

    if (strcmp(XepConfigPath(), "(none)") == 0) {
        LOG_ERR("no config and nowhere to write one, not patching anything");
        return;
    }

    if (!XepHooksInstall()) {
        LOG_ERR("no hooks installed, giving up");
        return;
    }

    if (g_cfg->dumpAt != 0)
        XepDumpCode(g_cfg->dumpAt, g_cfg->dumpWords);

    // The TLS MITM handshake fix (merged from the former ssltrust plugin): one
    // xam instruction so XHttp completes a TLS handshake with a proxy's cert.
    if (g_cfg->tlsIgnoreCert) {
        if (XepApplyTlsFix())
            LOG_INFO("tls: MITM handshake fix active (XHttp completes TLS with proxy certs)");
        else
            LOG_ERR("tls: MITM handshake fix NOT applied (see tlsfix line above)");
    }

    LOG_INFO("XeProxy: %d hooks, %d rules, log on %s", XepHookCount(),
             g_cfg->dnsCount + g_cfg->redirectCount + g_cfg->httpCount, XepLogDevice());

    // Hot reload off (and logging with it): nothing to drain or re-read, so the
    // worker is done. The hooks and TLS patch stay installed.
    if (g_cfg->reloadSeconds == 0)
        return;

    LOG_INFO("watching %s every %u s", XepConfigPath(), g_cfg->reloadSeconds);

    // Drain every 200 ms (a hook that downs the console takes the ring with it).
    for (ticks = 0;; ticks++) {
        DWORD seconds = g_cfg->reloadSeconds;

        Sleep(200);
        XepLogDrain();

        if (seconds == 0 || (ticks % (seconds * 5)) != 0)
            continue;

        if (XepConfigReload()) {
            OpenLogIfChanged();
            LOG_INFO("XeProxy: reloaded, %d rules",
                     g_cfg->dnsCount + g_cfg->redirectCount + g_cfg->httpCount);
        }
    }
}

static DWORD WINAPI Worker(LPVOID)
{
    // A fault in here would otherwise take xam down with it.
    __try {
        WorkerBody();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERR("worker faulted with code %08X, plugin inactive",
                (DWORD)GetExceptionCode());
    }
    return 0;
}

extern "C" BOOL WINAPI DllMain(HANDLE instance, DWORD reason, LPVOID reserved)
{
    HANDLE thread = NULL;

    (void)instance;
    (void)reserved;

    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    // Flag 2: a system thread, needed outside of any title.
    if (ExCreateThread(&thread, 0, NULL, NULL, Worker, NULL, 2) >= 0 && thread != NULL)
        CloseHandle(thread);

    return TRUE;
}
