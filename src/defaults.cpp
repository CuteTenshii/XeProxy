// defaults.cpp: writes xeproxy.ini when the console has none, so there is a real
// file to edit. Content is default_ini.h (from xeproxy.ini) plus a header, enabled = 0.

#include "xep.h"
#include "default_ini.h"

// Must be readable back, or every boot writes it again.
C_ASSERT(XEP_DEFAULT_INI_BYTES <= XEP_INI_MAX_BYTES);

// First writable wins. No Flash: (not worth a NAND write) and no Game:.
static const char *const kWritePaths[] = {
    "Hdd:\\xeproxy.ini",
    "Usb0:\\xeproxy.ini",
    "Usb1:\\xeproxy.ini",
    "Usb2:\\xeproxy.ini",
};

// Kept out of default_ini.h, which stays a byte-for-byte copy of the ini.
static const char *const kHeader[] = {
    "; ---------------------------------------------------------------------",
    "; Written by XeProxy.xex because no xeproxy.ini was found on this",
    "; console. It is the reference config, unchanged, and it is yours now:",
    "; edit it freely, the plugin will not touch it again.",
    ";",
    "; enabled = 0 below, so nothing is hooked yet. Set [proxy] host and port,",
    "; add the rules you want, then set enabled = 1 and reboot.",
    "; ---------------------------------------------------------------------",
    "",
};

#define OUT_BYTES 1024

// A couple of WriteFile calls instead of one per line.
struct Writer {
    HANDLE h;
    char   buf[OUT_BYTES];
    int    used;
    BOOL   failed;
    DWORD  written;
};

static void Flush(Writer *w)
{
    DWORD wrote = 0;

    if (w->failed || w->used == 0)
        return;
    if (!WriteFile(w->h, w->buf, (DWORD)w->used, &wrote, NULL) || wrote != (DWORD)w->used) {
        LOG_ERR("defaults: write failed after %u bytes, error %u",
                w->written, GetLastError());
        w->failed = TRUE;
        return;
    }
    w->written += wrote;
    w->used = 0;
}

static void PutLine(Writer *w, const char *line)
{
    size_t len = strlen(line);
    size_t i;

    if (w->failed)
        return;
    if (len + 2 > OUT_BYTES) {          // cannot happen; the generator caps it
        LOG_ERR("defaults: line of %u bytes does not fit the buffer", (DWORD)len);
        w->failed = TRUE;
        return;
    }
    if (w->used + (int)len + 2 > OUT_BYTES)
        Flush(w);

    for (i = 0; i < len; i++)
        w->buf[w->used++] = line[i];

    // CRLF: Notepad shows a LF-only file as one line.
    w->buf[w->used++] = '\r';
    w->buf[w->used++] = '\n';
}

// Guard against a device that mounted since discovery failed.
static BOOL Exists(const char *path)
{
    HANDLE h = XepOpen(path, FALSE, NULL);

    if (h == INVALID_HANDLE_VALUE)
        return FALSE;
    CloseHandle(h);
    return TRUE;
}

static BOOL WriteTo(const char *path)
{
    Writer      w;
    const char *how = "none";
    int         i;

    if (Exists(path)) {
        LOG_INFO("defaults: %s already exists, not overwriting it", path);
        return FALSE;
    }

    memset(&w, 0, sizeof(w));
    w.h = XepOpen(path, TRUE, &how);
    if (w.h == INVALID_HANDLE_VALUE) {
        LOG_INFO("defaults: cannot create %s", path);
        return FALSE;
    }

    for (i = 0; i < (int)(sizeof(kHeader) / sizeof(kHeader[0])); i++)
        PutLine(&w, kHeader[i]);
    for (i = 0; i < XEP_DEFAULT_INI_LINES; i++)
        PutLine(&w, kDefaultIni[i]);
    Flush(&w);

    if (!w.failed)
        FlushFileBuffers(w.h);
    CloseHandle(w.h);

    if (w.failed) {
        // A truncated config parses as real next boot. Take it away.
        if (!DeleteFile(path))
            LOG_ERR("defaults: %s is truncated and could not be deleted (error %u) "
                    "- delete it by hand", path, GetLastError());
        return FALSE;
    }

    LOG_INFO("defaults: wrote %s via %s, %u bytes", path, how, w.written);
    return TRUE;
}

// *pathOut receives the path written. Worker thread only.
BOOL XepWriteDefaultConfig(char *pathOut, size_t cch)
{
    size_t i;

    if (pathOut != NULL && cch > 0)
        pathOut[0] = '\0';

    for (i = 0; i < sizeof(kWritePaths) / sizeof(kWritePaths[0]); i++) {
        if (WriteTo(kWritePaths[i])) {
            if (pathOut != NULL)
                XepStrCopy(pathOut, cch, kWritePaths[i]);
            return TRUE;
        }
    }

    LOG_ERR("defaults: no writable device for xeproxy.ini");
    return FALSE;
}
