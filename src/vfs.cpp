// vfs.cpp: opening files without depending on drive-letter links.
//
// "Hdd:", "Usb0:" and "Flash:" are NOT kernel device links; the retail kernel
// knows only \??\D:, and the drive-style names are a DashLaunch/XeXMenu/FSD
// convention, so CreateFile("Hdd:\\x.ini") fails silently without one. The
// device paths the kernel always knows (confirmed against xboxkrnl strings):
//
//     \Device\Harddisk0\Partition1      HDD data partition
//     \Device\Mass0 .. \Device\Mass2    USB mass storage
//     \Device\Flash                     NAND
//
// So each path is tried three ways and the log says which one worked.

#include "xep.h"

// native file API

typedef struct _XEP_OBJECT_ATTRIBUTES {
    HANDLE         RootDirectory;
    POBJECT_STRING ObjectName;
    ULONG          Attributes;
} XEP_OBJECT_ATTRIBUTES, *PXEP_OBJECT_ATTRIBUTES;

typedef struct _XEP_IO_STATUS_BLOCK {
    NTSTATUS Status;
    ULONG    Information;
} XEP_IO_STATUS_BLOCK, *PXEP_IO_STATUS_BLOCK;

extern "C" {
    NTSTATUS NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                          PXEP_OBJECT_ATTRIBUTES ObjectAttributes,
                          PXEP_IO_STATUS_BLOCK IoStatusBlock,
                          PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                          ULONG ShareAccess, ULONG CreateDisposition,
                          ULONG CreateOptions);
}

#define OBJ_CASE_INSENSITIVE            0x00000040

#define FILE_OPEN                       0x00000001
#define FILE_OPEN_IF                    0x00000003

#define FILE_NON_DIRECTORY_FILE         0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020

// logical name translation

static const struct {
    const char *prefix;
    const char *device;
} kDevices[] = {
    { "Hdd:",   "\\Device\\Harddisk0\\Partition1" },
    { "HddX:",  "\\Device\\Harddisk0\\Partition0" },
    { "Usb0:",  "\\Device\\Mass0"                 },
    { "Usb1:",  "\\Device\\Mass1"                 },
    { "Usb2:",  "\\Device\\Mass2"                 },
    { "Usb:",   "\\Device\\Mass0"                 },
    { "Flash:", "\\Device\\Flash"                 },
};

static BOOL StartsWithNoCase(const char *s, const char *prefix)
{
    for (; *prefix != '\0'; s++, prefix++) {
        char a = (*s >= 'A' && *s <= 'Z') ? (char)(*s + 32) : *s;
        char b = (*prefix >= 'A' && *prefix <= 'Z') ? (char)(*prefix + 32) : *prefix;
        if (a != b)
            return FALSE;
    }
    return TRUE;
}

// "Hdd:\x.ini" -> "\Device\Harddisk0\Partition1\x.ini". FALSE when the prefix
// is not one we know, or the path is already a device path.
static BOOL ToDevicePath(const char *logical, char *out, size_t cch)
{
    size_t i;

    if (logical == NULL || logical[0] == '\0')
        return FALSE;
    if (logical[0] == '\\')
        return FALSE;                   // already native

    for (i = 0; i < sizeof(kDevices) / sizeof(kDevices[0]); i++) {
        size_t n = strlen(kDevices[i].prefix);

        if (!StartsWithNoCase(logical, kDevices[i].prefix))
            continue;

        XepStrCopy(out, cch, kDevices[i].device);
        if (logical[n] != '\\') {
            size_t len = strlen(out);
            if (len + 1 < cch) {
                out[len]     = '\\';
                out[len + 1] = '\0';
            }
        }
        {
            size_t len = strlen(out);
            XepStrCopy(out + len, cch - len, logical + n);
        }
        return TRUE;
    }
    return FALSE;
}

// native open

// Which route works is a property of the console, so a failed route is logged
// once (the ini reopens every reload interval) and never again.
static BOOL g_saidWin32;
static BOOL g_saidNative;

static HANDLE NativeOpen(const char *devicePath, BOOL forWrite)
{
    XEP_OBJECT_ATTRIBUTES attr;
    XEP_IO_STATUS_BLOCK   iosb;
    OBJECT_STRING         name;
    HANDLE                h = INVALID_HANDLE_VALUE;
    NTSTATUS              st;

    name.Length        = (USHORT)strlen(devicePath);
    name.MaximumLength = (USHORT)(name.Length + 1);
    name.Buffer        = (PCHAR)devicePath;

    attr.RootDirectory = NULL;
    attr.ObjectName    = &name;
    attr.Attributes    = OBJ_CASE_INSENSITIVE;

    memset(&iosb, 0, sizeof(iosb));

    st = NtCreateFile(&h,
                      (forWrite ? GENERIC_WRITE : GENERIC_READ) | SYNCHRONIZE,
                      &attr, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ,
                      forWrite ? FILE_OPEN_IF : FILE_OPEN,
                      FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

    if (st < 0 || h == NULL) {
        if (!g_saidNative) {
            g_saidNative = TRUE;
            LOG_INFO("vfs: NtCreateFile(%s) = %08X (said once)", devicePath, (DWORD)st);
        }
        return INVALID_HANDLE_VALUE;
    }
    return h;
}

static HANDLE Win32Open(const char *path, BOOL forWrite)
{
    HANDLE h = CreateFile(path,
                          forWrite ? GENERIC_WRITE : GENERIC_READ,
                          FILE_SHARE_READ, NULL,
                          forWrite ? OPEN_ALWAYS : OPEN_EXISTING,
                          FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE && !g_saidWin32) {
        g_saidWin32 = TRUE;
        LOG_INFO("vfs: CreateFile(%s) = %u, falling back (said once)",
                 path, GetLastError());
    }
    return h;
}

// public

// *howOut names the method that worked, for the log.
HANDLE XepOpen(const char *logical, BOOL forWrite, const char **howOut)
{
    char   device[XEP_MAX_PATH];
    HANDLE h;

    if (howOut != NULL)
        *howOut = "none";
    if (logical == NULL || logical[0] == '\0')
        return INVALID_HANDLE_VALUE;

    if (logical[0] == '\\') {
        h = NativeOpen(logical, forWrite);
        if (h != INVALID_HANDLE_VALUE && howOut != NULL)
            *howOut = "native";
        return h;
    }

    h = Win32Open(logical, forWrite);
    if (h != INVALID_HANDLE_VALUE) {
        if (howOut != NULL)
            *howOut = "link";
        return h;
    }

    if (!ToDevicePath(logical, device, sizeof(device)))
        return INVALID_HANDLE_VALUE;

    h = Win32Open(device, forWrite);
    if (h != INVALID_HANDLE_VALUE) {
        if (howOut != NULL)
            *howOut = "win32-device";
        return h;
    }

    h = NativeOpen(device, forWrite);
    if (h != INVALID_HANDLE_VALUE) {
        if (howOut != NULL)
            *howOut = "native-device";
        return h;
    }

    return INVALID_HANDLE_VALUE;
}
