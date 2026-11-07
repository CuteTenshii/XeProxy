// util.cpp: string, address and device-mount helpers.

#include "xep.h"

void XepStrCopy(char *dst, size_t cch, const char *src)
{
    size_t i = 0;

    if (dst == NULL || cch == 0)
        return;
    if (src != NULL)
        for (; i + 1 < cch && src[i] != '\0'; i++)
            dst[i] = src[i];
    dst[i] = '\0';
}

void XepFormatIp(DWORD addr, char *out, size_t cch)
{
    _snprintf(out, cch, "%u.%u.%u.%u",
              (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
              (addr >> 8) & 0xFF, addr & 0xFF);
    out[cch - 1] = '\0';
}

// Dotted quad to network order, which here is just the octets: 0x01020304.
DWORD XepParseIp(const char *s)
{
    DWORD octets[4] = { 0, 0, 0, 0 };
    int   i;

    if (s == NULL)
        return 0;

    for (i = 0; i < 4; i++) {
        int digits = 0;
        DWORD v = 0;

        while (*s >= '0' && *s <= '9') {
            v = v * 10 + (DWORD)(*s - '0');
            s++;
            if (++digits > 3 || v > 255)
                return 0;
        }
        if (digits == 0)
            return 0;
        octets[i] = v;

        if (i < 3) {
            if (*s != '.')
                return 0;
            s++;
        }
    }
    if (*s != '\0')
        return 0;

    return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
}

static char LowerCh(char c)
{
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

static BOOL EqualNoCase(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        if (LowerCh(*a) != LowerCh(*b))
            return FALSE;
        a++;
        b++;
    }
    return *a == *b;
}

// "*" matches everything; "*.suffix" matches ".suffix" and the bare
// "suffix"; anything else is an exact, case-insensitive name.
BOOL XepHostMatch(const char *pattern, const char *host)
{
    size_t lp, lh;

    if (pattern == NULL || host == NULL)
        return FALSE;
    if (pattern[0] == '*' && pattern[1] == '\0')
        return TRUE;

    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *suffix = pattern + 1;           // ".xboxlive.com"

        if (EqualNoCase(suffix + 1, host))          // bare "xboxlive.com"
            return TRUE;

        lp = strlen(suffix);
        lh = strlen(host);
        if (lh <= lp)
            return FALSE;
        return EqualNoCase(suffix, host + (lh - lp));
    }

    return EqualNoCase(pattern, host);
}
