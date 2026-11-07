// patch.cpp: PowerPC detour engine. Overwrites a 4-insn prologue with a jump
// through r11; originals run from a trampoline that returns via CTR to target+16.

#include "xep.h"
#include <ppcintrinsics.h>

#define XEP_CACHE_LINE 32
#define XEP_ISYNC()    __emit(0x4C00012Cu)

typedef void (*XepFlushFn)(void *start, int lines);

static XepFlushFn g_flush;

static void LineRange(void *addr, size_t len, BYTE **first, int *lines)
{
    DWORD start = (DWORD)addr & ~(DWORD)(XEP_CACHE_LINE - 1);
    DWORD end   = ((DWORD)addr + len + XEP_CACHE_LINE - 1) & ~(DWORD)(XEP_CACHE_LINE - 1);

    *first = (BYTE *)start;
    *lines = (int)((end - start) / XEP_CACHE_LINE);
}

static void WeakFlush(void *addr, size_t len)
{
    BYTE *p;
    int   lines;
    int   i;

    LineRange(addr, len, &p, &lines);
    for (i = 0; i < lines; i++)
        __dcbst(i * XEP_CACHE_LINE, p);
    __sync();
    XEP_ISYNC();
}

static void FlushRange(void *addr, size_t len)
{
    BYTE *p;
    int   lines;

    LineRange(addr, len, &p, &lines);

    if (g_flush != NULL)
        g_flush(p, lines);
    else
        WeakFlush(addr, len);
}

static const DWORD kFlushCode[8] = {
    0x7C8903A6u,        // mtctr r4
    0x7C00186Cu,        // dcbst 0, r3
    0x7C0004ACu,        // sync
    0x7C001FACu,        // icbi  0, r3
    0x38630020u,        // addi  r3, r3, 32
    0x4200FFF0u,        // bdnz  -16
    0x4C00012Cu,        // isync
    0x4E800020u,        // blr
};

#define OPCD(i)      (((i) >> 26) & 0x3F)
#define OP_BC        16
#define OP_B         18

#define INSN_BLR     0x4E800020u

// A target that ends within the 16 bytes a detour overwrites is too short.
static BOOL EndsWithin(const DWORD *code, int count)
{
    int i;

    for (i = 0; i < count; i++) {
        DWORD insn = code[i];

        if (insn == INSN_BLR)
            return TRUE;
        if (insn == 0x4E800420u)                    // bctr
            return TRUE;
        if (OPCD(insn) == OP_B && (insn & 1) == 0)  // b / ba, not bl
            return TRUE;
    }
    return FALSE;
}

static void BuildAbsJump(DWORD *out, DWORD target)
{
    WORD hi = (WORD)(target >> 16);
    WORD lo = (WORD)(target & 0xFFFF);

    if (lo & 0x8000)
        hi++;                       // addi sign-extends its immediate

    out[0] = 0x3D600000u | hi;      // lis   r11, hi
    out[1] = 0x396B0000u | lo;      // addi  r11, r11, lo
    out[2] = 0x7D6903A6u;           // mtctr r11
    out[3] = 0x4E800420u;           // bctr
}

static void BuildCtrLoad(DWORD *out, DWORD target)
{
    WORD hi = (WORD)(target >> 16);
    WORD lo = (WORD)(target & 0xFFFF);

    if (lo & 0x8000)
        hi++;

    out[0] = 0x3D600000u | hi;      // lis   r11, hi
    out[1] = 0x396B0000u | lo;      // addi  r11, r11, lo
    out[2] = 0x7D6903A6u;           // mtctr r11
}

// Refuse any copied insn that writes CTR: mtctr (mtspr 9) or a bdnz/bdz branch.
static BOOL WritesCtr(DWORD insn)
{
    if (OPCD(insn) == 31 && ((insn >> 1) & 0x3FF) == 467 &&
        (insn & 0x001FF800u) == 0x00090000u)
        return TRUE;                            // mtspr 9, rS
    if (OPCD(insn) == OP_BC && (((insn >> 21) & 31) & 0x04) == 0)
        return TRUE;                            // bdnz / bdz forms
    return FALSE;
}

static BOOL IsAbsJumpTo(const DWORD *code, DWORD target)
{
    DWORD want[4];
    BuildAbsJump(want, target);
    return memcmp(code, want, sizeof(want)) == 0;
}

// An export that is just a BuildAbsJump sequence is already hooked; *target is
// that hook's entry (e.g. DashLaunch fakelive on NetDll_XNetDnsLookup).
static BOOL DecodeAbsJump(const DWORD *code, DWORD *target)
{
    LONG lo;

    if ((code[0] & 0xFFFF0000u) != 0x3D600000u)     // lis   r11, hi
        return FALSE;
    if ((code[1] & 0xFFFF0000u) != 0x396B0000u)     // addi  r11, r11, lo
        return FALSE;
    if (code[2] != 0x7D6903A6u)                     // mtctr r11
        return FALSE;
    if (code[3] != 0x4E800420u)                     // bctr
        return FALSE;

    lo = (LONG)(SHORT)(code[1] & 0xFFFF);           // addi sign-extends
    *target = ((code[0] & 0xFFFF) << 16) + (DWORD)lo;
    return TRUE;
}

// A bl out of range becomes an absolute call through LR (CTR holds the return).
// A plain b cannot be veneered (no free register) and is refused.
static BOOL BuildBranchVeneer(DWORD insn, DWORD srcAddr, DWORD *out)
{
    LONG  disp;
    DWORD target;
    WORD  hi;
    WORD  lo;

    if (OPCD(insn) != OP_B || (insn & 0x2))         // only relative b/bl
        return FALSE;
    if ((insn & 1) == 0)                            // b, not bl
        return FALSE;

    disp = (LONG)(insn & 0x03FFFFFC);
    if (disp & 0x02000000)
        disp |= (LONG)0xFC000000;
    target = srcAddr + (DWORD)disp;

    hi = (WORD)(target >> 16);
    lo = (WORD)(target & 0xFFFF);
    if (lo & 0x8000)
        hi++;

    out[0] = 0x3D600000u | hi;      // lis   r11, hi
    out[1] = 0x396B0000u | lo;      // addi  r11, r11, lo
    out[2] = 0x7D6803A6u;           // mtlr  r11
    out[3] = 0x4E800021u;           // blrl
    return TRUE;
}

// Rewrites one copied instruction for its new address; FALSE if it cannot reach.
static BOOL RelocateInstruction(DWORD insn, DWORD srcAddr, DWORD dstAddr, DWORD *out)
{
    LONG  disp;
    LONG  newDisp;
    DWORD target;

    switch (OPCD(insn)) {
    case OP_B:
        if (insn & 0x2) {           // AA set: absolute target, nothing to do
            *out = insn;
            return TRUE;
        }
        disp = (LONG)(insn & 0x03FFFFFC);
        if (disp & 0x02000000)
            disp |= (LONG)0xFC000000;           // sign-extend 26 bits
        target  = srcAddr + (DWORD)disp;
        newDisp = (LONG)(target - dstAddr);
        if (newDisp > 0x01FFFFFC || newDisp < -0x02000000)
            return FALSE;
        *out = (insn & 0xFC000003u) | ((DWORD)newDisp & 0x03FFFFFCu);
        return TRUE;

    case OP_BC:
        if (insn & 0x2) {
            *out = insn;
            return TRUE;
        }
        disp = (LONG)(insn & 0x0000FFFC);
        if (disp & 0x8000)
            disp |= (LONG)0xFFFF0000;           // sign-extend 16 bits
        target  = srcAddr + (DWORD)disp;
        newDisp = (LONG)(target - dstAddr);
        if (newDisp > 0x7FFC || newDisp < -0x8000)
            return FALSE;
        *out = (insn & 0xFFFF0003u) | ((DWORD)newDisp & 0x0000FFFCu);
        return TRUE;

    default:
        *out = insn;
        return TRUE;
    }
}

// trampoline storage

#define STUB_DWORDS     24
#define STUB_SLOTS      (FN_COUNT + 4)

static DWORD  g_staticPool[STUB_SLOTS * STUB_DWORDS];
static DWORD *g_pool;
static int    g_poolNext;

static DWORD *AllocStub(void);

typedef DWORD (*ProbeFn)(void);

static BOOL ProbeExecutable(DWORD *mem)
{
    BOOL ok = FALSE;

    mem[0] = 0x38601234u;   // li r3, 0x1234
    mem[1] = 0x4E800020u;   // blr
    FlushRange(mem, 8);

    __try {
        ok = (((ProbeFn)(void *)mem)() == 0x1234u);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        ok = FALSE;
    }

    mem[0] = 0;
    mem[1] = 0;
    FlushRange(mem, 8);
    return ok;
}

static void InstallFlusher(void)
{
    DWORD *code = AllocStub();

    if (code == NULL) {
        LOG_ERR("patch: no slot for the flush routine, icbi unavailable");
        return;
    }

    memcpy(code, kFlushCode, sizeof(kFlushCode));
    WeakFlush(code, sizeof(kFlushCode));

    g_flush = (XepFlushFn)(void *)code;
    FlushRange(code, sizeof(kFlushCode));

    LOG_INFO("patch: cache flush routine at %08X", (DWORD)code);
}

BOOL XepPatchInit(void)
{
    const DWORD bytes = STUB_SLOTS * STUB_DWORDS * sizeof(DWORD);
    DWORD *phys;

    if (g_pool != NULL)
        return TRUE;

    phys = (DWORD *)XPhysicalAlloc(bytes, MAXULONG_PTR, 0, PAGE_READWRITE);
    if (phys != NULL) {
        memset(phys, 0, bytes);
        if (ProbeExecutable(phys)) {
            g_pool = phys;
            LOG_INFO("patch: trampoline pool at %08X (physical, %u bytes)", (DWORD)phys, bytes);
            InstallFlusher();
            return TRUE;
        }
        LOG_INFO("patch: physical pool at %08X is not executable, using static", (DWORD)phys);
        XPhysicalFree(phys);
    } else {
        LOG_ERR("patch: XPhysicalAlloc(%u) failed", bytes);
    }

    memset(g_staticPool, 0, sizeof(g_staticPool));
    if (ProbeExecutable(g_staticPool)) {
        g_pool = g_staticPool;
        LOG_INFO("patch: trampoline pool at %08X (static image data)", (DWORD)g_staticPool);
        InstallFlusher();
        return TRUE;
    }

    LOG_ERR("patch: no executable memory available, hooks disabled");
    return FALSE;
}

static DWORD *AllocStub(void)
{
    if (g_pool == NULL || g_poolNext >= STUB_SLOTS)
        return NULL;
    return g_pool + (g_poolNext++ * STUB_DWORDS);
}

// Publish the original before patching the target, else a call in the gap
// re-enters the detour and recurses.
static void PublishOriginal(void **origOut, void *value)
{
    if (origOut != NULL)
        *origOut = value;
    __sync();
}

void XepDumpCode(DWORD addr, DWORD count)
{
    const DWORD *p = (const DWORD *)addr;
    DWORD i;

    if (addr < 0x80000000u || (addr & 3) != 0) {
        LOG_ERR("dump: %08X is not a readable code address", addr);
        return;
    }
    if (count == 0 || count > 64)
        count = 16;

    __try {
        for (i = 0; i < count; i += 4)
            LOG_INFO("dump %08X: %08X %08X %08X %08X",
                     addr + i * 4, p[i], p[i + 1], p[i + 2], p[i + 3]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERR("dump: faulted reading %08X", addr);
    }
}

// TLS MITM fix (merged from ssltrust): the Certificate handler leaves TLS state
// 0x8a, which has no ServerHelloDone case and stalls; 0x25 handles it. Patch its
// success-state constant (refused unless live bytes match):
//     0x8195FDD0  li r10,0x8a (3940008A) -> li r10,0x25 (39400025)
#define XEP_TLSFIX_ADDR    0x8195FDD0u
#define XEP_TLSFIX_EXPECT  0x3940008Au   // li r10, 0x8a
#define XEP_TLSFIX_PATCH   0x39400025u   // li r10, 0x25

BOOL XepApplyTlsFix(void)
{
    volatile DWORD *t = (volatile DWORD *)XEP_TLSFIX_ADDR;
    DWORD cur;

    __try {
        cur = *t;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERR("tlsfix: cannot read %08X", XEP_TLSFIX_ADDR);
        return FALSE;
    }

    if (cur == XEP_TLSFIX_PATCH) {
        LOG_INFO("tlsfix: %08X already patched (li r10,0x25)", XEP_TLSFIX_ADDR);
        return TRUE;
    }
    if (cur != XEP_TLSFIX_EXPECT) {
        LOG_ERR("tlsfix: %08X = %08X, expected %08X (li r10,0x8a) - NOT patching",
                XEP_TLSFIX_ADDR, cur, XEP_TLSFIX_EXPECT);
        return FALSE;
    }

    __try {
        *t = XEP_TLSFIX_PATCH;
        FlushRange((void *)XEP_TLSFIX_ADDR, sizeof(DWORD));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        LOG_ERR("tlsfix: write to %08X faulted", XEP_TLSFIX_ADDR);
        return FALSE;
    }

    LOG_INFO("tlsfix: patched %08X %08X -> %08X (XHttp now completes TLS with "
             "untrusted/proxy certs)", XEP_TLSFIX_ADDR, cur, XEP_TLSFIX_PATCH);
    return TRUE;
}

BOOL XepHook(void *target, void *detour, void **origOut)
{
    DWORD *code = (DWORD *)target;
    DWORD *stub;
    DWORD  built[STUB_DWORDS];
    DWORD  chained;
    int    n = 0;
    int    i;

    if (code == NULL || detour == NULL) {
        LOG_ERR("hook: null target or detour");
        return FALSE;
    }
    if ((DWORD)code < 0x80000000u || ((DWORD)code & 3) != 0) {
        LOG_ERR("hook: implausible target %08X", (DWORD)code);
        return FALSE;
    }
    if (IsAbsJumpTo(code, (DWORD)detour)) {
        LOG_INFO("hook: %08X already points at %08X", (DWORD)code, (DWORD)detour);
        return FALSE;
    }

    // Already hooked by someone else: take over their jump and call theirs as
    // the original, chaining both with no trampoline.
    if (DecodeAbsJump(code, &chained)) {
        LOG_INFO("hook: %08X is already a jump to %08X (another plugin owns it), "
                 "chaining behind it", (DWORD)code, chained);
        PublishOriginal(origOut, (void *)chained);
        BuildAbsJump(code, (DWORD)detour);
        FlushRange(code, 4 * sizeof(DWORD));
        return TRUE;
    }

    if (EndsWithin(code, 4)) {
        LOG_ERR("hook: %08X is shorter than 16 bytes (%08X %08X %08X %08X), "
                "patching it would overwrite the next function",
                (DWORD)code, code[0], code[1], code[2], code[3]);
        return FALSE;
    }

    LOG_INFO("hook: %08X prologue %08X %08X %08X %08X",
             (DWORD)code, code[0], code[1], code[2], code[3]);

    stub = AllocStub();
    if (stub == NULL) {
        LOG_ERR("hook: trampoline pool exhausted");
        return FALSE;
    }

    // Build the whole trampoline before writing, so a refusal leaves target and
    // pool untouched. CTR carries the return, freeing the prologue to use r11.
    BuildCtrLoad(built, (DWORD)(code + 4));
    n = 3;

    for (i = 0; i < 4; i++) {
        DWORD srcAddr = (DWORD)(code + i);
        DWORD dstAddr = (DWORD)(stub + n);

        if (WritesCtr(code[i])) {
            LOG_ERR("hook: %08X prologue insn %d (%08X) writes CTR, which the "
                    "trampoline needs to get back", (DWORD)code, i, code[i]);
            g_poolNext--;
            return FALSE;
        }

        if (RelocateInstruction(code[i], srcAddr, dstAddr, &built[n])) {
            n++;
        } else if (BuildBranchVeneer(code[i], srcAddr, &built[n])) {
            LOG_INFO("hook: %08X insn %d (%08X) is out of branch range, "
                     "veneered through LR", (DWORD)code, i, code[i]);
            n += 4;
        } else {
            LOG_ERR("hook: %08X prologue insn %d (%08X) cannot be moved to %08X",
                    (DWORD)code, i, code[i], dstAddr);
            g_poolNext--;
            return FALSE;
        }
    }

    built[n++] = 0x4E800420u;           // bctr, back to target+16

    memcpy(stub, built, (size_t)n * sizeof(DWORD));
    FlushRange(stub, (size_t)n * sizeof(DWORD));

    PublishOriginal(origOut, (void *)stub);

    BuildAbsJump(code, (DWORD)detour);
    FlushRange(code, 4 * sizeof(DWORD));

    LOG_INFO("hook: %08X -> %08X (trampoline %08X, %d words)",
             (DWORD)code, (DWORD)detour, (DWORD)stub, n);
    return TRUE;
}
