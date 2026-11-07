# XHttp cert-trust gate — investigation log

Goal: make the 360 net stack trust mitmproxy's cert so HTTPS can be MITM'd.
ssltrust (validator-1 patch) works but does NOT gate XHttp. Find the function
that actually makes XHttp abort on the untrusted root.

## Environment / harness
- Console (xbdm) 192.168.50.30:730; proxy PC 192.168.50.180; mitmweb on :8080 (RSA-kx ciphers only, else DHE blocks the handshake before cert).
- `tools/xbdm.py` — clean XBDM client (getmem/setmem/words/cmd/context/break/unbreak/notify). Library + CLI.
- Loop-prober: netprobe/title.cpp main() loops DoXHttp(www.google.com,443,proxy) every 6s. Launch via `python tools/xbdm.py cmd 'magicboot title=Hdd:\netprobe_title.xex'` (magicboot goes through DashLaunch so ssltrust loads; confirmed validator1=38600000 after).
- Notifications: `notify reconnectport=0` on a 2nd connection -> 205, stream lines on same socket. Break-hit = `break addr=0x.. thread=0x..`. netprobe's thread id changes per boot — grab it from the `[netprobe ...]` debugstr line.
- NON-HALTING breakpoints only. DO NOT use `stopon` — it SUSPENDS threads (KeSuspendThread) and wedged netprobe; recover with `resume thread=0x..` or reboot.
- liveblock=TRUE currently (backup scratchpad\launch.ini.bak). Revert when done.

## Confirmed (dynamic, via breakpoint hit-counts on netprobe's thread)
- validator 1 (0x81955E38): 0 hits during XHttp handshake -> OFF PATH.
- validator 2 (0x8195FB40): 0 hits -> OFF PATH.
- handshake state machine sub_81960FA8: 1 hit/handshake, BUT its 12 direct callees all 0 hits
  (sub_81956788/81956840/819618d0/81959f08/8195e510/819566e8/8195a300/8195ff00/8195fe10/81960818/81956b00/81960d70).
  => on netprobe's flow it returns early / that single hit may be unrelated; cert verdict is elsewhere.
- sub_8195F4C0: pathologically hot (7MB of hits in 14s) BUT thread filter was OFF — likely another thread's noise. Re-check with thread filter.

## Method (current)
Batch non-halting breakpoints over all 212 cert-cluster entries (0x81954000-0x81965000,
research/cert-trust/cert-cluster-entries.txt), count hits BY THREAD over ~8s, keep only
netprobe-thread hits. Those are the real XHttp cert path. Then drill to the verdict/abort.

## Open
- Find the exact function + instruction where XHttp decides untrusted -> abort, then patch it
  (surgical, do-all-work-then-trust), port into ssltrust.

## UPDATE (dynamic trace, thread-filtered to netprobe 0xf9000000)
- ENTIRE SChannel region 0x81954000-0x8195FFFF = 0 hits on netprobe's thread (3 batches). SChannel is NOT XHttp's cert path, full stop.
- XHttp's TLS is the 0x8196xxxx cluster. Functions seen on netprobe's thread:
  - sub_81960FA8 (state machine) ~1/handshake
  - sub_81961B20 HOT (~5500/s) = security-provider lookup by name (string-compares vs "Microsoft TLS 1.x" table @0x81632A50, calls sub_8195ed38)
  - sub_81961C18 (~1) = wide-string helper
- Verdict function still not pinned; likely just past 0x81965000 or via fn-ptr. Widen scan to 0x81960000-0x81985000 and trace filtered to netprobe.

## RESOLVED 2026-11-07 — the "0 hits" was a DEAD HARNESS, not off-path
The whole "SChannel region 0 hits / validators off-path" result is INVALID: the
netprobe handshakes were not completing. Today netprobe fails at
`XHttpConnect/OpenRequest err=8` (ERROR_NOT_ENOUGH_MEMORY — a handle leak after
~230 loop rounds) BEFORE any TLS, and a non-halting break on sub_8195fb40 entry +
its untrusted-root site got 0 hits while netprobe "probed" every 6s. No handshake
reached the Certificate stage, so every cert function looked cold.

Static call graph (authoritative) — decompiled sub_81960FA8 (the state machine,
confirmed ~1/handshake on netprobe's thread, so it IS XHttp's path):
- dispatch key `r11_3 = (msg_type<<16) | state_byte`.
- msg_type 0x0b = TLS **Certificate** message -> cases 0xb0029 / 0xb0012 call
  **sub_8195fb40**, and `if (ret) goto error/abort`. So sub_8195fb40 = the XHttp
  Certificate-message handler / cert-trust verdict. (Earlier labelled "validator 2"
  and wrongly ruled out.)

Inside sub_8195fb40: builds the chain, reads chain-status flags at
`(conn+0xc)+0x2dc)+0xc`; bit 0x8000 = untrusted root. Three reject exits:
  0x8195fca0  SEC_E_CERT_EXPIRED   0x80090328  (gated by 0x8195fc84 bne)
  0x8195fcd0  SEC_E_UNTRUSTED_ROOT 0x80090325  (gated by 0x8195fcb4 beq)  <-- mitmproxy blocker
  0x8195fd80  SEC_E_WRONG_PRINCIPAL 0x80090322 (CN mismatch; left alone, mitmproxy CN matches)
Success path sets conn state 0x8a, but 0x8195fde4 re-tests 0x8000 and downgrades to 0x25.

PATCH (do all the work, skip only the distrust verdicts, keep state 0x8a) — a
plain `li r3,0; blr` at entry does NOT work (skips the state=0x8a store -> caller
sets 0x25 -> aborts; this is why the earlier entry-patch "failed"):
  0x8195fc84  40820028 bne 0x8195fcac -> 48000028 b   (skip expired)
  0x8195fcb4  41820028 beq 0x8195fcdc -> 48000028 b   (skip untrusted-root)  <-- key
  0x8195fde4  41820014 beq 0x8195fdf8 -> 48000014 b   (keep state 0x8a)

DONE: applied all three live via setmem (read back OK, xam stable). Ported into
ssltrust.cpp (dropped the off-path validator-1 target), rebuilt, deployed +
MD5-verified to Hdd:\ssltrust.xex. g_mark still @ base+0xB040 -> 0x91ECB040;
g_mark[3] now packs applied<<16|already<<8|bad per-site bitmask, [4]=result
(1=all good). NOT yet exercised by a complete handshake.

## VALIDATED 2026-11-07 — verdict bypass CONFIRMED, but forced trust CRASHES downstream
Relaunched netprobe fresh via `magicboot title=Hdd:\netprobe_title.xex directory=Hdd:\`
(the `directory=` arg is REQUIRED — without it DashLaunch falls back to the default title
Aurora; `xbeinfo running` shows the real title). Fresh netprobe cleared the err=8 leak and
reached the Certificate stage. Observed:
- **sub_8195fb40 HIT on netprobe thread 0xf9000000** -> CONFIRMS it is XHttp's cert path
  (the earlier "0 hits / off-path" was the dead-harness artifact, now proven).
- **0x8195FCD0 (untrusted-root error site) got 0 hits** -> the patch at 0x8195fcb4 branches
  around the rejection: the cert IS accepted, verdict = trusted. The patch does what it says.
- **THEN: 0xC0000005 crash loop on thread 0xf9000000**, fault address WALKS +4 from ~0:
  0xfffffffc, 0, 4, 8, 0xc, 0x10 ... 0x54+ ("Unhandled Exception (last chance)" x many),
  then `modunload netprobe_title.xex` and the console falls back to Aurora.
  Fault IAR not directly capturable: thread parks in the kernel exception reporter
  (Iar=0x80075360 lr=0x80072C7C in xboxkrnl) while reporting; one sample caught netprobe
  code (0x820005EC). The walk = a loop reading array[i] from a NULL base.
- Also: netprobe's own `XHttpSetOption(SECURITY_FEATURE=0x30000)` fails err=12018 (dead end,
  as known).

DIAGNOSIS: this is the "trust isn't a bool" wall (cf. memory [[xam-tls-cert-trust]] line re
sub_81955ab8). Forcing the verdict to trusted leaves a trusted-chain structure uninitialized;
the handshake continuation walks it -> NULL deref. sub_8195fb40's own success path runs fully
(pubkey IS extracted: sub_81953d80 populates r30+0x2e8), and the matched-cert ptrs
(*arg6/*arg7 via sub_81954540) are set. So the NULL is DOWNSTREAM of sub_8195fb40 returning
success, OR the still-set 0x8000 chain-status bit sends later code down an "untrusted but
proceeding" branch that derefs NULL. The chain-status 0x8000 flag is NOT set by sub_81954540
(that's just the hostname matcher) — it is set by the deeper root-trust verifier (unlocated).

## APPROACH A investigation 2026-11-07 — why forcing the verdict crashes
tshark of console<->proxy (interface 4, `host 192.168.50.30 and tcp port 8080`) during a
fresh probe: EVERY round is ClientHello -> (ServerHello,Certificate,ServerHelloDone) -> console
FIN. No ClientKeyExchange, same as pre-patch — but now with the 0xC0000005 crash. So the crash
happens in xam's handshake CONTINUATION (it tears down the connection = the FIN), not in netprobe.

Crash chain (static): ServerHelloDone (state-machine type 0x0e -> label_81961150) calls
  sub_81956b00(ssl_ctx, ...)   = negotiated-cipher setup; walks a STATIC cipher table
                                 (data_81a96f10, count data_81a97100) — not the NULL. Fine.
  then sub_8195fe10(ssl_ctx):  r11=*(ssl_ctx+0x60) [checked non-NULL], calls fn-ptr
                                 *(*(r11+0xc)+8), allocs 0x226 buf, then tail-calls
                                 sub_819592e0 (if *(ssl_ctx+8)!=0x20) or sub_819597d0 —
                                 THIS is the RSA key-exchange (encrypt premaster w/ server
                                 pubkey). The fault walk (read 0,4,8,... many words from ~0)
                                 matches reading an RSA modulus bignum from a NULL pointer.
CONCLUSION: forcing the verdict "trusted" is insufficient. The GENUINE trusted path populates
key-exchange structures (server pubkey / key material the premaster encrypt reads) that the
untrusted path never sets; sub_8195fb40's success path extracts a pubkey to ssl_ctx+0x2e8 (via
sub_81953d80) but the key-exchange reads a different, unpopulated location. Real approach A =
make the chain VALIDATE for real (so the trusted path runs and populates everything), i.e.
neutralize the ROOT-TRUST DECISION in xam's CryptoAPI chain engine — not merely skip the verdict.
Engine mapped so far: trust-error enum -> status bits in sub_81965b98 (var_578==0 -> 0x8000
untrusted-root; ==1 ->0x2000; ==2 ->0x4000; ==3 ->0x10000; 4 ->0x40000; 5 ->0x20000), emitted via
sub_8196c550 into a locally-built chain ctx; the DECISION (what sets var_578) is upstream in the
engine (sub_8196d498/sub_8196e610/sub_8196f100/sub_8196dbe8/sub_8196d5e8/sub_81930508 ...), a
large subsystem. The 0x8000 flag sub_8195fb40 reads at chainctx+0xc is the aggregated result.
Couldn't get the faulting IAR cleanly: thread parks in kernel exception reporter (0x80075360)
during the last-chance loop; `debugger connect` suppressed the notify-channel exception lines.

## PIVOTAL CORRECTION 2026-11-07 (live halting via debugger+stopon) — CERT IS ACCEPTED
Breakthrough tooling: `debugger connect name="cc"` THEN `stopon break` DOES halt the thread
(plain stopon without attaching did not). getcontext then returns the real regs (64-bit as
"0q................"; strip "0q"). This finally allowed live reads. Also: magicboot is a SOFT
reboot — it does NOT reload xam or DashLaunch plugins; only a physical power-cycle does. The
cold boot with ssltrust disabled (launch.ini plugin5 commented) gave a clean UNPATCHED xam
(sites 40820028/41820028/41820014) and a netprobe that loops cleanly (cert rejected, no crash).

Live facts at sub_8195fb40 (clean xam, mitmproxy cert), ssl_ctx is a FIXED GLOBAL 0x81B642E0:
- chainctx = *(ssl+0x2dc) heap; chainctx+0xc flag = 0x00000000 THROUGHOUT the function (the
  0x8000 "untrusted root" bit is NEVER set for this cert).
- sub_8195fb40 reaches the SUCCESS exit 0x8195FDCC (state=0x8a) every handshake and RETURNS 0.
  i.e. **xam ACCEPTS mitmproxy's cert.** No error exit (not 0x80090325/0328/0322) is ever taken.
- server pubkey IS extracted: ssl+0x2e8 = valid heap ptr after success. ver ssl+8 = 0x800 (TLS1.2).
- (0x81960818's 0x8000 is the TLS-version flag at ssl+8, a red herring; the heavy CryptoAPI chain
  engine sub_81965b98 etc. does NOT fire on this path.)

State-machine (sub_81960fa8) message trace per handshake: ServerHello(state 0x1B) ->
Certificate(state 0x29) -> sub_8195fb40 success(state 0x8a) -> sub_819566e8 runs -> THEN NOTHING.
**ServerHelloDone (type 0x0e) is NEVER processed**; the connection is torn down right after the
Certificate message and a brand-new handshake starts (new conn addr). Packet capture matches:
ClientHello -> ServerHello,Certificate,ServerHelloDone -> console FIN, no ClientKeyExchange.
netprobe logs send FAIL err=-2147023667 (WSAETIMEDOUT).

=> THE MITM BLOCKER IS NOT CERT TRUST. xam trusts mitmproxy's cert fine. The failure is a
handshake STALL after the Certificate message (ServerHelloDone/ClientKeyExchange never happen).
The whole ssltrust/cert-trust effort was aimed at a non-problem. The earlier "crash on forced
trust" was residual from a prior crash-looping netprobe instance, not the patch.

## *** SOLVED 2026-11-07 — MITM WORKS. One-instruction fix. ***
Root cause of the post-Certificate stall: the handshake state machine sub_81960fa8 is dispatched
on (msg_type<<16)|state. After the Certificate message, sub_8195fb40's SUCCESS path sets the
connection state to 0x8a. But there is NO case for a following ServerHelloDone at state 0x8a
((0x0e<<16)|0x8a = 0xe008a is unhandled) -> handshake silently stalls, console FINs, no
ClientKeyExchange, no alert. The handshake only advances from state 0x25, which DOES handle
ServerHelloDone (0xe0025) AND ServerKeyExchange (0xc0025). (sub_8195fb40 sets 0x8a for a cert it
deems "trusted"/flag0, 0x25 for "untrusted"/flag0x8000 — so paradoxically the TRUSTED state is the
dead-end. mitmproxy's cert reads trusted because the check is essentially hostname-match and
mitmproxy's CN matches, so flag=0 -> 0x8a -> stall.)

FIX (verified live, end-to-end): patch the success-state constant so the Certificate handler leaves
state 0x25 instead of 0x8a:
    0x8195FDD0  li r10,0x8a (3940008A)  ->  li r10,0x25 (39400025)
Result: netprobe HTTPS to www.google.com through mitmproxy went from silent FIN to **OK status=200
every round**; packet capture shows full handshake (ClientKeyExchange+CCS+Finished) and Application
Data flowing BOTH ways (incl. a 13KB response), plus TLS session resumption on later rounds.
This is a SINGLE patch; the old 3-branch "skip the reject / keep 0x8a" patches were based on the
wrong premise (cert trust) and patch #3 actively FORCED the stalling 0x8a — all removed.
ssltrust.cpp now applies only this one patch (kPatches = {0x8195FDD0, 3940008A -> 39400025}),
rebuilt + being deployed; launch.ini plugin5 re-enabled; keep liveblock=true (the patch forces
every TLS handshake down the 0x25 path system-wide).

## (obsolete) earlier NEXT: find why the handshake stalls after Certificate
Candidates: (a) xam sends a TLS alert vs silent close after Certificate (capture content_type==21);
(b) sub_819566e8's return after Certificate drives a close in the message loop (sub_819614e0);
(c) a record-framing issue: ServerHelloDone in the same/next segment not consumed. Investigate the
message loop that feeds sub_81960fa8 and what it does after the Certificate call returns.

## (OBSOLETE) earlier candidate fixes — were based on the wrong premise (cert trust)
A. ROOT CAUSE (preferred): find where the chain-status 0x8000 "untrusted root" bit is SET
   (the root-trust comparison that writes (conn+0xc)+0x2dc)+0xc) and prevent it, so the GENUINE
   trusted path runs and populates every structure -> no downstream NULL. Writer is a computed
   store to +0xc of the chain ctx; trace from sub_81952b40 / the chain-ctx allocator, or set a
   DATA write breakpoint on that DWORD during a handshake.
B. PIN THE CRASH: get the faulting IAR (register as debugger to read the first-chance context,
   or carve the saved CONTEXT from the kernel trap frame on the thread stack), decompile that
   function, and either supply the missing pointer or clear the 0x8000 bit in memory before it.
Console state after test: Aurora, stable; ssltrust still active (patches reboot-persistent).
WARNING: with ssltrust active, ANY untrusted-cert HTTPS handshake (not just mitmproxy) will
crash the title this same way. liveblock=TRUE keeps background Live off, but a MITM/untrusted
HTTPS from any title will crash it. To get a fully stable console meanwhile, remove ssltrust
from launch.ini (plugin5).
