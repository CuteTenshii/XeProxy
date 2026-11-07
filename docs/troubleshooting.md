# Troubleshooting

## No log at all - check this first

A DashLaunch system plugin loads *only* at the base address built into its xex; nothing relocates it. If its range overlaps a plugin already mapped, it does not load at all - no `DllMain`, no thread, no log - and the one listed later in `launch.ini` is the one that loses. This is the single most common reason a plugin is silently absent, and it looks identical to "the code is broken".

Known occupants, from [Xbox360AutoDNS PR #4](https://github.com/dclstn/Xbox360AutoDNS/pull/4):

| Range | Plugin |
|---|---|
| `0x91000000` | xbdm |
| `0x91900000` | JRPC2 |
| `0x91C10000-0x91D2A000` | NiNJA_WAW |
| `0x91D00000-0x91D8A000` | codxe, XeCord, iw3-codjumper, PcMic-360, 0xJ |
| `0x91DC0000-0x91DC8000` | AutoDNS |
| `0x91DE0000-0x91DE8000` | CoronaKeysFix |
| `0x91DF0000-0x91DF8000` | UsbdSecPatch |
| `0x91E00000-0x91E6D000` | RPC360 |
| `0x91F00000-` | **DashLaunch's own `launch.xex`** |

XeProxy is built at `0x91E80000` and needs about 116 KB, so it occupies `0x91E80000-0x91EAB000` - in the gap between RPC360's end and `launch.xex`.

Anything *not* in that table is unknown, not free. Copy your other plugins off the console and check for yourself:

```
python tools/xexbase.py XeProxy.xex Xbdm.xex XeCord.xex HvP2.xex Proto.xex
```

It prints each one's real mapped range (from the xex security header, which is readable even on a compressed xex) and names any pair that overlaps. If XeProxy clashes, pick a free address, change `baseaddr` in `XeProxy.xex.xml`, and rebuild.

Once it does load, the first log line reports where it landed - `XeProxy 1.0 starting, image at ~91E80000` - so a later collision caused by adding another plugin is visible rather than mysterious.

## Still nothing, and the base is clear

Then either the `[Plugins]` path is wrong, or you are out of plugin slots (`plugin1`-`plugin5` only). Failing that, watch the debug output live - see below.

## "no ini found", or no log file anywhere

These are usually the same fault: the plugin cannot open files by the names you gave it.

`Hdd:`, `Usb0:` and `Flash:` are **not kernel device links**. A real retail kernel's object namespace contains only `\??\D:` - the drive-style names are a convention of DashLaunch, XeXMenu and FSD, each of which resolves them privately. A plugin calling `CreateFile("Hdd:\\xeproxy.ini")` is relying on a link that may simply not be published, and when it is not, every open fails and the plugin reports "no ini found" having never read a byte.

So each path is tried three ways, and the log names the one that worked:

```
log: writing to Hdd:\xeproxy.log (opened via native-device)
config: opened Hdd:\xeproxy.ini via native-device
```

| `how` | meaning |
|---|---|
| `link` | plain `CreateFile` on `Hdd:\...` worked - a link existed |
| `win32-device` | `CreateFile` on `\Device\Harddisk0\Partition1\...` worked |
| `native-device` | only `NtCreateFile` on the raw device path worked |
| `native` | you gave a `\Device\...` path yourself |

The device paths come from the kernel's own strings: `\Device\Harddisk0\Partition1` (HDD), `\Device\Mass0`-`Mass2` (USB), `\Device\Flash` (NAND). You can also put a raw path straight into `[general] log`, and `mount: n/6 device links usable` says how many drive-letter links exist at all.

## The ini is found but ignored

There is a size limit (16 KB) and a file over it is refused, which reads downstream as "not found". The annotated `xeproxy.ini` is already 7.9 KB of comments, so there is room, but the log says so explicitly: `config: ... is N bytes, limit is 16384`.

## Watching it live over xbdm

Everything the plugin logs also goes out via `OutputDebugString`, which does not depend on any filesystem. With `debugout = true` in `launch.ini` and `xbdm.xex` loaded as a plugin, point the XDK's `xbwatson.exe` (in `bin\win32`) at the console and reboot - or stream it with `python tools/xbdm.py notify`. If lines appear there but no file is written, the plugin is running fine and the problem is only the log device. If nothing appears at all, it never loaded.

## Log messages

**`NetDll_x (ordinal n) did not resolve`.** That ordinal is not an export on your kernel. Put the right one under `[ordinals]`; the names there match the log exactly.

**`no executable memory available, hooks disabled`.** Neither `XPhysicalAlloc`'d memory nor the plugin's own image data would execute. The plugin stops instead of writing a jump to a trampoline that cannot run.

**`prologue insn N (xxxxxxxx) will not reach`.** That function starts with a branch that cannot be relocated into the trampoline. The hook refused itself and xam is untouched; everything else still installed.

**`socks5: greeting failed` / `http: no reply to CONNECT`, after exactly `socks_timeout_ms`.** The proxy accepted the TCP connection but never answered the handshake. Usually the mode is wrong for the proxy: mitmproxy's default regular mode speaks HTTP, so it needs `mode = http`, not `socks5`. For `http` it can also mean the destination itself never answered - mitmproxy connects upstream before it replies `200`.

## The console hangs or freezes

Set `log_level = 3`, put the config on a USB stick (it overrides the hard drive's and logs to the stick, so the log survives the hang), reproduce, and read the last lines on a PC. Then narrow things down:

- a `*` rule catches the console's own traffic to Microsoft as well as the game's - add `passthrough` exceptions above it;
- with more than the default nine `[hooks]` enabled, see [Known issues](limits.md#known-issues).
