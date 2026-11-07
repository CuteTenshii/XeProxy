# Building

You need an Xbox 360 XDK with the PowerPC `cl.exe`, `include/xbox` and `lib/xbox`. 21256 is the usual one, and the scripts default to `C:\Program Files (x86)\Microsoft Xbox 360 SDK`.

```bash
./build.sh                  # git bash / msys
```

```bat
build.bat                   :: cmd
```

Both produce `build/XeProxy.xex`. Point them elsewhere with the variables they document at the top:

```bash
XEDK=/c/XDK21256/XDK ./build.sh
EXTRA_DEFS="-W4" ./build.sh          # stricter warnings
```

The toolchain steps, for reference: `cl -c -W4 -Ox -MT -GR- -EHsc -TP` per source, then `link -DLL -ENTRY:_DllMainCRTStartup -XEX:NO -ALIGN:128,4096` against `xboxkrnl.lib xapilib.lib`, then `imagexex -config:XeProxy.xex.xml`. The xex is a `<sysdll/>`, which is what DashLaunch loads.

Both scripts first run `tools/mkdefaults.py`, which regenerates `src/default_ini.h` from `xeproxy.ini` so the config the plugin writes for itself cannot drift from the reference one. The header is committed, so a build without python uses it as-is; `mkdefaults.py --check` fails if it is stale. The generator refuses an `xeproxy.ini` with CRLF endings or without a bare `enabled = 0` line, so the self-written default can never come up live; `.gitattributes` keeps both files LF on a Windows checkout.

## Build status

Built and verified against XDK 21256, through both `build.sh` and `build.bat`:

- all nine sources compile with **zero warnings at `/W4`**, and link clean
- output is a valid `XEX2` DLL, PPCBE, subsystem Xbox, based where `XeProxy.xex.xml` says
- it imports **only `xboxkrnl.exe`** - everything from xam is resolved at runtime by ordinal, so there is no load-order dependency on xam's exports
- every hand-assembled instruction word was fed back through the XDK's own PowerPC disassembler and decodes as intended:

  ```
  7C8903A6 mtctr r4        3D601234 lis   r11,0x1234
  7C00186C dcbst r0,r3     396B5678 addi  r11,r11,0x5678
  7C0004AC sync            7D6903A6 mtctr r11
  7C001FAC icbi  r0,r3     4E800420 bctr
  38630020 addi  r3,r3,32
  4200FFF0 bdnz  -16       (lands on the dcbst)
  4C00012C isync
  4E800020 blr
  ```

Loaded and verified on a console (JTAG/RGH, DashLaunch, dashboard 17559) with the default nine hooks: hooks install, TCP traffic - Aurora's HTTP, a stealth server's raw TCP, XHttp's non-blocking connects - is tunnelled through mitmproxy in its regular mode with `mode = http`, and the TLS fix lets XHttp complete a handshake with mitmproxy's certificate (confirmed with the `netprobe` test title). See [Limits and known issues](limits.md) for what is not working yet.
