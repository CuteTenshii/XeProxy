#!/usr/bin/env bash
# Builds XeProxy.xex with the Xbox 360 XDK's own PowerPC compiler. No Visual
# Studio involved. Override any of these if your XDK is laid out differently:
#
#   XEDK      SDK root                  (default: the XEDK environment variable)
#   XDK_BIN   host tools                (default: $XEDK/bin/win32)
#   XDK_INC   Xbox headers              (default: $XEDK/include/xbox)
#   XDK_LIB   Xbox import libraries     (default: $XEDK/lib/xbox)
#   CRT_INC   extra C headers, if the compiler keeps them apart from XDK_INC
#   EXTRA_DEFS  extra cl flags, e.g. "-D SOMETHING=1"

set -e
cd "$(dirname "$0")"

XEDK="${XEDK:-/c/Program Files (x86)/Microsoft Xbox 360 SDK}"
BIN="${XDK_BIN:-$XEDK/bin/win32}"
INC="${XDK_INC:-$XEDK/include/xbox}"
LIBDIR="${XDK_LIB:-$XEDK/lib/xbox}"

if [ ! -f "$BIN/cl.exe" ]; then
    cat >&2 <<MSG
error: no PowerPC compiler at $BIN/cl.exe

Set XEDK to an Xbox 360 XDK that has bin/win32/cl.exe, include/xbox and
lib/xbox. Some installs keep the plain C headers apart from include/xbox;
point CRT_INC at those as well:

  XEDK=/c/XDK21256/XDK CRT_INC=/c/XDK21256/TP/.../include/xbox ./build.sh
MSG
    exit 1
fi

for d in "$INC" "$LIBDIR"; do
    if [ ! -d "$d" ]; then
        echo "error: $d does not exist (set XDK_INC / XDK_LIB)" >&2
        exit 1
    fi
done

WINC="$(cygpath -w "$INC")"
WLIB="$(cygpath -w "$LIBDIR")"
if [ -n "$CRT_INC" ]; then
    WINC="$WINC;$(cygpath -w "$CRT_INC")"
fi

# The XDK force-includes this to get the platform macros right. It has to stay
# one argument, since the path contains spaces.
CLFLAGS=(-nologo -c -W4 -Ox -MT -GR- -EHsc -TP -D _XBOX -D NDEBUG)
if [ -f "$INC/xbox_intellisense_platform.h" ]; then
    CLFLAGS+=("-FI$(cygpath -w "$INC/xbox_intellisense_platform.h")")
fi
# shellcheck disable=SC2206
[ -n "$EXTRA_DEFS" ] && CLFLAGS+=($EXTRA_DEFS)

SOURCES=(src/main.cpp src/hooks.cpp src/vfs.cpp src/patch.cpp src/config.cpp src/defaults.cpp src/socks.cpp src/log.cpp src/util.cpp)

# src/default_ini.h is the committed copy of xeproxy.ini the plugin writes when a
# console has none; regenerated here (when python is present) so an ini edit is not forgotten.
PY="$(command -v python3 || command -v python || true)"
if [ -n "$PY" ]; then
    "$PY" tools/mkdefaults.py
else
    echo "warning: no python, using the committed src/default_ini.h as-is"
fi

mkdir -p build
rm -f build/*.obj

OBJS=()
for src in "${SOURCES[@]}"; do
    obj="build/$(basename "${src%.cpp}").obj"
    echo "cl  $src"
    INCLUDE="$WINC" "$BIN/cl.exe" "${CLFLAGS[@]}" -Fo"$obj" "$src"
    OBJS+=("$obj")
done

echo "link"
LIB="$WLIB" "$BIN/link.exe" -nologo -RELEASE -OPT:REF -DLL -ENTRY:_DllMainCRTStartup \
    -XEX:NO -ALIGN:128,4096 -OUT:build/XeProxy.exe "${OBJS[@]}" xboxkrnl.lib xapilib.lib

echo "imagexex"
"$BIN/imagexex.exe" -nologo -config:XeProxy.xex.xml -out:build/XeProxy.xex build/XeProxy.exe

echo
echo "build/XeProxy.xex"
echo "copy it next to xeproxy.ini and add it to launch.ini"
