@echo off
rem Builds netprobe title.xex, a launchable Xbox 360 homebrew (not a plugin).
setlocal enabledelayedexpansion
cd /d "%~dp0"

if "%XEDK%"=="" set XEDK=C:\Program Files (x86)\Microsoft Xbox 360 SDK
if "%XDK_BIN%"=="" set XDK_BIN=%XEDK%\bin\win32
if "%XDK_INC%"=="" set XDK_INC=%XEDK%\include\xbox
if "%XDK_LIB%"=="" set XDK_LIB=%XEDK%\lib\xbox

if not exist "%XDK_BIN%\cl.exe" echo error: no compiler at "%XDK_BIN%\cl.exe" & exit /b 1

set INCLUDE=%XDK_INC%
if not "%CRT_INC%"=="" set INCLUDE=%XDK_INC%;%CRT_INC%
set LIB=%XDK_LIB%

set FORCEINC=
if exist "%XDK_INC%\xbox_intellisense_platform.h" set FORCEINC=-FI"%XDK_INC%\xbox_intellisense_platform.h"

if not exist out mkdir out
del /q out\title.obj 2>nul

echo cl  title.cpp
"%XDK_BIN%\cl.exe" -nologo -c -W4 -Ox -MT -GR- -EHsc -TP -D _XBOX -D NDEBUG %FORCEINC% -Foout\title.obj title.cpp || exit /b 1

echo link (title exe)
"%XDK_BIN%\link.exe" -nologo -RELEASE -OPT:REF -ENTRY:mainCRTStartup -XEX:NO -OUT:out\title.exe out\title.obj xboxkrnl.lib xapilib.lib xnet.lib xhttp.lib xbdm.lib || exit /b 1

echo imagexex (title)
"%XDK_BIN%\imagexex.exe" -nologo -config:title.xex.xml -out:out\netprobe_title.xex out\title.exe || exit /b 1

echo.
echo out\netprobe_title.xex
endlocal
