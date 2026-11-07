@echo off
rem Builds XeProxy.xex with the Xbox 360 XDK's PowerPC compiler.
rem Override the layout by setting these before running:
rem   XEDK      SDK root
rem   XDK_BIN   host tools            (default %XEDK%\bin\win32)
rem   XDK_INC   Xbox headers          (default %XEDK%\include\xbox)
rem   XDK_LIB   Xbox import libraries (default %XEDK%\lib\xbox)
rem   CRT_INC   extra C headers, when the compiler keeps them apart
rem   EXTRA_DEFS  extra cl flags, e.g. -D SOMETHING=1

setlocal enabledelayedexpansion
cd /d "%~dp0"

if "%XEDK%"=="" set XEDK=C:\Program Files (x86)\Microsoft Xbox 360 SDK
if "%XDK_BIN%"=="" set XDK_BIN=%XEDK%\bin\win32
if "%XDK_INC%"=="" set XDK_INC=%XEDK%\include\xbox
if "%XDK_LIB%"=="" set XDK_LIB=%XEDK%\lib\xbox

if not exist "%XDK_BIN%\cl.exe" (
  echo error: no PowerPC compiler at "%XDK_BIN%\cl.exe"
  echo.
  echo Set XEDK to an Xbox 360 XDK that has bin\win32\cl.exe, include\xbox and
  echo lib\xbox. If the plain C headers live elsewhere, set CRT_INC too.
  exit /b 1
)
if not exist "%XDK_INC%" echo error: "%XDK_INC%" does not exist ^(set XDK_INC^) & exit /b 1
if not exist "%XDK_LIB%" echo error: "%XDK_LIB%" does not exist ^(set XDK_LIB^) & exit /b 1

set INCLUDE=%XDK_INC%
if not "%CRT_INC%"=="" set INCLUDE=%XDK_INC%;%CRT_INC%
set LIB=%XDK_LIB%

set FORCEINC=
if exist "%XDK_INC%\xbox_intellisense_platform.h" set FORCEINC=-FI"%XDK_INC%\xbox_intellisense_platform.h"

rem src\default_ini.h is the committed copy of xeproxy.ini the plugin writes when
rem a console has none; regenerated here (when python is present) so an ini edit is not forgotten.
where python >nul 2>nul
if %ERRORLEVEL%==0 (
  python tools\mkdefaults.py || exit /b 1
) else (
  echo warning: no python, using the committed src\default_ini.h as-is
)

if not exist build mkdir build
del /q build\*.obj 2>nul

set OBJS=
for %%S in (main hooks vfs patch config defaults socks log util) do (
  echo cl  src\%%S.cpp
  "%XDK_BIN%\cl.exe" -nologo -c -W4 -Ox -MT -GR- -EHsc -TP -D _XBOX -D NDEBUG %EXTRA_DEFS% %FORCEINC% -Fobuild\%%S.obj src\%%S.cpp || exit /b 1
  set OBJS=!OBJS! build\%%S.obj
)

echo link
"%XDK_BIN%\link.exe" -nologo -RELEASE -OPT:REF -DLL -ENTRY:_DllMainCRTStartup -XEX:NO -ALIGN:128,4096 -OUT:build\XeProxy.exe !OBJS! xboxkrnl.lib xapilib.lib || exit /b 1

echo imagexex
"%XDK_BIN%\imagexex.exe" -nologo -config:XeProxy.xex.xml -out:build\XeProxy.xex build\XeProxy.exe || exit /b 1

echo.
echo build\XeProxy.xex
echo copy it next to xeproxy.ini and add it to launch.ini
endlocal
