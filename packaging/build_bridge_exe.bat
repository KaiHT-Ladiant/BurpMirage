@echo off
REM Build the standalone BurpMirage Frida bridge (burpmirage-bridge.exe).
REM Requires a 64-bit Python 3.9+ on PATH. Installs build deps automatically.
setlocal

set "PY=%~1"
if "%PY%"=="" set "PY=python"

echo [*] Using Python: %PY%
"%PY%" -m pip install --upgrade pyinstaller frida || goto :err

echo [*] Building single-file executable...
"%PY%" -m PyInstaller packaging\burpmirage_bridge.spec --noconfirm --clean || goto :err

echo.
echo [+] Done: dist\burpmirage-bridge.exe
exit /b 0

:err
echo [!] Build failed.
exit /b 1
