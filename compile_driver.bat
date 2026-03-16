@echo off
REM ================================================================
REM Live Memory Forensics Toolkit - Driver Compilation Script
REM ================================================================
REM Requirements:
REM 1. Visual Studio 2019/2022 with C++ Desktop Development
REM 2. Windows Driver Kit (WDK) 10/11
REM ================================================================

echo [*] Checking for WDK environment...

if not defined WDKContentRoot (
    echo [!] WDK Environment Variables not found.
    echo [!] Please open "x64 Native Tools Command Prompt for VS 2022"
    echo [!] and unsure WDK is installed.
    pause
    exit /b 1
)

echo [*] Setting up build environment...
set DRIVER_NAME=LMFDriver
set SOURCE_DIR=kernel\driver
set BUILD_DIR=kernel\build

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [*] Compiling %DRIVER_NAME%...
cl /nologo /c /O2 /W4 /GS /D_WIN32_WINNT=0x0A00 /I"%WDKContentRoot%\Include\10.0.22621.0\km" /I"%WDKContentRoot%\Include\10.0.22621.0\shared" "%SOURCE_DIR%\%DRIVER_NAME%.c" /Fo"%BUILD_DIR%\"

if %ERRORLEVEL% NEQ 0 (
    echo [!] Compilation Failed!
    pause
    exit /b %ERRORLEVEL%
)

echo [*] Linking...
link /nologo /DRIVER /ENTRY:DriverEntry /OUT:"%BUILD_DIR%\%DRIVER_NAME%.sys" "%BUILD_DIR%\%DRIVER_NAME%.obj" /SUBSYSTEM:NATIVE /IGNORE:4078

if %ERRORLEVEL% NEQ 0 (
    echo [!] Linking Failed!
    pause
    exit /b %ERRORLEVEL%
)

echo.
echo [SUCCESS] Driver compiled at: %BUILD_DIR%\%DRIVER_NAME%.sys
echo.
echo NOTE: To load this driver, you must enable Test Signing Mode:
echo bcdedit /set testsigning on
echo (Requires Reboot)
echo.
pause
