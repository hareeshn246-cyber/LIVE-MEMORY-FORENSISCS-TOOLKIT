@echo off
setlocal
set OLD_NAME=INFOZIANT
set NEW_NAME=FORENSICS PROJECT

echo ============================================================
echo PROJECT RENAME UTILITY: %OLD_NAME% -^> %NEW_NAME%
echo ============================================================
echo.
echo 1. Please CLOSE your IDE (VS Code) and all open terminals.
echo 2. This script will wait 10 seconds to allow file locks to release.
echo 3. The folder will then be renamed automatically.
echo.
timeout /t 10

cd ..
ren "%OLD_NAME%" "%NEW_NAME%"

if %ERRORLEVEL% equ 0 (
    echo.
    echo SUCCESS! Project folder renamed to "%NEW_NAME%"
) else (
    echo.
    echo ERROR: Could not rename folder. Please ensure all programs 
    echo accessing the folder (IDE, Terminal, Explorer) are closed.
)
pause
