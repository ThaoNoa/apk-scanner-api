@echo off
echo ============================================================
echo Installing APK Malware Scanner as Windows Service
echo ============================================================
echo.

REM Run as Administrator check
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Please run this script as Administrator
    echo Right-click -> Run as Administrator
    pause
    exit /b 1
)

echo Installing service...
APKMalwareScanner.exe service --install

echo.
echo Setting service to auto-start...
sc config APKMalwareScanner start= auto

echo.
echo Starting service...
net start APKMalwareScanner

echo.
echo ============================================================
echo Service installed successfully!
echo Service will run automatically after server restarts
echo ============================================================
echo.
echo To stop service: net stop APKMalwareScanner
echo To uninstall: APKMalwareScanner.exe service --remove
echo.
pause