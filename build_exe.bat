@echo off
echo ============================================================
echo Building APK Malware Scanner
echo ============================================================

REM Clean old builds
rmdir /s /q build dist 2>nul

REM Build with PyInstaller
pyinstaller --onefile ^
    --name APKMalwareScanner ^
    --hidden-import=app.sdk_patch ^
    --hidden-import=app.models.scan_models ^
    --hidden-import=app.scanners.combined_scanner ^
    --hidden-import=app.scanners.androguard_scanner ^
    --hidden-import=app.scanners.voice_phishing_scanner ^
    --hidden-import=app.utils.file_handler ^
    --hidden-import=win32service ^
    --hidden-import=win32serviceutil ^
    --hidden-import=win32event ^
    --hidden-import=servicemanager ^
    windows_service.py

echo.
echo ============================================================
echo BUILD COMPLETE!
echo Executable: dist\APKMalwareScanner.exe
echo ============================================================
echo.
echo To run as console: APKMalwareScanner.exe
echo To install as service: APKMalwareScanner.exe service --install
echo ============================================================
pause