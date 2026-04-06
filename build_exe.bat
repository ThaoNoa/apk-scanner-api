@echo off
echo ============================================================
echo Building APK Malware Scanner Executable
echo ============================================================

REM Clean old builds
rmdir /s /q build dist 2>nul

REM Build with PyInstaller
pyinstaller --onefile ^
    --name APKMalwareScanner ^
    --hidden-import=app.sdk_patch ^
    --hidden-import=androguard ^
    --hidden-import=androguard.core ^
    --hidden-import=androguard.core.bytecodes ^
    --hidden-import=androguard.core.analysis ^
    --collect-data=androguard ^
    windows_service.py

echo.
echo ============================================================
echo Build complete!
echo Executable: dist\APKMalwareScanner.exe
echo ============================================================
pause