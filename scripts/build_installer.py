#!/usr/bin/env python3
"""
Build script for creating Windows installer
Run: python build_installer.py
"""

import subprocess
import sys
import os
import shutil
from pathlib import Path


def run_command(cmd, description):
    """Run a command and print output"""
    print(f"\n{description}...")
    print(f"Command: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"ERROR: {result.stderr}")
        return False
    print(f"SUCCESS: {result.stdout[:200] if result.stdout else 'Done'}")
    return True


def main():
    print("=" * 60)
    print("APK Malware Scanner - Installer Builder")
    print("=" * 60)

    # Step 1: Install required packages
    print("\nStep 1: Installing build dependencies...")
    packages = [
        "pyinstaller",
        "pywin32" if sys.platform == "win32" else ""
    ]
    for pkg in packages:
        if pkg:
            run_command(f"pip install {pkg}", f"Installing {pkg}")

    # Step 2: Clean previous builds
    print("\nStep 2: Cleaning previous builds...")
    for dir_name in ["build", "dist", "__pycache__"]:
        if os.path.exists(dir_name):
            shutil.rmtree(dir_name)
            print(f"Removed: {dir_name}")

    # Step 3: Run PyInstaller
    print("\nStep 3: Building executable with PyInstaller...")
    if not run_command("pyinstaller --onefile --name APKMalwareScanner windows_service.py", "PyInstaller build"):
        print("ERROR: PyInstaller build failed")
        return

    # Step 4: Create config file in dist directory
    print("\nStep 4: Creating configuration file...")
    shutil.copy("config.json", "dist/config.json")

    # Step 5: Create documentation files
    print("\nStep 5: Copying documentation...")
    doc_files = [
        "docs/RESULT_DOCUMENTATION.md",
        "docs/DETECTION_CRITERIA.md",
        "README.md"
    ]
    for doc in doc_files:
        if os.path.exists(doc):
            shutil.copy(doc, "dist/")
            print(f"Copied: {doc}")

    # Step 6: Create directory structure
    print("\nStep 6: Creating directory structure...")
    for dir_name in ["uploads", "logs"]:
        os.makedirs(f"dist/{dir_name}", exist_ok=True)
        print(f"Created: dist/{dir_name}")

    # Step 7: Create Inno Setup script
    print("\nStep 7: Creating Inno Setup script...")
    inno_script = '''
[Setup]
AppName=APK Malware Scanner
AppVersion=2.0.0
AppPublisher=Security Team
DefaultDirName={pf}\\APKMalwareScanner
DefaultGroupName=APK Malware Scanner
UninstallDisplayIcon={app}\\APKMalwareScanner.exe
Compression=lzma2
SolidCompression=yes
OutputDir=installer
OutputBaseFilename=APKMalwareScanner_Setup

[Files]
Source: "dist\\APKMalwareScanner.exe"; DestDir: "{app}"
Source: "dist\\config.json"; DestDir: "{app}"
Source: "dist\\RESULT_DOCUMENTATION.md"; DestDir: "{app}"
Source: "dist\\DETECTION_CRITERIA.md"; DestDir: "{app}"
Source: "dist\\README.md"; DestDir: "{app}"

[Icons]
Name: "{group}\\APK Malware Scanner"; Filename: "{app}\\APKMalwareScanner.exe"
Name: "{group}\\Uninstall APK Malware Scanner"; Filename: "{uninstallexe}"
Name: "{commondesktop}\\APK Malware Scanner"; Filename: "{app}\\APKMalwareScanner.exe"

[Run]
Filename: "{app}\\APKMalwareScanner.exe"; Description: "Launch APK Malware Scanner"; Flags: postinstall nowait skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\\uploads"
Type: filesandordirs; Name: "{app}\\logs"
'''

    with open('installer.iss', 'w') as f:
        f.write(inno_script)
    print("Created: installer.iss")

    # Step 8: Run Inno Setup (if available)
    print("\nStep 8: Creating installer with Inno Setup...")
    inno_paths = [
        "C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe",
        "C:\\Program Files\\Inno Setup 6\\ISCC.exe"
    ]

    inno_found = False
    for inno_path in inno_paths:
        if os.path.exists(inno_path):
            if run_command(f'"{inno_path}" installer.iss', "Inno Setup compilation"):
                inno_found = True
            break

    if inno_found:
        print("\n" + "=" * 60)
        print("BUILD SUCCESSFUL!")
        print("Installer location: installer/APKMalwareScanner_Setup.exe")
        print("=" * 60)
    else:
        print("\nInno Setup not found. Manual packaging required.")
        print("1. Install Inno Setup from: https://jrsoftware.org/isinfo.php")
        print("2. Open installer.iss in Inno Setup")
        print("3. Click Compile")
        print("\nThe executable is located in: dist/APKMalwareScanner.exe")

    print("\nTo run the scanner:")
    print("  Console mode: dist\\APKMalwareScanner.exe")
    print("  Service mode: dist\\APKMalwareScanner.exe service")
    print("  API docs: http://localhost:8000/docs")


if __name__ == "__main__":
    main()