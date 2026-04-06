# APK Malware Scanner

## Overview

A comprehensive APK malware scanner with voice phishing detection, static analysis, and F1 Score evaluation.

## Features

- Static analysis with Androguard
- Voice phishing detection (outgoing call hijacking + incoming call spoofing)
- Windows Service support
- RESTful API with Swagger documentation
- Batch processing (multiple APK files)
- F1 Score evaluation with 20,000+ dataset

## Installation

### Windows

1. Download APKMalwareScanner_Setup.exe
2. Run the installer
3. Follow setup wizard
4. Launch from desktop shortcut

### Manual Installation

git clone <repository>
cd apk-scanner-api
pip install -r requirements.txt
python windows_service.py

## Usage

### Start Scanner

Console mode:
python windows_service.py

Windows Service mode:
python windows_service.py service

### API Endpoints

POST /scan/apks - Upload and scan APK files
GET /scan/result/{batch_id} - Get scan results
GET /health - Health check
GET /docs - Swagger documentation

### Example Request

curl -X POST "http://localhost:8000/scan/apks" -F "files=@app.apk"

## Detection Criteria

See DETECTION_CRITERIA.md for detailed detection rules.

## Result Documentation

See RESULT_DOCUMENTATION.md for field descriptions.

## Building Installer

python scripts/build_installer.py

## Requirements

- Windows 10/11 or Windows Server 2019+
- Python 3.14+
- 4GB RAM minimum
- 1GB free disk space

## License

Proprietary - Internal Use Only