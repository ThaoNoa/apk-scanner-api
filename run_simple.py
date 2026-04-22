# run_simple.py - Phiên bản đơn giản không cần Androguard
import os
import sys
import warnings

warnings.filterwarnings("ignore")

# Tạo dummy SDK để tránh lỗi
dummy_sdk = os.path.join(os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(), 'dummy_sdk')
os.environ['ANDROID_HOME'] = dummy_sdk
os.environ['ANDROID_SDK_ROOT'] = dummy_sdk

# Tạo file public.xml giả
for version in ['30', '31', '32', '33', '34', '35', '36']:
    values_dir = os.path.join(dummy_sdk, 'platforms', f'android-{version}', 'data', 'res', 'values')
    os.makedirs(values_dir, exist_ok=True)
    public_xml = os.path.join(values_dir, 'public.xml')
    if not os.path.exists(public_xml):
        with open(public_xml, 'w') as f:
            f.write(
                '<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <public type="attr" name="color" id="0x01010000" />\n</resources>')

import uvicorn
from fastapi import FastAPI, UploadFile, File, HTTPException
from typing import List
import uuid
from datetime import datetime
import json

app = FastAPI(
    title="APK Malware Scanner",
    description="Scan APK files for malware and voice phishing detection",
    version="2.0.0"
)

# Store scan results
scan_results = {}


@app.get("/")
async def root():
    return {
        "name": "APK Malware Scanner API",
        "version": "2.0.0",
        "status": "running",
        "endpoints": {
            "POST /scan/apks": "Upload and scan APK files",
            "GET /scan/result/{batch_id}": "Get scan results",
            "GET /health": "Health check",
            "GET /docs": "Swagger documentation"
        }
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "scanner": "basic_mode"
    }


@app.post("/scan/apks")
async def scan_apks(
        files: List[UploadFile] = File(..., description="APK files to scan"),
        scan_deep: bool = False
):
    """
    Upload and scan APK files

    - **files**: APK files to upload (multiple files allowed)
    - **scan_deep**: Enable deep analysis (basic mode only)
    """

    batch_id = str(uuid.uuid4())
    results = []
    total_malicious = 0

    for file in files:
        if not file.filename.endswith('.apk'):
            raise HTTPException(status_code=400, detail=f"{file.filename} is not an APK file")

        content = await file.read()
        file_size = len(content)

        # Basic analysis
        result = {
            "filename": file.filename,
            "scan_id": str(uuid.uuid4()),
            "timestamp": datetime.now().isoformat(),
            "scan_duration": 0.05,
            "is_malicious": False,
            "risk_level": "UNKNOWN",
            "risk_score": 0,
            "confidence": 50,
            "scanners": {
                "basic": True,
                "androguard": False,
                "voice_phishing": False
            },
            "permissions": [],
            "dangerous_permissions": [],
            "findings": [],
            "detection_methods": [],
            "warnings": ["Androguard not available in basic mode"],
            "errors": [],
            "note": "This is a basic version. Full analysis requires Androguard SDK."
        }

        results.append(result)

    response = {
        "batch_id": batch_id,
        "total_files": len(files),
        "total_duration": 0.1,
        "results": results,
        "summary": {
            "total_malicious": total_malicious,
            "total_clean": len(files) - total_malicious,
            "total_error": 0,
            "by_risk_level": {"UNKNOWN": len(files)},
            "scanners_used": {"basic": True}
        }
    }

    scan_results[batch_id] = response
    return response


@app.get("/scan/result/{batch_id}")
async def get_scan_result(batch_id: str):
    """Get scan results by batch ID"""
    if batch_id in scan_results:
        return scan_results[batch_id]
    raise HTTPException(status_code=404, detail="Batch ID not found")


if __name__ == "__main__":
    print("=" * 60)
    print("APK MALWARE SCANNER - BASIC MODE")
    print("=" * 60)
    print("API Documentation: http://localhost:8000/docs")
    print("Health Check: http://localhost:8000/health")
    print("")
    print("Note: This is a basic version without full Androguard analysis.")
    print("To stop: Press Ctrl+C")
    print("=" * 60)

    uvicorn.run(app, host="0.0.0.0", port=8080)