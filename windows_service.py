# windows_service.py
import os
import sys
import warnings
warnings.filterwarnings("ignore")

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

# Import SDK patch first
import app.sdk_patch
app.sdk_patch.setup_android_sdk()

import uvicorn
from app.main import app

if __name__ == "__main__":
    print("=" * 60)
    print("APK Malware Scanner - Starting...")
    print("=" * 60)
    print(f"Android SDK: {os.environ.get('ANDROID_HOME', 'Not set')}")
    print("API Documentation: http://localhost:8000/docs")
    print("Health Check: http://localhost:8000/health")
    print("")
    print("Press Ctrl+C to stop")
    print("=" * 60)

    uvicorn.run(app, host="0.0.0.0", port=8000)