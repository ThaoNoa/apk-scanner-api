"""
Windows Service Wrapper for APK Malware Scanner
Allows the scanner to run as a Windows Service
"""

import sys
import os
import time
import logging
import signal
import threading
from pathlib import Path

# Setup logging for Windows Event Log
try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False
    print("Warning: pywin32 not installed. Running in console mode.")

import uvicorn
from app.main import app

# Configuration
CONFIG = {
    "host": "0.0.0.0",
    "port": 8000,
    "log_dir": "C:\\ProgramData\\APKMalwareScanner\\logs",
    "upload_dir": "C:\\ProgramData\\APKMalwareScanner\\uploads",
    "config_file": "C:\\ProgramData\\APKMalwareScanner\\config.json"
}

class APKScannerService:
    """Windows Service for APK Malware Scanner"""

    def __init__(self):
        self.server_thread = None
        self.server = None
        self.is_running = False

    def start(self):
        """Start the service"""
        self.is_running = True
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True
        self.server_thread.start()

    def _run_server(self):
        """Run the FastAPI server"""
        uvicorn.run(
            app,
            host=CONFIG["host"],
            port=CONFIG["port"],
            log_level="info",
            access_log=True
        )

    def stop(self):
        """Stop the service"""
        self.is_running = False
        if self.server_thread:
            self.server_thread.join(timeout=5)

class ServiceLauncher:
    """Launch the application as Windows Service or Console"""

    @staticmethod
    def run_as_service():
        """Run as Windows Service"""
        if not IS_WINDOWS:
            print("Cannot run as service on non-Windows platform")
            return

        win32serviceutil.ServiceFramework.__init__()

    @staticmethod
    def run_as_console():
        """Run as console application"""
        server = APKScannerService()

        def signal_handler(signum, frame):
            print("\nShutting down server...")
            server.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        print("=" * 60)
        print("APK Malware Scanner starting...")
        print(f"API Documentation: http://{CONFIG['host']}:{CONFIG['port']}/docs")
        print(f"Health Check: http://{CONFIG['host']}:{CONFIG['port']}/health")
        print("Press Ctrl+C to stop")
        print("=" * 60)

        server.start()

        while True:
            time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "service":
        ServiceLauncher.run_as_service()
    else:
        ServiceLauncher.run_as_console()