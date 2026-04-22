"""
APK Malware Scanner - Windows Service
Run as: APKMalwareScanner.exe service --install
"""

import os
import sys
import time
import logging
import warnings
warnings.filterwarnings("ignore")

# Setup paths
if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

os.chdir(BASE_DIR)
sys.path.insert(0, BASE_DIR)

# Setup logging
LOG_DIR = os.path.join(BASE_DIR, 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'scanner.log')),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Windows Service imports
try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    IS_WINDOWS = True
except ImportError:
    IS_WINDOWS = False
    logger.warning("pywin32 not installed. Running in console mode.")

import uvicorn
from app.main import app

class APKScannerService:
    def __init__(self):
        self.is_running = True

    def start(self):
        logger.info("Starting APK Malware Scanner...")
        uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")

    def stop(self):
        self.is_running = False
        logger.info("Stopping APK Malware Scanner...")

if IS_WINDOWS:
    class APKScannerWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "APKMalwareScanner"
        _svc_display_name_ = "APK Malware Scanner Service"
        _svc_description_ = "Scans APK files for malware and voice phishing"

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.scanner = APKScannerService()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
            self.scanner.stop()

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            self.scanner.start()

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "service" and IS_WINDOWS:
        win32serviceutil.HandleCommandLine(APKScannerWindowsService)
    else:
        scanner = APKScannerService()
        try:
            scanner.start()
        except KeyboardInterrupt:
            scanner.stop()

if __name__ == "__main__":
    main()