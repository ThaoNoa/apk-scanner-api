import subprocess
import time
import os
import logging
from typing import Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)


class EmulatorManager:
    """Quản lý Android emulator cho dynamic analysis"""

    def __init__(self, avd_name: str = "dynamic_analyzer"):
        self.avd_name = avd_name
        self.emulator_process = None
        self.adb_path = self._find_adb()

    def _find_adb(self) -> str:
        """Tìm đường dẫn ADB"""
        possible_paths = [
            "adb",
            os.path.expanduser("~/Android/Sdk/platform-tools/adb"),
            "C:\\Android\\Sdk\\platform-tools\\adb.exe"
        ]

        for path in possible_paths:
            try:
                subprocess.run([path, "version"], capture_output=True)
                return path
            except:
                continue

        raise Exception("ADB not found")

    def create_avd(self, android_version: str = "android-30") -> bool:
        """Tạo AVD mới"""
        try:
            # Tạo avd
            cmd = f"avdmanager create avd -n {self.avd_name} -k 'system-images;{android_version};google_apis;x86'"
            subprocess.run(cmd, shell=True, check=True)

            logger.info(f"AVD {self.avd_name} created")
            return True
        except Exception as e:
            logger.error(f"Failed to create AVD: {e}")
            return False

    def start_emulator(self, wipe_data: bool = True) -> bool:
        """Start emulator"""
        try:
            cmd = f"emulator -avd {self.avd_name}"
            if wipe_data:
                cmd += " -wipe-data"

            self.emulator_process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # Đợi emulator boot
            time.sleep(30)

            # Đợi device online
            self._wait_for_device()

            logger.info("Emulator started")
            return True
        except Exception as e:
            logger.error(f"Failed to start emulator: {e}")
            return False

    def _wait_for_device(self, timeout: int = 60):
        """Đợi device online"""
        start = time.time()
        while time.time() - start < timeout:
            result = subprocess.run(
                [self.adb_path, "shell", "getprop", "sys.boot_completed"],
                capture_output=True,
                text=True
            )
            if result.stdout.strip() == "1":
                return True
            time.sleep(2)
        raise TimeoutError("Device not ready")

    def install_apk(self, apk_path: str) -> bool:
        """Install APK lên emulator"""
        try:
            subprocess.run(
                [self.adp_path, "install", "-r", apk_path],
                check=True,
                capture_output=True
            )
            logger.info(f"APK installed: {apk_path}")
            return True
        except Exception as e:
            logger.error(f"Install failed: {e}")
            return False

    def run_monkey_test(self, package_name: str, events: int = 1000) -> Dict:
        """Run Android Monkey test để tương tác tự động"""
        try:
            cmd = [
                self.adb_path, "shell",
                f"monkey -p {package_name} -v {events}"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)

            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr
            }
        except Exception as e:
            logger.error(f"Monkey test failed: {e}")
            return {"success": False, "error": str(e)}

    def capture_network_traffic(self, package_name: str, duration: int = 60) -> Path:
        """Capture network traffic bằng tcpdump"""
        pcap_path = Path(f"/tmp/{package_name}_{int(time.time())}.pcap")

        try:
            # Start tcpdump
            subprocess.Popen([
                self.adb_path, "shell",
                "tcpdump", "-i", "any",
                "-w", f"/data/local/tmp/capture.pcap"
            ])

            time.sleep(duration)

            # Pull pcap file
            subprocess.run([
                self.adb_path, "pull",
                "/data/local/tmp/capture.pcap",
                str(pcap_path)
            ])

            return pcap_path
        except Exception as e:
            logger.error(f"Traffic capture failed: {e}")
            return None

    def stop_emulator(self):
        """Stop emulator"""
        if self.emulator_process:
            self.emulator_process.terminate()
            self.emulator_process = None