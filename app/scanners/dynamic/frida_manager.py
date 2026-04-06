import frida
import time
import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class FridaManager:
    """Quản lý kết nối Frida và thực thi scripts"""

    def __init__(self):
        self.session = None
        self.device = None
        self.scripts = []

    def connect_to_device(self, device_id: str = None) -> bool:
        """Kết nối đến thiết bị Android qua USB"""
        try:
            if device_id:
                self.device = frida.get_device(device_id)
            else:
                # Tự động tìm thiết bị USB
                devices = frida.enumerate_devices()
                for device in devices:
                    if device.type == 'usb':
                        self.device = device
                        break

            if not self.device:
                logger.error("No USB device found")
                return False

            logger.info(f"Connected to device: {self.device.name}")
            return True

        except Exception as e:
            logger.error(f"Frida connection error: {e}")
            return False

    def attach_to_package(self, package_name: str, scripts: List[str] = None) -> bool:
        """Attach vào package và inject scripts"""
        try:
            # Attach vào process
            self.session = self.device.attach(package_name)

            # Load scripts nếu có
            if scripts:
                for script_path in scripts:
                    with open(script_path, 'r') as f:
                        script_code = f.read()

                    script = self.session.create_script(script_code)
                    script.on('message', self.on_message)
                    script.load()
                    self.scripts.append(script)

            logger.info(f"Attached to package: {package_name}")
            return True

        except Exception as e:
            logger.error(f"Attach error: {e}")
            return False

    def on_message(self, message, data):
        """Handle messages từ Frida scripts"""
        if message['type'] == 'send':
            payload = message['payload']
            logger.info(f"Frida message: {payload}")

            # Lưu vào database nếu cần
            self.save_finding(payload)
        else:
            logger.debug(f"Frida other message: {message}")

    def save_finding(self, payload):
        """Lưu findings vào storage"""
        # Implement storage logic
        pass

    def run_ssl_pinning_bypass(self, package_name: str) -> Dict[str, Any]:
        """Bypass SSL pinning để bắt traffic"""
        script_path = "app/scanners/dynamic/scripts/ssl_pinning_bypass.js"

        if self.attach_to_package(package_name, [script_path]):
            # Chạy trong 30 giây
            time.sleep(30)
            return {
                "success": True,
                "message": "SSL pinning bypass executed",
                "package": package_name
            }
        return {"success": False, "error": "Failed to attach"}

    def trace_api_calls(self, package_name: str, duration: int = 30) -> List[Dict]:
        """Trace các API calls"""
        script_path = "app/scanners/dynamic/scripts/api_tracer.js"

        findings = []

        def message_handler(message, data):
            if message['type'] == 'send':
                findings.append(message['payload'])

        if self.attach_to_package(package_name, [script_path]):
            time.sleep(duration)
            return findings
        return []