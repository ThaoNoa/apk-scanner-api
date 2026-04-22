import os
import requests
import json
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class MOBSFScanner:
    def __init__(self, mobsf_url: str = None, api_key: str = None):
        # Cho phép tùy chỉnh URL qua environment variable
        self.mobsf_url = mobsf_url or os.getenv("MOBSF_URL", "http://localhost:8000")
        self.mobsf_url = self.mobsf_url.rstrip('/')

        # Lấy API key từ nhiều nguồn (ưu tiên: tham số > env > file config)
        self.api_key = api_key or os.getenv("MOBSF_API_KEY")

        # Nếu vẫn chưa có, thử đọc từ file config
        if not self.api_key:
            self.api_key = self._load_api_key_from_config()

        if not self.api_key:
            logger.warning("MOBSF_API_KEY not found. Please set it via environment variable or config file.")

        self.headers = {
            "Authorization": self.api_key
        } if self.api_key else {}

        logger.info(
            f"MOBSF Scanner initialized. URL: {self.mobsf_url}, API Key: {'Set' if self.api_key else 'Not set'}")

    def _load_api_key_from_config(self) -> Optional[str]:
        """Đọc API key từ file config.json"""
        config_paths = [
            "config.json",
            os.path.expanduser("~/.mobsf/config.json"),
            os.path.join(os.path.dirname(__file__), "../../config.json")
        ]

        for config_path in config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        config = json.load(f)
                        if "mobsf_api_key" in config:
                            logger.info(f"Loaded API key from {config_path}")
                            return config["mobsf_api_key"]
                        if "mobsf" in config and "api_key" in config["mobsf"]:
                            logger.info(f"Loaded API key from {config_path}")
                            return config["mobsf"]["api_key"]
                except Exception as e:
                    logger.warning(f"Error reading {config_path}: {e}")

        return None

    def check_connection(self) -> bool:
        """Kiểm tra kết nối đến MOBSF server"""
        if not self.api_key:
            logger.error("Cannot check connection: No API key configured")
            return False

        try:
            response = requests.get(
                f"{self.mobsf_url}/api/v1/version",
                headers=self.headers,
                timeout=10
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            return False

    def upload_file(self, file_path: str) -> Optional[str]:
        """Upload APK to MOBSF"""
        if not self.api_key:
            logger.error("Cannot upload: No API key configured")
            return None

        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
                response = requests.post(
                    f"{self.mobsf_url}/api/v1/upload",
                    files=files,
                    headers=self.headers,
                    timeout=60
                )

            if response.status_code == 200:
                result = response.json()
                return result.get('hash')
            else:
                logger.error(f"MOBSF upload failed: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"Error uploading to MOBSF: {e}")
            return None

    def scan_file(self, file_hash: str, scan_type: str = "apk") -> Optional[Dict[str, Any]]:
        """Trigger scan on MOBSF"""
        if not self.api_key:
            logger.error("Cannot scan: No API key configured")
            return None

        try:
            data = {
                'hash': file_hash,
                'scan_type': scan_type
            }

            response = requests.post(
                f"{self.mobsf_url}/api/v1/scan",
                data=data,
                headers=self.headers,
                timeout=300
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"MOBSF scan failed: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"Error scanning with MOBSF: {e}")
            return None

    def get_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get scan report from MOBSF"""
        if not self.api_key:
            logger.error("Cannot get report: No API key configured")
            return None

        try:
            data = {'hash': file_hash}
            response = requests.post(
                f"{self.mobsf_url}/api/v1/report_json",
                data=data,
                headers=self.headers,
                timeout=60
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"MOBSF report failed: {response.status_code} - {response.text}")
                return None

        except Exception as e:
            logger.error(f"Error getting MOBSF report: {e}")
            return None

    def scan_apk(self, file_path: str) -> Dict[str, Any]:
        """Complete MOBSF scan workflow"""
        result = {
            "enabled": bool(self.api_key),
            "connected": False,
            "file_hash": None,
            "scan_result": {},
            "error": None
        }

        if not self.api_key:
            result["error"] = "MOBSF_API_KEY not configured. Set environment variable or add to config.json"
            return result

        # Check connection first
        if not self.check_connection():
            result["error"] = f"Cannot connect to MOBSF at {self.mobsf_url}. Make sure Docker is running."
            return result

        result["connected"] = True

        try:
            # Upload file
            file_hash = self.upload_file(file_path)
            if not file_hash:
                result["error"] = "Failed to upload to MOBSF"
                return result

            result["file_hash"] = file_hash

            # Trigger scan
            scan_result = self.scan_file(file_hash)
            if not scan_result:
                result["error"] = "Failed to trigger MOBSF scan"
                return result

            # Wait for scan to complete
            time.sleep(5)

            # Get report
            report = self.get_report(file_hash)
            if report:
                result["scan_result"] = {
                    "app_name": report.get("app_name", ""),
                    "package_name": report.get("package_name", ""),
                    "version": report.get("version", ""),
                    "permissions": report.get("permissions", []),
                    "malware_family": report.get("malware_family", ""),
                    "threat_level": report.get("threat_level", ""),
                    "security_score": report.get("security_score", 0),
                }
            else:
                result["error"] = "Failed to get MOBSF report"

        except Exception as e:
            logger.error(f"Error in MOBSF scan workflow: {e}")
            result["error"] = str(e)

        return result