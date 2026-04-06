import requests
import json
import time
import logging
from typing import Dict, Any, Optional
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MOBSFScanner:
    def __init__(self, mobsf_url: str = "http://localhost:8000", api_key: str = None):
        self.mobsf_url = mobsf_url.rstrip('/')
        self.api_key = api_key or os.getenv("MOBSF_API_KEY", "")
        self.headers = {
            "Authorization": self.api_key
        }

    def upload_file(self, file_path: str) -> Optional[str]:
        """Upload APK to MOBSF"""
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
                response = requests.post(
                    f"{self.mobsf_url}/api/v1/upload",
                    files=files,
                    headers=self.headers
                )

            if response.status_code == 200:
                result = response.json()
                return result.get('hash')
            else:
                logger.error(f"MOBSF upload failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error uploading to MOBSF: {e}")
            return None

    def scan_file(self, file_hash: str, scan_type: str = "apk") -> Optional[Dict[str, Any]]:
        """Trigger scan on MOBSF"""
        try:
            data = {
                'hash': file_hash,
                'scan_type': scan_type
            }

            response = requests.post(
                f"{self.mobsf_url}/api/v1/scan",
                data=data,
                headers=self.headers
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"MOBSF scan failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error scanning with MOBSF: {e}")
            return None

    def get_report(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Get scan report from MOBSF"""
        try:
            data = {'hash': file_hash}
            response = requests.post(
                f"{self.mobsf_url}/api/v1/report_json",
                data=data,
                headers=self.headers
            )

            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"MOBSF report failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error getting MOBSF report: {e}")
            return None

    def scan_apk(self, file_path: str) -> Dict[str, Any]:
        """Complete MOBSF scan workflow"""
        result = {}

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
                # Extract relevant information
                result["scan_result"] = {
                    "app_name": report.get("app_name", ""),
                    "package_name": report.get("package_name", ""),
                    "version": report.get("version", ""),
                    "permissions": report.get("permissions", []),
                    "malware_family": report.get("malware_family", ""),
                    "threat_level": report.get("threat_level", ""),
                    "average_cvss": report.get("average_cvss", 0),
                    "security_score": report.get("security_score", 0),
                    "manifest_analysis": report.get("manifest_analysis", {}),
                    "code_analysis": report.get("code_analysis", {}),
                    "urls": report.get("urls", []),
                    "domains": report.get("domains", []),
                    "emails": report.get("emails", [])
                }
            else:
                result["error"] = "Failed to get MOBSF report"

        except Exception as e:
            logger.error(f"Error in MOBSF scan workflow: {e}")
            result["error"] = str(e)

        return result