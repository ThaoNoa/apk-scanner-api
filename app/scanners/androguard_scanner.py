# app/scanners/androguard_scanner.py
import os
import sys
import logging
import hashlib
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# IMPORTANT: Patch SDK trước khi import androguard
import app.sdk_patch

app.sdk_patch.setup_android_sdk()

# Now safe to import androguard
from androguard.core.bytecodes import apk, dvm
from androguard.core.analysis import analysis

from .voice_phishing_scanner import VoicePhishingScanner


class AndroguardScanner:
    def __init__(self):
        self.results = {}
        self.voice_phishing_scanner = VoicePhishingScanner()

    def scan_apk(self, file_path: str) -> Dict[str, Any]:
        """Scan APK file using Androguard"""
        results = {
            "permissions": [],
            "dangerous_permissions": [],
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "certificates": {},
            "findings": [],
            "package_name": "",
            "version_name": "",
            "version_code": "",
            "min_sdk": "",
            "target_sdk": "",
            "voice_phishing": None,
            "warning": None
        }

        try:
            print(f"Loading APK: {file_path}")
            a = apk.APK(file_path)

            # Basic app info
            results["package_name"] = a.get_package()
            results["version_name"] = a.get_androidversion_name()
            results["version_code"] = a.get_androidversion_code()
            results["min_sdk"] = a.get_min_sdk_version()
            results["target_sdk"] = a.get_target_sdk_version()

            # Get permissions
            results["permissions"] = a.get_permissions()

            # Identify dangerous permissions
            dangerous_perms = [
                "android.permission.READ_SMS",
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION",
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS",
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG",
                "android.permission.READ_PHONE_STATE",
                "android.permission.PROCESS_OUTGOING_CALLS",
                "android.permission.CALL_PHONE",
                "android.permission.BIND_INCALL_SERVICE"
            ]

            dangerous_found = []
            for perm in dangerous_perms:
                if perm in results["permissions"]:
                    dangerous_found.append(perm)
                    results["findings"].append({
                        "type": "dangerous_permission",
                        "permission": perm,
                        "severity": "high",
                        "description": f"App requests dangerous permission: {perm}"
                    })

            results["dangerous_permissions"] = dangerous_found

            # Get components
            results["activities"] = list(a.get_activities())
            results["services"] = list(a.get_services())
            results["receivers"] = list(a.get_receivers())
            results["providers"] = list(a.get_providers())

            # Get certificate info
            try:
                certs = a.get_certificates()
                for i, cert in enumerate(certs):
                    try:
                        cert_info = {
                            "issuer": str(cert.issuer),
                            "subject": str(cert.subject),
                            "serial_number": str(cert.serial_number),
                            "not_before": str(cert.not_valid_before),
                            "not_after": str(cert.not_valid_after),
                            "signature_algorithm": cert.signature_algorithm,
                            "fingerprint": hashlib.sha256(cert.public_bytes()).hexdigest()
                        }
                        results["certificates"][f"cert_{i}"] = cert_info
                    except Exception as e:
                        logger.warning(f"Error extracting certificate {i}: {e}")
            except Exception as e:
                logger.warning(f"Error getting certificates: {e}")

            # Voice Phishing Analysis
            try:
                dex_files = a.get_all_dex()
                dex_code = None
                if dex_files:
                    try:
                        d = dvm.DalvikVMFormat(dex_files[0])
                        dex_code = str(d.get_classes())
                    except Exception as e:
                        logger.warning(f"Error parsing dex: {e}")

                voice_phishing_results = self.voice_phishing_scanner.scan_apk(a, dex_code)
                results["voice_phishing"] = voice_phishing_results

                if voice_phishing_results.get("findings"):
                    results["findings"].extend(voice_phishing_results["findings"])

            except Exception as e:
                logger.error(f"Error in voice phishing analysis: {e}")
                results["voice_phishing"] = {"error": str(e)}

            print(f"Scan completed for {file_path}")

        except Exception as e:
            logger.error(f"Error in Androguard scan: {e}")
            results["error"] = str(e)

        return results