from __future__ import annotations
from typing import Dict, Any, List, Optional
import hashlib
import time
import logging
from pathlib import Path
import asyncio

from .androguard_scanner import AndroguardScanner
from .mobsf_scanner import MOBSFScanner

logger = logging.getLogger(__name__)


class CombinedScanner:
    def __init__(self, use_mobsf: bool = True):
        self.androguard_scanner = AndroguardScanner()
        self.mobsf_scanner = MOBSFScanner() if use_mobsf else None

    def calculate_risk_score(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Tính điểm nguy hiểm kết hợp cả static analysis và voice phishing detection
        """
        risk_score = 0
        confidence = 0
        detection_methods = []

        # 1. PHÂN TÍCH PERMISSIONS (0-30 điểm)
        androguard = results.get("androguard", {})
        dangerous_perms = androguard.get("dangerous_permissions", [])

        # Danh sách permissions cực kỳ nguy hiểm
        critical_perms = [
            "android.permission.INSTALL_PACKAGES",
            "android.permission.DELETE_PACKAGES",
            "android.permission.ACCESS_SUPERUSER",
            "android.permission.FACTORY_TEST"
        ]

        # Danh sách permissions nguy hiểm cao
        high_risk_perms = [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION"
        ]

        perm_score = 0
        for perm in dangerous_perms:
            if perm in critical_perms:
                perm_score += 10
                detection_methods.append(f"Critical permission: {perm}")
            elif perm in high_risk_perms:
                perm_score += 5
                detection_methods.append(f"High-risk permission: {perm}")
            else:
                perm_score += 2

        risk_score += min(perm_score, 30)

        # 2. VOICE PHISHING ANALYSIS (0-40 điểm) - Dựa trên research của Mr. Shin
        voice_phishing = androguard.get("voice_phishing", {})
        if voice_phishing:
            voice_score = voice_phishing.get("risk_score", 0)
            risk_score += min(voice_score, 40)

            # Thêm detection methods từ voice phishing
            if voice_phishing.get("outgoing_hijacking_detected"):
                detection_methods.append(
                    f"Outgoing call hijacking detected: {voice_phishing.get('outgoing_hijacking_method', 'Unknown method')}"
                )

            if voice_phishing.get("incoming_spoofing_detected"):
                detection_methods.append(
                    f"Incoming call spoofing detected: {voice_phishing.get('incoming_spoofing_method', 'Unknown method')}"
                )

            if voice_phishing.get("call_log_manipulation_detected"):
                detection_methods.append("Call log manipulation detected - can hide phishing calls")

            if voice_phishing.get("contacts_manipulation_detected"):
                detection_methods.append("Contacts manipulation detected - can add phishing numbers")

        # 3. PHÂN TÍCH COMPONENTS (0-15 điểm)
        activities = androguard.get("activities", [])
        services = androguard.get("services", [])
        receivers = androguard.get("receivers", [])

        if len(activities) > 100:
            risk_score += 5
            detection_methods.append(f"Abnormal number of activities: {len(activities)}")

        if len(services) > 50:
            risk_score += 5
            detection_methods.append(f"Abnormal number of services: {len(services)}")

        if len(receivers) > 50:
            risk_score += 5
            detection_methods.append(f"Abnormal number of receivers: {len(receivers)}")

        # 4. PHÂN TÍCH FINDINGS TỪ ANDROGUARD (0-15 điểm)
        findings = androguard.get("findings", [])
        for finding in findings:
            severity = finding.get("severity", "low")
            if severity == "critical":
                risk_score += 15
                detection_methods.append(f"Critical finding: {finding.get('description', '')}")
            elif severity == "high":
                risk_score += 10
                detection_methods.append(f"High-risk finding: {finding.get('description', '')}")
            elif severity == "medium":
                risk_score += 5

        # Giới hạn risk_score trong khoảng 0-100
        risk_score = min(max(risk_score, 0), 100)

        # Tính confidence dựa trên số lượng phương pháp phát hiện
        unique_methods = len(set(detection_methods))
        confidence = min(unique_methods * 10, 95)

        # Xác định risk level
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 50:
            risk_level = "HIGH"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
        elif risk_score >= 10:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "detection_methods": list(set(detection_methods))
        }

    async def scan_single_apk(self, file_path: str | Path, options: Dict[str, bool]) -> Dict[str, Any]:
        """Scan a single APK file với voice phishing detection"""
        start_time = time.perf_counter()
        file_path = Path(file_path)

        result = {
            "filename": file_path.name,
            "start_time": time.time(),
            "androguard": {},
            "mobsf": {},
            "warnings": [],
            "errors": []
        }

        # Calculate file hash
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            result["file_hash"] = file_hash
        except Exception as e:
            result["errors"].append(f"Error calculating hash: {e!s}")

        # Androguard scan (bao gồm voice phishing detection)
        if options.get("scan_androguard", True):
            try:
                logger.info(f"Starting Androguard scan for {file_path.name}")
                scan_start = time.perf_counter()
                androguard_results = self.androguard_scanner.scan_apk(str(file_path))
                result["androguard"] = androguard_results
                result["androguard_duration"] = time.perf_counter() - scan_start

                # Log voice phishing results nếu có
                if androguard_results.get("voice_phishing"):
                    vp = androguard_results["voice_phishing"]
                    if vp.get("outgoing_hijacking_detected") or vp.get("incoming_spoofing_detected"):
                        logger.warning(f"Voice phishing detected in {file_path.name}")
                        result["warnings"].append(
                            f"Voice phishing capabilities detected - Risk: {vp.get('risk_level', 'UNKNOWN')}"
                        )

            except Exception as e:
                error_msg = f"Androguard scan error: {e!s}"
                logger.error(error_msg)
                result["errors"].append(error_msg)

        # MOBSF scan (giữ nguyên)
        if options.get("scan_mobsf", True) and self.mobsf_scanner:
            try:
                logger.info(f"Starting MOBSF scan for {file_path.name}")
                scan_start = time.perf_counter()
                mobsf_results = await self.mobsf_scanner.scan_apk(str(file_path))
                result["mobsf"] = mobsf_results
                result["mobsf_duration"] = time.perf_counter() - scan_start
            except Exception as e:
                error_msg = f"MOBSF scan error: {e!s}"
                logger.error(error_msg)
                result["errors"].append(error_msg)

        # Calculate risk score
        risk_analysis = self.calculate_risk_score(result)
        result.update(risk_analysis)

        # Xác định is_malicious
        result["is_malicious"] = (
                risk_analysis["risk_score"] >= 50 or
                len(result.get("androguard", {}).get("dangerous_permissions", [])) >= 3 or
                "Critical finding" in str(risk_analysis["detection_methods"])
        )

        result["scan_duration"] = time.perf_counter() - start_time

        return result

    async def scan_multiple_apks(self, file_paths: List[str | Path], options: Dict[str, bool]) -> List[Dict[str, Any]]:
        """Scan multiple APK files concurrently"""
        tasks = []
        for file_path in file_paths:
            logger.info(f"Queueing scan for {file_path}")
            tasks.append(self.scan_single_apk(file_path, options))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Scan error for {file_paths[i]}: {result}")
                processed_results.append({
                    "filename": str(file_paths[i]),
                    "error": str(result),
                    "is_malicious": False,
                    "risk_level": "ERROR",
                    "risk_score": 0,
                    "confidence": 0,
                    "detection_methods": [],
                    "scan_duration": 0,
                    "warnings": [],
                    "errors": [str(result)]
                })
            else:
                processed_results.append(result)

        return processed_results