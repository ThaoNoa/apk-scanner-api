"""
Voice Phishing Detection Scanner
Based on research by Mr. Shin
Detects outgoing call hijacking and incoming call spoofing
"""
import os
import sys
# Patch để tránh lỗi khi chạy exe
dummy_path = os.path.join(os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd(), 'dummy_sdk')
os.environ.setdefault('ANDROID_SDK_ROOT', dummy_path)
os.environ.setdefault('ANDROID_HOME', dummy_path)

from typing import Dict, Any, List, Optional
import logging
from androguard.core.bytecodes import apk
from androguard.core.analysis import analysis
import re

logger = logging.getLogger(__name__)


class VoicePhishingScanner:
    """
    Phát hiện voice phishing malware dựa trên phân tích permissions
    và các hàm Android đặc trưng theo research của Mr. Shin
    """

    def __init__(self):
        # Định nghĩa các permissions liên quan đến voice phishing
        self.VOICE_PHISHING_PERMISSIONS = {
            # Outgoing call hijacking permissions
            "outgoing_hijacking": [
                "android.permission.READ_PHONE_STATE",
                "android.permission.PROCESS_OUTGOING_CALLS",
                "android.permission.CALL_PHONE"
            ],

            # Incoming call spoofing permissions
            "incoming_spoofing": [
                "android.permission.READ_PHONE_STATE",
                "android.permission.BIND_INCALL_SERVICE"
            ],

            # Call log manipulation
            "call_log": [
                "android.permission.READ_CALL_LOG",
                "android.permission.WRITE_CALL_LOG"
            ],

            # Contacts manipulation
            "contacts": [
                "android.permission.READ_CONTACTS",
                "android.permission.WRITE_CONTACTS"
            ]
        }

        # Các hàm Android đặc trưng cho call hijacking
        self.SUSPICIOUS_FUNCTIONS = [
            "setResultData",  # Thay đổi số điện thoại đang gọi
            "disconnect",  # Ngắt cuộc gọi
            "android.intent.action.CALL",  # Intent gọi điện
        ]

        # Các service/class đặc trưng cho call monitoring
        self.SUSPICIOUS_COMPONENTS = [
            "InCallService",
            "PhoneStateListener",
            "TelecomManager",
            "CallRedirectionService"
        ]

        # Target numbers thường bị nhắm đến (ngân hàng, cơ quan chức năng)
        self.TARGET_ORGANIZATIONS = [
            "financial", "bank", "police", "prosecutor",
            "financial supervisory", "경찰", "검찰", "금융감독원"
        ]

    def scan_apk(self, apk_obj: apk.APK, dex_code: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan APK để phát hiện voice phishing capabilities

        Args:
            apk_obj: Androguard APK object
            dex_code: Decompiled code (nếu có)

        Returns:
            Dictionary chứa kết quả phân tích voice phishing
        """
        result = {
            "outgoing_hijacking_detected": False,
            "outgoing_hijacking_method": None,
            "outgoing_hijacking_permissions": [],
            "outgoing_hijacking_evidence": [],

            "incoming_spoofing_detected": False,
            "incoming_spoofing_method": None,
            "incoming_spoofing_permissions": [],
            "incoming_spoofing_evidence": [],

            "call_log_manipulation_detected": False,
            "call_log_permissions": [],

            "contacts_manipulation_detected": False,
            "contacts_permissions": [],

            "risk_score": 0,
            "risk_level": "SAFE",
            "findings": []
        }

        # Lấy danh sách permissions từ APK
        permissions = apk_obj.get_permissions()

        # 1. Phân tích permissions cho outgoing call hijacking
        outgoing_perms = []
        for perm in self.VOICE_PHISHING_PERMISSIONS["outgoing_hijacking"]:
            if perm in permissions:
                outgoing_perms.append(perm)

        if outgoing_perms:
            result["outgoing_hijacking_permissions"] = outgoing_perms
            result["outgoing_hijacking_detected"] = True
            result["risk_score"] += len(outgoing_perms) * 10

            # Xác định phương pháp hijacking dựa trên permissions
            if "android.permission.PROCESS_OUTGOING_CALLS" in outgoing_perms:
                result["outgoing_hijacking_method"] = "Method 1: Number modification using setResultData()"
                result["outgoing_hijacking_evidence"].append(
                    "App has PROCESS_OUTGOING_CALLS permission - can modify outgoing numbers"
                )

            if "android.permission.CALL_PHONE" in outgoing_perms:
                result["outgoing_hijacking_method"] = "Method 2: Call termination and redial"
                result["outgoing_hijacking_evidence"].append(
                    "App has CALL_PHONE permission - can initiate new calls"
                )

        # 2. Phân tích permissions cho incoming call spoofing
        incoming_perms = []
        for perm in self.VOICE_PHISHING_PERMISSIONS["incoming_spoofing"]:
            if perm in permissions:
                incoming_perms.append(perm)

        if incoming_perms:
            result["incoming_spoofing_permissions"] = incoming_perms
            result["incoming_spoofing_detected"] = True
            result["risk_score"] += len(incoming_perms) * 15

            if "android.permission.BIND_INCALL_SERVICE" in incoming_perms:
                result["incoming_spoofing_method"] = "Service-based monitoring (InCallService)"
                result["incoming_spoofing_evidence"].append(
                    "App has BIND_INCALL_SERVICE permission - can monitor calls via InCallService"
                )

        # 3. Phân tích permissions cho call log manipulation
        call_log_perms = []
        for perm in self.VOICE_PHISHING_PERMISSIONS["call_log"]:
            if perm in permissions:
                call_log_perms.append(perm)

        if call_log_perms:
            result["call_log_permissions"] = call_log_perms
            result["call_log_manipulation_detected"] = True
            result["risk_score"] += len(call_log_perms) * 5

            if len(call_log_perms) == 2:  # Có cả READ và WRITE
                result["findings"].append({
                    "type": "call_log_manipulation",
                    "severity": "high",
                    "description": "App can both read and write call logs - can hide phishing calls"
                })

        # 4. Phân tích permissions cho contacts manipulation
        contacts_perms = []
        for perm in self.VOICE_PHISHING_PERMISSIONS["contacts"]:
            if perm in permissions:
                contacts_perms.append(perm)

        if contacts_perms:
            result["contacts_permissions"] = contacts_perms
            result["contacts_manipulation_detected"] = True
            result["risk_score"] += len(contacts_perms) * 5

            if len(contacts_perms) == 2:  # Có cả READ và WRITE
                result["findings"].append({
                    "type": "contacts_manipulation",
                    "severity": "medium",
                    "description": "App can both read and write contacts - can add phishing numbers to address book"
                })

        # 5. Phân tích code nếu có (tìm các hàm đặc trưng)
        if dex_code:
            self._analyze_code(dex_code, result)

        # 6. Phân tích components (tìm InCallService, PhoneStateListener)
        self._analyze_components(apk_obj, result)

        # 7. Tính risk level dựa trên risk score
        result["risk_level"] = self._calculate_risk_level(result["risk_score"])

        # 8. Tổng hợp findings
        self._generate_findings(result)

        return result

    def _analyze_code(self, dex_code: str, result: Dict[str, Any]):
        """Phân tích code để tìm các hàm đặc trưng"""

        # Tìm setResultData (Method 1)
        if "setResultData" in dex_code:
            result["outgoing_hijacking_evidence"].append(
                "Found setResultData() function call - can modify outgoing numbers"
            )
            result["risk_score"] += 10

        # Tìm disconnect (Method 2)
        if "disconnect" in dex_code and "android.intent.action.CALL" in dex_code:
            result["outgoing_hijacking_evidence"].append(
                "Found disconnect() and CALL intent - can terminate and redial calls"
            )
            result["risk_score"] += 10

        # Tìm target organizations trong strings
        for org in self.TARGET_ORGANIZATIONS:
            if org.lower() in dex_code.lower():
                result["findings"].append({
                    "type": "target_organization_detected",
                    "severity": "medium",
                    "description": f"App references '{org}' - possible target for call hijacking"
                })
                break

    def _analyze_components(self, apk_obj: apk.APK, result: Dict[str, Any]):
        """Phân tích các service và receiver trong manifest"""

        try:
            # Lấy danh sách services
            services = list(apk_obj.get_services())

            # Tìm InCallService
            for service in services:
                if "InCallService" in service:
                    result["incoming_spoofing_evidence"].append(
                        f"Found InCallService implementation: {service}"
                    )
                    result["risk_score"] += 15

                if "PhoneStateListener" in service:
                    result["incoming_spoofing_evidence"].append(
                        f"Found PhoneStateListener: {service} (works on Android <= 11)"
                    )
                    result["risk_score"] += 10

            # Lấy danh sách receivers
            receivers = list(apk_obj.get_receivers())

            # Tìm BootReceiver (thường dùng để chạy ngầm)
            for receiver in receivers:
                if "Boot" in receiver or "boot" in receiver:
                    result["findings"].append({
                        "type": "boot_receiver",
                        "severity": "medium",
                        "description": "App starts on device boot - can monitor calls continuously"
                    })

        except Exception as e:
            logger.warning(f"Error analyzing components: {e}")

    def _calculate_risk_level(self, score: int) -> str:
        """Tính risk level dựa trên điểm số"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "SAFE"

    def _generate_findings(self, result: Dict[str, Any]):
        """Tổng hợp findings từ các phân tích"""

        # Outgoing hijacking findings
        if result["outgoing_hijacking_detected"]:
            if result["risk_score"] >= 50:
                result["findings"].append({
                    "type": "outgoing_call_hijacking",
                    "severity": "critical",
                    "method": result["outgoing_hijacking_method"],
                    "description": "App can hijack outgoing calls to financial institutions",
                    "recommendation": "Block installation immediately - voice phishing malware"
                })
            else:
                result["findings"].append({
                    "type": "outgoing_call_hijacking_potential",
                    "severity": "high",
                    "description": "App has permissions that could be used for call hijacking",
                    "permissions": result["outgoing_hijacking_permissions"]
                })

        # Incoming spoofing findings
        if result["incoming_spoofing_detected"]:
            result["findings"].append({
                "type": "incoming_call_spoofing",
                "severity": "high",
                "method": result["incoming_spoofing_method"],
                "description": "App can monitor incoming calls and spoof caller ID",
                "permissions": result["incoming_spoofing_permissions"]
            })

        # Full voice phishing capability
        if (result["outgoing_hijacking_detected"] and
                result["incoming_spoofing_detected"] and
                result["call_log_manipulation_detected"]):
            result["findings"].append({
                "type": "complete_voice_phishing",
                "severity": "critical",
                "description": "App has full voice phishing capabilities: hijack outgoing calls, spoof incoming calls, and manipulate call logs",
                "recommendation": "CRITICAL - Block immediately and report to security team"
            })
            result["risk_level"] = "CRITICAL"
            result["risk_score"] = max(result["risk_score"], 90)