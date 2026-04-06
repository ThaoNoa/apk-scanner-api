from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime


class APKScanRequest(BaseModel):
    files: List[str]
    deep_scan: bool = False
    scan_mobsf: bool = True
    scan_androguard: bool = True


class VoicePhishingAnalysis(BaseModel):
    """Kết quả phân tích voice phishing từ research của Mr. Shin"""
    outgoing_hijacking_detected: bool = False
    outgoing_hijacking_method: Optional[str] = None
    outgoing_hijacking_permissions: List[str] = []
    outgoing_hijacking_evidence: List[str] = []

    incoming_spoofing_detected: bool = False
    incoming_spoofing_method: Optional[str] = None
    incoming_spoofing_permissions: List[str] = []
    incoming_spoofing_evidence: List[str] = []

    call_log_manipulation_detected: bool = False
    call_log_permissions: List[str] = []

    contacts_manipulation_detected: bool = False
    contacts_permissions: List[str] = []

    risk_score: int = 0
    risk_level: str = "SAFE"

class ScanResult(BaseModel):
    filename: str
    scan_id: str
    timestamp: datetime
    scan_duration: float  # Thời gian phân tích file này (giây)
    is_malicious: bool
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: float  # Điểm số nguy hiểm (0-100)
    confidence: float  # Độ tin cậy của kết luận (0-100%)
    scanners: Dict[str, bool]
    permissions: List[str]
    dangerous_permissions: List[str]
    activities: List[str]
    services: List[str]
    receivers: List[str]
    providers: List[str]
    certificates: Dict[str, Any]
    mobsf_results: Optional[Dict[str, Any]]
    androguard_results: Optional[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    detection_methods: List[str]  # Các phương pháp phát hiện malware
    warnings: List[str]
    errors: List[str]

    # Thêm trường mới cho voice phishing analysis
    voice_phishing_analysis: Optional[VoicePhishingAnalysis] = None

class BatchScanResponse(BaseModel):
    batch_id: str
    total_files: int
    total_duration: float
    results: List[ScanResult]
    summary: Dict[str, Any]