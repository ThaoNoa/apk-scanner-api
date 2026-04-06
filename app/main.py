from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from typing import List
import time
import uuid
from datetime import datetime
import logging
from pathlib import Path
from app.routers import large_scale_test

from app.models.scan_models import BatchScanResponse, ScanResult, VoicePhishingAnalysis
from app.scanners.combined_scanner import CombinedScanner
from app.utils.file_handler import FileHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="APK Malware Scanner API with Voice Phishing Detection",
    description="API for scanning APK files using Androguard, MOBSF, and Voice Phishing Detection (based on Mr. Shin's research)",
    version="2.0.0"
)
app.include_router(large_scale_test.router)

# Initialize components
file_handler = FileHandler(upload_dir=Path("uploads"))
scanner = CombinedScanner(use_mobsf=False)

# Store scan results
scan_results: dict[str, BatchScanResponse] = {}


@app.post("/scan/apks", response_model=BatchScanResponse)
async def scan_apks(
        background_tasks: BackgroundTasks,
        files: List[UploadFile] = File(...),
        scan_mobsf: bool = False,
        scan_androguard: bool = True
):
    """
    Upload and scan multiple APK files
    Includes Voice Phishing Detection based on Mr. Shin's research
    """
    batch_start_time = time.perf_counter()
    batch_id = uuid.uuid4().hex

    # Validate files
    for file in files:
        if not file.filename or not file.filename.endswith('.apk'):
            raise HTTPException(
                status_code=400,
                detail=f"File {file.filename} is not an APK file"
            )

    file_paths = []
    try:
        # Save uploaded files
        file_paths = await file_handler.save_multiple_files(files)

        # Configure scan options
        scan_options = {
            "scan_mobsf": scan_mobsf,
            "scan_androguard": scan_androguard
        }

        # Perform scans concurrently
        scan_results_list = await scanner.scan_multiple_apks(file_paths, scan_options)

        # Process results
        results = []
        total_duration = 0
        risk_counts = {"SAFE": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0, "ERROR": 0}
        voice_phishing_count = 0

        for scan_result in scan_results_list:
            if "error" in scan_result:
                # Xử lý lỗi (giữ nguyên)
                pass
            else:
                androguard = scan_result.get("androguard", {})
                mobsf = scan_result.get("mobsf", {})

                scan_duration = scan_result.get("scan_duration", 0)
                total_duration += scan_duration

                # Xử lý voice phishing results
                voice_phishing_data = androguard.get("voice_phishing", {})
                voice_phishing_analysis = None

                if voice_phishing_data and not voice_phishing_data.get("error"):
                    voice_phishing_analysis = VoicePhishingAnalysis(
                        outgoing_hijacking_detected=voice_phishing_data.get("outgoing_hijacking_detected", False),
                        outgoing_hijacking_method=voice_phishing_data.get("outgoing_hijacking_method"),
                        outgoing_hijacking_permissions=voice_phishing_data.get("outgoing_hijacking_permissions", []),
                        outgoing_hijacking_evidence=voice_phishing_data.get("outgoing_hijacking_evidence", []),

                        incoming_spoofing_detected=voice_phishing_data.get("incoming_spoofing_detected", False),
                        incoming_spoofing_method=voice_phishing_data.get("incoming_spoofing_method"),
                        incoming_spoofing_permissions=voice_phishing_data.get("incoming_spoofing_permissions", []),
                        incoming_spoofing_evidence=voice_phishing_data.get("incoming_spoofing_evidence", []),

                        call_log_manipulation_detected=voice_phishing_data.get("call_log_manipulation_detected", False),
                        call_log_permissions=voice_phishing_data.get("call_log_permissions", []),

                        contacts_manipulation_detected=voice_phishing_data.get("contacts_manipulation_detected", False),
                        contacts_permissions=voice_phishing_data.get("contacts_permissions", []),

                        risk_score=voice_phishing_data.get("risk_score", 0),
                        risk_level=voice_phishing_data.get("risk_level", "SAFE")
                    )

                    if (voice_phishing_data.get("outgoing_hijacking_detected") or
                            voice_phishing_data.get("incoming_spoofing_detected")):
                        voice_phishing_count += 1

                result = ScanResult(
                    filename=scan_result["filename"],
                    scan_id=uuid.uuid4().hex,
                    timestamp=datetime.now(),
                    scan_duration=scan_duration,
                    is_malicious=scan_result["is_malicious"],
                    risk_level=scan_result["risk_level"],
                    risk_score=scan_result["risk_score"],
                    confidence=scan_result["confidence"],
                    scanners={
                        "androguard": bool(androguard),
                        "mobsf": bool(mobsf)
                    },
                    permissions=androguard.get("permissions", []),
                    dangerous_permissions=androguard.get("dangerous_permissions", []),
                    activities=androguard.get("activities", []),
                    services=androguard.get("services", []),
                    receivers=androguard.get("receivers", []),
                    providers=androguard.get("providers", []),
                    certificates=androguard.get("certificates", {}),
                    mobsf_results=mobsf,
                    androguard_results=androguard,
                    findings=androguard.get("findings", []),
                    detection_methods=scan_result.get("detection_methods", []),
                    warnings=scan_result.get("warnings", []),
                    errors=scan_result.get("errors", []),
                    voice_phishing_analysis=voice_phishing_analysis
                )
                risk_counts[result.risk_level] = risk_counts.get(result.risk_level, 0) + 1

            results.append(result)

        # Calculate batch duration
        batch_duration = time.perf_counter() - batch_start_time

        # Create response
        response = BatchScanResponse(
            batch_id=batch_id,
            total_files=len(files),
            total_duration=batch_duration,
            results=results,
            summary={
                "total_malicious": sum(1 for r in results if r.is_malicious),
                "total_clean": sum(
                    1 for r in results if not r.is_malicious and r.risk_level not in ["ERROR", "UNKNOWN"]),
                "total_error": risk_counts["ERROR"],
                "by_risk_level": risk_counts,
                "voice_phishing_detected": voice_phishing_count,
                "average_risk_score": sum(r.risk_score for r in results if r.risk_level != "ERROR") / max(
                    len([r for r in results if r.risk_level != "ERROR"]), 1),
                "average_confidence": sum(r.confidence for r in results if r.risk_level != "ERROR") / max(
                    len([r for r in results if r.risk_level != "ERROR"]), 1),
                "average_scan_time": total_duration / len(results) if results else 0,
                "scanners_used": {
                    "androguard": scan_androguard,
                    "mobsf": scan_mobsf,
                    "voice_phishing": True  # Luôn bật vì tích hợp trong Androguard
                }
            }
        )

        # Store results
        scan_results[batch_id] = response

        # Cleanup files in background
        background_tasks.add_task(file_handler.cleanup_multiple_files, file_paths)

        logger.info(
            f"Batch {batch_id} completed: {len(results)} files scanned, "
            f"{voice_phishing_count} voice phishing apps detected"
        )
        return response

    except Exception as e:
        logger.error(f"Error in scan_apks: {e}")
        if file_paths:
            await file_handler.cleanup_multiple_files(file_paths)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/")
async def root():
    return {
        "name": "APK Malware Scanner API",
        "version": "2.0.0",
        "features": [
            "Static Analysis (Androguard)",
            "MOBSF Integration",
            "Voice Phishing Detection (based on Mr. Shin's research)"
        ],
        "endpoints": {
            "GET /": "This info",
            "GET /health": "Health check",
            "POST /scan/apks": "Upload and scan APK files",
            "GET /scan/result/{batch_id}": "Get scan results"
        }
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "scanners": {
            "androguard": True,
            "mobsf": False,
            "voice_phishing": True
        },
        "version": "2.0.0"
    }


@app.get("/scan/result/{batch_id}")
async def get_scan_result(batch_id: str):
    if batch_id in scan_results:
        return scan_results[batch_id]
    else:
        raise HTTPException(status_code=404, detail="Batch ID not found")