from fastapi import APIRouter, HTTPException, UploadFile, File
from typing import List, Optional
import json
from pathlib import Path

from app.utils.metrics_calculator import metrics_calculator
from app.utils.ground_truth import ground_truth
from app.scanners.combined_scanner import CombinedScanner

router = APIRouter(prefix="/evaluate", tags=["evaluation"])


@router.post("/batch")
async def evaluate_batch(
        ground_truth_file: UploadFile = File(...),
        scan_results_file: Optional[UploadFile] = None
):
    """
    Đánh giá F1 score dựa trên ground truth file

    Ground truth file format (JSON):
    [
        {
            "filename": "app1.apk",
            "is_malicious": true,
            "malware_family": "Joker",
            "source": "virustotal"
        }
    ]
    """

    # Reset metrics
    metrics_calculator.reset()

    # Load ground truth
    content = await ground_truth_file.read()
    truth_data = json.loads(content)

    for item in truth_data:
        ground_truth.add_ground_truth(
            item['filename'],
            item['is_malicious'],
            item.get('malware_family'),
            item.get('source', 'uploaded')
        )

    # Nếu có scan results, dùng luôn
    if scan_results_file:
        results_content = await scan_results_file.read()
        scan_results = json.loads(results_content)

        for result in scan_results['results']:
            actual = ground_truth.is_malicious(result['filename'])
            if actual is not None:
                metrics_calculator.add_prediction(
                    filename=result['filename'],
                    actual_label="malicious" if actual else "normal",
                    predicted_label="malicious" if result['is_malicious'] else "normal",
                    predicted_risk=result['risk_level'],
                    risk_score=result['risk_score'],
                    scanner_used=next((s for s, v in result['scanners'].items() if v), 'unknown'),
                    ground_truth=ground_truth.get_truth(result['filename'])['source']
                )

    return metrics_calculator.get_summary()


@router.get("/metrics")
async def get_metrics():
    """Lấy metrics hiện tại"""
    return metrics_calculator.get_summary()


@router.post("/reset")
async def reset_metrics():
    """Reset tất cả metrics"""
    metrics_calculator.reset()
    return {"message": "Metrics reset successfully"}


@router.post("/add-prediction")
async def add_prediction(
        filename: str,
        actual_label: str,
        predicted_label: str,
        predicted_risk: str,
        risk_score: float,
        scanner_used: str = "combined"
):
    """Thêm một prediction manual"""
    metrics_calculator.add_prediction(
        filename=filename,
        actual_label=actual_label,
        predicted_label=predicted_label,
        predicted_risk=predicted_risk,
        risk_score=risk_score,
        scanner_used=scanner_used,
        ground_truth="manual"
    )
    return {"message": "Prediction added"}


@router.get("/confusion-matrix")
async def get_confusion_matrix():
    """Lấy confusion matrix dạng HTML"""
    return {
        "html": metrics_calculator.get_confusion_matrix_html(),
        "data": {
            "tp": metrics_calculator.tp,
            "fp": metrics_calculator.fp,
            "fn": metrics_calculator.fn,
            "tn": metrics_calculator.tn
        }
    }


@router.get("/threshold-analysis")
async def analyze_threshold(thresholds: Optional[str] = None):
    """Phân tích F1 score ở các threshold khác nhau"""
    threshold_list = [float(t) for t in thresholds.split(',')] if thresholds else None

    # Lấy predictions từ metrics
    predictions = metrics_calculator.predictions

    if not predictions:
        raise HTTPException(404, "No predictions available")

    analysis = metrics_calculator.evaluate_threshold(predictions, threshold_list)

    # Tìm threshold tối ưu
    optimal = analysis['optimal_threshold']
    f1_at_optimal = analysis['optimal_f1']

    return {
        "analysis": analysis['threshold_analysis'],
        "optimal_threshold": optimal,
        "optimal_f1_score": f1_at_optimal,
        "recommendation": f"Use threshold {optimal} for best F1 score ({f1_at_optimal})"
    }