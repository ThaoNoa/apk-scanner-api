"""
Large Scale F1 Score Testing Module
For evaluating scanner with 10,000+ normal and 10,000+ malicious APKs
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any, List, Optional
from pathlib import Path
import asyncio
import json
import time
import logging
from datetime import datetime
import hashlib

from app.scanners.combined_scanner import CombinedScanner
from app.scanners.androguard_scanner import AndroguardScanner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/evaluate", tags=["evaluation"])

# Global storage for evaluation results
evaluation_results = {
    "current_batch": None,
    "history": []
}


class LargeScaleTester:
    """
    Large scale tester for F1 Score evaluation
    """

    def __init__(self):
        self.scanner = CombinedScanner(use_mobsf=False)
        self.results = {
            "tp": 0,  # True Positive
            "fp": 0,  # False Positive
            "fn": 0,  # False Negative
            "tn": 0,  # True Negative
            "total_normal": 0,
            "total_malicious": 0,
            "details": []
        }

    async def test_single_file(self, file_path: Path, expected_is_malicious: bool) -> Dict[str, Any]:
        """Test a single file and return result"""
        try:
            scan_result = await self.scanner.scan_single_apk(file_path, {
                "scan_mobsf": False,
                "scan_androguard": True
            })

            predicted = scan_result["is_malicious"]
            is_correct = (predicted == expected_is_malicious)

            # Determine classification type
            if expected_is_malicious and predicted:
                classification = "TP"
            elif not expected_is_malicious and predicted:
                classification = "FP"
            elif expected_is_malicious and not predicted:
                classification = "FN"
            else:
                classification = "TN"

            return {
                "filename": file_path.name,
                "expected": "malicious" if expected_is_malicious else "normal",
                "predicted": "malicious" if predicted else "normal",
                "is_correct": is_correct,
                "classification": classification,
                "risk_score": scan_result.get("risk_score", 0),
                "risk_level": scan_result.get("risk_level", "UNKNOWN"),
                "voice_phishing": scan_result.get("androguard", {}).get("voice_phishing", {}),
                "error": None
            }
        except Exception as e:
            logger.error(f"Error testing {file_path}: {e}")
            return {
                "filename": file_path.name,
                "expected": "malicious" if expected_is_malicious else "normal",
                "predicted": "error",
                "is_correct": False,
                "classification": "ERROR",
                "error": str(e)
            }

    async def test_normal_files(self, normal_dir: str, limit: int = 10000) -> List[Dict]:
        """Test all normal APK files in directory"""
        normal_path = Path(normal_dir)
        if not normal_path.exists():
            raise FileNotFoundError(f"Directory not found: {normal_dir}")

        apk_files = list(normal_path.glob("*.apk"))[:limit]
        self.results["total_normal"] = len(apk_files)

        logger.info(f"Testing {len(apk_files)} normal APK files...")

        results = []
        for i, file in enumerate(apk_files):
            if i % 100 == 0:
                logger.info(f"Progress: {i}/{len(apk_files)} normal files")

            result = await self.test_single_file(file, expected_is_malicious=False)
            results.append(result)

            # Update counters
            if result["classification"] == "FP":
                self.results["fp"] += 1
            elif result["classification"] == "TN":
                self.results["tn"] += 1

        return results

    async def test_malicious_files(self, malicious_dir: str, limit: int = 10000) -> List[Dict]:
        """Test all malicious APK files in directory"""
        malicious_path = Path(malicious_dir)
        if not malicious_path.exists():
            raise FileNotFoundError(f"Directory not found: {malicious_dir}")

        apk_files = list(malicious_path.glob("*.apk"))[:limit]
        self.results["total_malicious"] = len(apk_files)

        logger.info(f"Testing {len(apk_files)} malicious APK files...")

        results = []
        for i, file in enumerate(apk_files):
            if i % 100 == 0:
                logger.info(f"Progress: {i}/{len(apk_files)} malicious files")

            result = await self.test_single_file(file, expected_is_malicious=True)
            results.append(result)

            # Update counters
            if result["classification"] == "TP":
                self.results["tp"] += 1
            elif result["classification"] == "FN":
                self.results["fn"] += 1

        return results

    def calculate_metrics(self) -> Dict[str, Any]:
        """Calculate all metrics from results"""
        tp = self.results["tp"]
        fp = self.results["fp"]
        fn = self.results["fn"]
        tn = self.results["tn"]

        total = tp + fp + fn + tn

        # Calculate metrics
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
        accuracy = (tp + tn) / total if total > 0 else 0

        return {
            "confusion_matrix": {
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "true_negatives": tn,
                "total": total
            },
            "metrics": {
                "precision": round(precision * 100, 2),
                "recall": round(recall * 100, 2),
                "f1_score": round(f1 * 100, 2),
                "false_positive_rate": round(fpr * 100, 2),
                "false_negative_rate": round(fnr * 100, 2),
                "accuracy": round(accuracy * 100, 2)
            },
            "dataset_summary": {
                "normal_files": self.results["total_normal"],
                "malicious_files": self.results["total_malicious"],
                "total_files": self.results["total_normal"] + self.results["total_malicious"],
                "files_processed": total,
                "files_with_errors": len([r for r in self.results["details"] if r.get("classification") == "ERROR"])
            }
        }

    async def run_full_test(self, normal_dir: str, malicious_dir: str, limit: int = 10000) -> Dict[str, Any]:
        """Run full test on both normal and malicious datasets"""
        start_time = time.time()

        # Reset results
        self.results = {
            "tp": 0, "fp": 0, "fn": 0, "tn": 0,
            "total_normal": 0, "total_malicious": 0,
            "details": []
        }

        # Test normal files
        logger.info("Starting normal files test...")
        normal_results = await self.test_normal_files(normal_dir, limit)
        self.results["details"].extend(normal_results)

        # Test malicious files
        logger.info("Starting malicious files test...")
        malicious_results = await self.test_malicious_files(malicious_dir, limit)
        self.results["details"].extend(malicious_results)

        # Calculate metrics
        metrics = self.calculate_metrics()

        # Add timing info
        metrics["test_duration"] = round(time.time() - start_time, 2)
        metrics["timestamp"] = datetime.now().isoformat()

        return metrics


@router.post("/run-large-scale-test")
async def run_large_scale_test(
        normal_dir: str,
        malicious_dir: str,
        limit: int = 10000,
        background_tasks: BackgroundTasks = None
):
    """
    Run large scale F1 Score test with 10,000+ normal and 10,000+ malicious APKs

    - **normal_dir**: Directory containing normal APK files
    - **malicious_dir**: Directory containing malicious APK files
    - **limit**: Maximum number of files to test from each directory (default: 10000)
    """
    try:
        tester = LargeScaleTester()

        logger.info(
            f"Starting large scale test with normal_dir={normal_dir}, malicious_dir={malicious_dir}, limit={limit}")

        results = await tester.run_full_test(normal_dir, malicious_dir, limit)

        # Store results
        evaluation_results["current_batch"] = results
        evaluation_results["history"].append(results)

        return {
            "status": "success",
            "message": f"Test completed. Processed {results['dataset_summary']['files_processed']} files",
            "results": results
        }

    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/large-scale-results")
async def get_large_scale_results():
    """Get the latest large scale test results"""
    if evaluation_results["current_batch"] is None:
        return {
            "status": "no_data",
            "message": "No test has been run yet. Please run /run-large-scale-test first"
        }
    return {
        "status": "success",
        "results": evaluation_results["current_batch"]
    }


@router.get("/f1-score-summary")
async def get_f1_score_summary():
    """Get a concise summary of F1 Score results for reporting"""
    if evaluation_results["current_batch"] is None:
        return {
            "status": "no_data",
            "message": "No test results available"
        }

    results = evaluation_results["current_batch"]
    metrics = results["metrics"]

    return {
        "f1_score": f"{metrics['f1_score']}%",
        "precision": f"{metrics['precision']}%",
        "recall": f"{metrics['recall']}%",
        "false_positive_rate": f"{metrics['false_positive_rate']}%",
        "accuracy": f"{metrics['accuracy']}%",
        "dataset_size": results["dataset_summary"]["total_files"],
        "confusion_matrix": results["confusion_matrix"],
        "meets_requirements": metrics["f1_score"] >= 95 and metrics["false_positive_rate"] <= 20,
        "test_duration_seconds": results["test_duration"]
    }


@router.get("/f1-score-report")
async def get_f1_score_report():
    """Generate a complete report in the format requested by Mr. Shin"""
    if evaluation_results["current_batch"] is None:
        return {
            "status": "no_data",
            "message": "Please run a large scale test first using /run-large-scale-test"
        }

    results = evaluation_results["current_batch"]
    metrics = results["metrics"]
    cm = results["confusion_matrix"]

    # Determine if requirements are met
    meets_f1_requirement = metrics["f1_score"] >= 95
    meets_fpr_requirement = metrics["false_positive_rate"] <= 20
    overall_ready = meets_f1_requirement and meets_fpr_requirement

    return {
        "report_type": "F1 Score Evaluation Report",
        "timestamp": results["timestamp"],
        "test_duration_seconds": results["test_duration"],

        "dataset": {
            "normal_apks_tested": results["dataset_summary"]["normal_files"],
            "malicious_apks_tested": results["dataset_summary"]["malicious_files"],
            "total_files_tested": results["dataset_summary"]["total_files"],
            "files_with_errors": results["dataset_summary"]["files_with_errors"]
        },

        "confusion_matrix": {
            "true_positives_TP": cm["true_positives"],
            "false_positives_FP": cm["false_positives"],
            "false_negatives_FN": cm["false_negatives"],
            "true_negatives_TN": cm["true_negatives"],
            "total": cm["total"]
        },

        "metrics": {
            "precision_percent": metrics["precision"],
            "recall_percent": metrics["recall"],
            "f1_score_percent": metrics["f1_score"],
            "false_positive_rate_percent": metrics["false_positive_rate"],
            "false_negative_rate_percent": metrics["false_negative_rate"],
            "accuracy_percent": metrics["accuracy"]
        },

        "requirements_check": {
            "f1_score_requirement_95_percent": {
                "achieved": meets_f1_requirement,
                "actual": metrics["f1_score"],
                "required": 95
            },
            "false_positive_rate_requirement_20_percent": {
                "achieved": meets_fpr_requirement,
                "actual": metrics["false_positive_rate"],
                "required": 20
            },
            "overall_ready_for_production": overall_ready
        },

        "recommendation": (
            "READY FOR PRODUCTION" if overall_ready
            else "NEEDS IMPROVEMENT - Please review false positives and missed detections"
        )
    }