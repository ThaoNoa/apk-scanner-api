#!/usr/bin/env python3
"""
Complete F1 Score Evaluation Script
This script will:
1. Check dataset availability
2. Run the large scale test
3. Generate report
"""

import asyncio
import json
import sys
from pathlib import Path
import subprocess
import requests

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


async def check_datasets():
    """Check if datasets are available"""
    normal_dir = Path("./datasets/normal_apks")
    malicious_dir = Path("./datasets/malicious_apks")

    normal_count = len(list(normal_dir.glob("*.apk"))) if normal_dir.exists() else 0
    malicious_count = len(list(malicious_dir.glob("*.apk"))) if malicious_dir.exists() else 0

    print(f"Dataset Status:")
    print(f"  Normal APKs: {normal_count} files")
    print(f"  Malicious APKs: {malicious_count} files")
    print(f"  Total: {normal_count + malicious_count} files")

    if normal_count < 100 or malicious_count < 100:
        print("\nWARNING: Dataset is too small for meaningful evaluation.")
        print("Consider generating sample datasets for testing:")
        print("  python scripts/prepare_dataset.py --generate-sample")
        return False

    return True


async def run_test():
    """Run the actual test"""
    print("\nStarting large scale evaluation...")

    try:
        response = requests.post(
            "http://localhost:8000/evaluate/run-large-scale-test",
            params={
                "normal_dir": "./datasets/normal_apks",
                "malicious_dir": "./datasets/malicious_apks",
                "limit": 10000
            },
            timeout=3600  # 1 hour timeout
        )

        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code}")
            return None

    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to server. Make sure server is running:")
        print("  uvicorn app.main:app --reload --port 8000")
        return None


def generate_report(results):
    """Generate final report for Mr. Shin"""
    if not results:
        return

    metrics = results.get("results", {}).get("metrics", {})
    cm = results.get("results", {}).get("confusion_matrix", {})
    dataset = results.get("results", {}).get("dataset_summary", {})

    report = {
        "evaluation_report": {
            "date": results.get("results", {}).get("timestamp"),
            "test_duration_seconds": results.get("results", {}).get("test_duration"),

            "dataset": {
                "normal_apks": dataset.get("normal_files"),
                "malicious_apks": dataset.get("malicious_files"),
                "total_files": dataset.get("total_files"),
                "files_with_errors": dataset.get("files_with_errors")
            },

            "confusion_matrix": {
                "true_positives": cm.get("true_positives"),
                "false_positives": cm.get("false_positives"),
                "false_negatives": cm.get("false_negatives"),
                "true_negatives": cm.get("true_negatives")
            },

            "metrics": {
                "precision": metrics.get("precision"),
                "recall": metrics.get("recall"),
                "f1_score": metrics.get("f1_score"),
                "false_positive_rate": metrics.get("false_positive_rate"),
                "accuracy": metrics.get("accuracy")
            },

            "requirements_check": {
                "f1_score_meets_95_percent": metrics.get("f1_score", 0) >= 95,
                "fpr_meets_20_percent": metrics.get("false_positive_rate", 100) <= 20,
                "ready_for_production": (metrics.get("f1_score", 0) >= 95 and
                                         metrics.get("false_positive_rate", 100) <= 20)
            }
        }
    }

    # Save report
    report_file = Path("f1_score_report.json")
    with open(report_file, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nReport saved to: {report_file}")

    # Print summary
    print("\n" + "=" * 60)
    print("F1 SCORE EVALUATION REPORT")
    print("=" * 60)
    print(f"Date: {report['evaluation_report']['date']}")
    print(f"\nDataset:")
    print(f"  Normal APKs: {dataset.get('normal_files')}")
    print(f"  Malicious APKs: {dataset.get('malicious_files')}")
    print(f"  Total: {dataset.get('total_files')}")

    print(f"\nConfusion Matrix:")
    print(f"  True Positives (TP): {cm.get('true_positives')}")
    print(f"  False Positives (FP): {cm.get('false_positives')}")
    print(f"  False Negatives (FN): {cm.get('false_negatives')}")
    print(f"  True Negatives (TN): {cm.get('true_negatives')}")

    print(f"\nMetrics:")
    print(f"  Precision: {metrics.get('precision')}%")
    print(f"  Recall: {metrics.get('recall')}%")
    print(f"  F1 Score: {metrics.get('f1_score')}%")
    print(f"  False Positive Rate: {metrics.get('false_positive_rate')}%")
    print(f"  Accuracy: {metrics.get('accuracy')}%")

    print(f"\nRequirements Check:")
    f1_ok = metrics.get('f1_score', 0) >= 95
    fpr_ok = metrics.get('false_positive_rate', 100) <= 20
    print(f"  F1 Score >= 95%: {'✓ PASS' if f1_ok else '✗ FAIL'} ({metrics.get('f1_score')}%)")
    print(f"  FPR <= 20%: {'✓ PASS' if fpr_ok else '✗ FAIL'} ({metrics.get('false_positive_rate')}%)")
    print(f"  Overall: {'✓ READY FOR PRODUCTION' if (f1_ok and fpr_ok) else '✗ NEEDS IMPROVEMENT'}")
    print("=" * 60)


async def main():
    print("=" * 60)
    print("F1 SCORE EVALUATION SYSTEM")
    print("=" * 60)

    # Check datasets
    if not await check_datasets():
        print("\nTo generate sample datasets for testing, run:")
        print("  python scripts/prepare_dataset.py --generate-sample")
        print("  python scripts/run_f1_evaluation.py --run-test")
        return

    # Run test
    results = await run_test()

    if results:
        generate_report(results)

        # Get summary
        try:
            summary = requests.get("http://localhost:8000/evaluate/f1-score-summary")
            if summary.status_code == 200:
                print("\nQuick Summary:")
                summary_data = summary.json()
                print(json.dumps(summary_data, indent=2))
        except:
            pass
    else:
        print("\nTest failed. Please check server and try again.")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--run-test", action="store_true", help="Run F1 Score test")
    args = parser.parse_args()

    if args.run_test:
        asyncio.run(main())
    else:
        print("Usage: python scripts/run_f1_evaluation.py --run-test")