"""
Script to download and organize APK datasets
Run this script to prepare test datasets
"""

import os
import sys
import json
import requests
import hashlib
from pathlib import Path
import subprocess
import time
from datetime import datetime

# Configuration
NORMAL_APK_DIR = Path("./datasets/normal_apks")
MALICIOUS_APK_DIR = Path("./datasets/malicious_apks")


def create_directories():
    """Create necessary directories"""
    NORMAL_APK_DIR.mkdir(parents=True, exist_ok=True)
    MALICIOUS_APK_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Created directories:")
    print(f"  - {NORMAL_APK_DIR}")
    print(f"  - {MALICIOUS_APK_DIR}")


def download_from_apk_mirror(category: str, max_downloads: int = 100):
    """Download APKs from APKMirror (simplified)"""
    # This is a placeholder - actual implementation would use APKMirror API or scraping
    print(f"Downloading {max_downloads} APKs from {category} category...")
    # Implementation would go here
    return []


def download_from_virusshare(api_key: str, max_downloads: int = 1000):
    """Download malware samples from VirusShare"""
    print(f"Downloading {max_downloads} malware samples from VirusShare...")
    # Implementation would go here
    return []


def generate_sample_datasets():
    """
    Generate sample datasets for testing when real datasets are not available
    This creates dummy APK files for testing the evaluation framework
    """
    print("Generating sample datasets for testing...")

    # Create sample normal APKs (fake)
    for i in range(100):  # Create 100 sample normal APKs
        fake_apk = NORMAL_APK_DIR / f"normal_sample_{i:04d}.apk"
        fake_apk.touch()
        print(f"  Created: {fake_apk.name}")

    # Create sample malicious APKs (fake)
    for i in range(100):  # Create 100 sample malicious APKs
        fake_apk = MALICIOUS_APK_DIR / f"malicious_sample_{i:04d}.apk"
        fake_apk.touch()
        print(f"  Created: {fake_apk.name}")

    print(f"Generated {100} sample normal APKs and {100} sample malicious APKs")
    print("Note: These are empty files for testing only. Replace with real APKs for actual evaluation.")


def create_ground_truth_file():
    """Create ground truth file from dataset"""
    ground_truth = []

    # Add normal APKs
    for apk in NORMAL_APK_DIR.glob("*.apk"):
        ground_truth.append({
            "filename": apk.name,
            "is_malicious": False,
            "source": "normal_dataset",
            "notes": "Verified normal application"
        })

    # Add malicious APKs
    for apk in MALICIOUS_APK_DIR.glob("*.apk"):
        ground_truth.append({
            "filename": apk.name,
            "is_malicious": True,
            "source": "malware_dataset",
            "notes": "Known malware sample"
        })

    # Save ground truth
    ground_truth_file = Path("./ground_truth.json")
    with open(ground_truth_file, "w") as f:
        json.dump(ground_truth, f, indent=2)

    print(f"Created ground truth file with {len(ground_truth)} entries")
    return ground_truth_file


def run_evaluation():
    """Run the F1 Score evaluation via API"""
    import requests

    print("Running F1 Score evaluation...")

    try:
        response = requests.post(
            "http://localhost:8000/evaluate/run-large-scale-test",
            params={
                "normal_dir": str(NORMAL_APK_DIR),
                "malicious_dir": str(MALICIOUS_APK_DIR),
                "limit": 10000
            }
        )

        if response.status_code == 200:
            results = response.json()
            print("\n" + "=" * 60)
            print("F1 SCORE EVALUATION RESULTS")
            print("=" * 60)

            metrics = results["results"]["metrics"]
            cm = results["results"]["confusion_matrix"]

            print(f"Dataset:")
            print(f"  Normal APKs: {results['results']['dataset_summary']['normal_files']}")
            print(f"  Malicious APKs: {results['results']['dataset_summary']['malicious_files']}")
            print(f"  Total: {results['results']['dataset_summary']['total_files']}")
            print(f"  Files processed: {cm['total']}")
            print(f"  Files with errors: {results['results']['dataset_summary']['files_with_errors']}")

            print(f"\nConfusion Matrix:")
            print(f"  True Positives (TP): {cm['true_positives']}")
            print(f"  False Positives (FP): {cm['false_positives']}")
            print(f"  False Negatives (FN): {cm['false_negatives']}")
            print(f"  True Negatives (TN): {cm['true_negatives']}")

            print(f"\nMetrics:")
            print(f"  Precision: {metrics['precision']}%")
            print(f"  Recall: {metrics['recall']}%")
            print(f"  F1 Score: {metrics['f1_score']}%")
            print(f"  False Positive Rate: {metrics['false_positive_rate']}%")
            print(f"  Accuracy: {metrics['accuracy']}%")
            print(f"\nTest Duration: {results['results']['test_duration']} seconds")

            print("\n" + "=" * 60)

            # Check requirements
            f1_ok = metrics['f1_score'] >= 95
            fpr_ok = metrics['false_positive_rate'] <= 20

            print("\nRequirements Check:")
            print(f"  F1 Score >= 95%: {'✓ PASS' if f1_ok else '✗ FAIL'} ({metrics['f1_score']}%)")
            print(f"  FPR <= 20%: {'✓ PASS' if fpr_ok else '✗ FAIL'} ({metrics['false_positive_rate']}%)")
            print(f"  Overall: {'✓ READY FOR PRODUCTION' if (f1_ok and fpr_ok) else '✗ NEEDS IMPROVEMENT'}")

            return results
        else:
            print(f"Error: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.ConnectionError:
        print("ERROR: Cannot connect to API server. Please start the server first:")
        print("  uvicorn app.main:app --reload --port 8000")
        return None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Prepare dataset for F1 Score evaluation")
    parser.add_argument("--generate-sample", action="store_true", help="Generate sample datasets for testing")
    parser.add_argument("--run-eval", action="store_true", help="Run evaluation after preparing datasets")

    args = parser.parse_args()

    create_directories()

    if args.generate_sample:
        generate_sample_datasets()

    # Create ground truth file if any APKs exist
    if list(NORMAL_APK_DIR.glob("*.apk")) or list(MALICIOUS_APK_DIR.glob("*.apk")):
        create_ground_truth_file()

    if args.run_eval:
        run_evaluation()