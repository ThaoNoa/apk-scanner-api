import json
import csv
from typing import Dict, List, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class GroundTruthManager:
    """
    Quản lý ground truth data để đánh giá scanner
    Có thể load từ file CSV/JSON hoặc nhập manual
    """

    def __init__(self, truth_file: Optional[Path] = None):
        self.truth_data = {}
        if truth_file and truth_file.exists():
            self.load_from_file(truth_file)

    def add_ground_truth(self,
                         filename: str,
                         is_malicious: bool,
                         malware_family: str = None,
                         source: str = "manual",
                         notes: str = ""):
        """
        Thêm ground truth cho một file
        """
        self.truth_data[filename] = {
            'is_malicious': is_malicious,
            'malware_family': malware_family,
            'source': source,
            'notes': notes,
            'timestamp': __import__('datetime').datetime.now().isoformat()
        }

    def load_from_file(self, file_path: Path):
        """Load ground truth từ file"""
        try:
            if file_path.suffix == '.json':
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    for item in data:
                        self.add_ground_truth(
                            item['filename'],
                            item['is_malicious'],
                            item.get('malware_family'),
                            item.get('source', 'file'),
                            item.get('notes', '')
                        )

            elif file_path.suffix == '.csv':
                with open(file_path, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        self.add_ground_truth(
                            row['filename'],
                            row['is_malicious'].lower() == 'true',
                            row.get('malware_family'),
                            row.get('source', 'csv'),
                            row.get('notes', '')
                        )

            logger.info(f"Loaded {len(self.truth_data)} ground truth records from {file_path}")

        except Exception as e:
            logger.error(f"Error loading ground truth: {e}")

    def get_truth(self, filename: str) -> Optional[Dict]:
        """Lấy ground truth cho một file"""
        return self.truth_data.get(filename)

    def is_malicious(self, filename: str) -> Optional[bool]:
        """Kiểm tra file có malicious không theo ground truth"""
        truth = self.get_truth(filename)
        return truth['is_malicious'] if truth else None

    def save_to_file(self, file_path: Path):
        """Save ground truth to file"""
        try:
            data = []
            for filename, truth in self.truth_data.items():
                data.append({
                    'filename': filename,
                    **truth
                })

            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Saved {len(data)} ground truth records to {file_path}")

        except Exception as e:
            logger.error(f"Error saving ground truth: {e}")


# Singleton instance
ground_truth = GroundTruthManager()