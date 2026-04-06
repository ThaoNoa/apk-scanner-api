from typing import List, Dict, Any
import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class MetricsCalculator:
    """
    Tính toán các metrics đánh giá hiệu suất của scanner
    Bao gồm: TP, FP, FN, TN, Precision, Recall, F1 Score
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset tất cả metrics về 0"""
        self.tp = 0  # True Positive
        self.fp = 0  # False Positive
        self.fn = 0  # False Negative
        self.tn = 0  # True Negative

        # Lưu lịch sử predictions để phân tích
        self.predictions = []

        # Metrics theo từng scanner
        self.scanner_metrics = defaultdict(lambda: {
            'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0,
            'predictions': []
        })

    def add_prediction(self,
                       filename: str,
                       actual_label: str,  # "malicious" hoặc "normal"
                       predicted_label: str,  # "malicious" hoặc "normal"
                       predicted_risk: str,  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
                       risk_score: float,
                       scanner_used: str = "combined",
                       ground_truth: str = None):
        """
        Thêm một prediction vào metrics

        Args:
            filename: Tên file APK
            actual_label: Nhãn thực tế (từ ground truth)
            predicted_label: Nhãn dự đoán từ scanner
            predicted_risk: Mức độ risk dự đoán
            risk_score: Điểm risk (0-100)
            scanner_used: Scanner đã dùng (androguard, mobsf, combined)
            ground_truth: Nguồn ground truth (manual, virustotal, etc.)
        """

        # Chuyển đổi label thành boolean
        actual = actual_label.lower() == "malicious"
        predicted = predicted_label.lower() == "malicious"

        # Tạo prediction record
        prediction = {
            'filename': filename,
            'timestamp': datetime.now().isoformat(),
            'actual': actual_label,
            'predicted': predicted_label,
            'predicted_risk': predicted_risk,
            'risk_score': risk_score,
            'scanner': scanner_used,
            'ground_truth': ground_truth,
            'correct': actual == predicted
        }

        # Update tổng metrics
        if actual and predicted:  # TP
            self.tp += 1
            prediction['classification'] = 'TP'
        elif not actual and predicted:  # FP
            self.fp += 1
            prediction['classification'] = 'FP'
        elif actual and not predicted:  # FN
            self.fn += 1
            prediction['classification'] = 'FN'
        elif not actual and not predicted:  # TN
            self.tn += 1
            prediction['classification'] = 'TN'

        # Update metrics theo scanner
        scanner_metrics = self.scanner_metrics[scanner_used]
        if actual and predicted:
            scanner_metrics['tp'] += 1
        elif not actual and predicted:
            scanner_metrics['fp'] += 1
        elif actual and not predicted:
            scanner_metrics['fn'] += 1
        elif not actual and not predicted:
            scanner_metrics['tn'] += 1

        scanner_metrics['predictions'].append(prediction)
        self.predictions.append(prediction)

    def calculate_precision(self, tp: int = None, fp: int = None) -> float:
        """
        Tính Precision = TP / (TP + FP)
        Precision cao = ít false alarms
        """
        if tp is None:
            tp = self.tp
        if fp is None:
            fp = self.fp

        if tp + fp == 0:
            return 0.0
        return tp / (tp + fp)

    def calculate_recall(self, tp: int = None, fn: int = None) -> float:
        """
        Tính Recall = TP / (TP + FN)
        Recall cao = ít missed detections
        """
        if tp is None:
            tp = self.tp
        if fn is None:
            fn = self.fn

        if tp + fn == 0:
            return 0.0
        return tp / (tp + fn)

    def calculate_f1_score(self, precision: float = None, recall: float = None) -> float:
        """
        Tính F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
        F1 là harmonic mean của precision và recall
        """
        if precision is None:
            precision = self.calculate_precision()
        if recall is None:
            recall = self.calculate_recall()

        if precision + recall == 0:
            return 0.0
        return 2 * (precision * recall) / (precision + recall)

    def calculate_accuracy(self) -> float:
        """
        Tính Accuracy = (TP + TN) / (TP + FP + FN + TN)
        """
        total = self.tp + self.fp + self.fn + self.tn
        if total == 0:
            return 0.0
        return (self.tp + self.tn) / total

    def calculate_false_positive_rate(self) -> float:
        """
        Tính FPR = FP / (FP + TN)
        """
        if self.fp + self.tn == 0:
            return 0.0
        return self.fp / (self.fp + self.tn)

    def calculate_false_negative_rate(self) -> float:
        """
        Tính FNR = FN / (FN + TP)
        """
        if self.fn + self.tp == 0:
            return 0.0
        return self.fn / (self.fn + self.tp)

    def get_summary(self) -> Dict[str, Any]:
        """Lấy tổng hợp tất cả metrics"""
        precision = self.calculate_precision()
        recall = self.calculate_recall()
        f1 = self.calculate_f1_score(precision, recall)

        return {
            "total_predictions": len(self.predictions),
            "confusion_matrix": {
                "true_positives": self.tp,
                "false_positives": self.fp,
                "false_negatives": self.fn,
                "true_negatives": self.tn
            },
            "metrics": {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "accuracy": round(self.calculate_accuracy(), 4),
                "false_positive_rate": round(self.calculate_false_positive_rate(), 4),
                "false_negative_rate": round(self.calculate_false_negative_rate(), 4)
            },
            "by_scanner": self.get_scanner_metrics(),
            "recent_predictions": self.predictions[-10:]  # 10 predictions gần nhất
        }

    def get_scanner_metrics(self) -> Dict[str, Any]:
        """Lấy metrics theo từng scanner"""
        result = {}
        for scanner, metrics in self.scanner_metrics.items():
            tp = metrics['tp']
            fp = metrics['fp']
            fn = metrics['fn']
            tn = metrics['tn']

            precision = tp / (tp + fp) if tp + fp > 0 else 0
            recall = tp / (tp + fn) if tp + fn > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if precision + recall > 0 else 0

            result[scanner] = {
                "confusion_matrix": {
                    "tp": tp, "fp": fp, "fn": fn, "tn": tn
                },
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "predictions_count": len(metrics['predictions'])
            }
        return result

    def get_confusion_matrix_html(self) -> str:
        """Tạo HTML table cho confusion matrix"""
        return f"""
        <table border="1" style="border-collapse: collapse;">
            <tr>
                <th colspan="2" rowspan="2">Confusion Matrix</th>
                <th colspan="2" style="text-align: center;">Actual</th>
            </tr>
            <tr>
                <th>Malicious (P)</th>
                <th>Normal (N)</th>
            </tr>
            <tr>
                <th rowspan="2">Predicted</th>
                <th>Malicious (P')</th>
                <td style="background-color: #90EE90;">TP = {self.tp}</td>
                <td style="background-color: #FFB6C1;">FP = {self.fp}</td>
            </tr>
            <tr>
                <th>Normal (N')</th>
                <td style="background-color: #FFB6C1;">FN = {self.fn}</td>
                <td style="background-color: #90EE90;">TN = {self.tn}</td>
            </tr>
        </table>
        """

    def evaluate_threshold(self, predictions: List[Dict], thresholds: List[float] = None):
        """
        Đánh giá F1 score ở các threshold khác nhau
        Giúp tìm threshold tối ưu cho risk_score
        """
        if thresholds is None:
            thresholds = [i / 10 for i in range(10)]  # 0.0, 0.1, ..., 0.9

        results = []
        for threshold in thresholds:
            tp = fp = fn = tn = 0

            for pred in predictions:
                actual = pred['actual'] == 'malicious'
                predicted = pred['risk_score'] >= threshold * 100

                if actual and predicted:
                    tp += 1
                elif not actual and predicted:
                    fp += 1
                elif actual and not predicted:
                    fn += 1
                elif not actual and not predicted:
                    tn += 1

            precision = tp / (tp + fp) if tp + fp > 0 else 0
            recall = tp / (tp + fn) if tp + fn > 0 else 0
            f1 = 2 * (precision * recall) / (precision + recall) if precision + recall > 0 else 0

            results.append({
                'threshold': threshold,
                'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
                'precision': round(precision, 4),
                'recall': round(recall, 4),
                'f1_score': round(f1, 4)
            })

        # Tìm threshold tối ưu
        best = max(results, key=lambda x: x['f1_score'])

        return {
            'threshold_analysis': results,
            'optimal_threshold': best['threshold'],
            'optimal_f1': best['f1_score']
        }


# Singleton instance
metrics_calculator = MetricsCalculator()