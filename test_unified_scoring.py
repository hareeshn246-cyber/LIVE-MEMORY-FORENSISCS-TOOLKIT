
import sys
import os
import unittest
import json
from typing import Dict

# Ensure project root is in path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from detection.feature_extractor import FeatureExtractor

class TestUnifiedScoring(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor()
        # Mock features that would be extracted
        self.base_features = {
            'signature_indicators': {'is_signature_match': False, 'matched_rules': [], 'total_detections': 0},
            'integrity_indicators': {'hooks_detected': [], 'is_compromised': False},
            'metadata': {'source_dump': 'C:\\temp\\unknown_malware_proc.raw'}
        }

    def test_benign_process(self):
        """Test a clean process gets a low score."""
        risk_data = self.extractor.calculate_weighted_risk(self.base_features, anomaly_score=0.0, ml_confidence=0.0)
        self.assertEqual(risk_data['risk_score'], 0.0)

    def test_yara_only(self):
        """Test YARA matches contribute 15 points (critical)."""
        features = self.base_features.copy()
        features['signature_indicators'] = {
            'is_signature_match': True,
            'matched_rules': [{'name': 'TestRule', 'severity': 'critical'}],
            'total_detections': 1
        }
        risk_data = self.extractor.calculate_weighted_risk(features, anomaly_score=0.0, ml_confidence=0.0)
        self.assertEqual(risk_data['risk_score'], 15.0)

    def test_combined_malicious(self):
        """Test combination of signals (15 + 10 + 28 + 24 = 77)."""
        features = self.base_features.copy()
        features['signature_indicators'] = {
            'is_signature_match': True,
            'matched_rules': [{'name': 'Ransomware', 'severity': 'critical'}],
            'total_detections': 1
        }
        features['integrity_indicators'] = {
            'hooks_detected': ['Hook1', 'Hook2'],
            'is_compromised': True
        }
        # 15 + 10 + (80 * 0.35 = 28) + (60 * 0.40 = 24) = 77
        risk_data = self.extractor.calculate_weighted_risk(features, anomaly_score=60.0, ml_confidence=80.0)
        
        print("\nDEBUG INFO:")
        print(f"YARA Score: {risk_data['components']['yara_score']}")
        print(f"Integrity Score: {risk_data['components']['integrity_score']}")
        print(f"ML Weighted: {risk_data['components']['ml_weighted']}")
        print(f"Anomaly Weighted: {risk_data['components']['anomaly_weighted']}")
        print(f"Total Risk Score: {risk_data['risk_score']}")
        
        self.assertEqual(risk_data['risk_score'], 77.0)

if __name__ == "__main__":
    unittest.main()
