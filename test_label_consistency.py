import sys
from detection.ml_inference import MLDetector

def test_label_consistency():
    detector = MLDetector()
    
    # Mock data for Critical YARA match
    data_critical = {
        'signature_indicators': {
            'is_signature_match': True,
            'matched_rules': [{'name': 'Malware_Critical', 'severity': 'critical'}]
        },
        'integrity_indicators': {'hooks_detected': []},
        'anomaly_detection': {'anomaly_score': 0.0},
        'status': 'completed'
    }
    
    # Mock data for Low Score (No YARA, Low components)
    data_low = {
        'signature_indicators': {'is_signature_match': False, 'matched_rules': []},
        'integrity_indicators': {'hooks_detected': []},
        'anomaly_detection': {'anomaly_score': 10.0},
        'status': 'completed'
    }

    print("\n--- Testing Forensic Override (Critical YARA) ---")
    res_crit = detector.predict_from_artifact(data_critical)
    print(f"Classification: {res_crit['classification']}")
    print(f"Severity: {res_crit['severity']}")
    print(f"Risk Score: {res_crit['risk_score']}")
    
    # Check 1: Should now be boosted to 85.0
    success = True
    if res_crit['classification'] != "MALICIOUS" or res_crit['risk_score'] < 81:
        print(f"[FAIL] Critical YARA match should be MALICIOUS with score >= 81 (Got {res_crit['classification']} - {res_crit['risk_score']})")
        success = False
        
    print("\n--- Testing Low Score (10% Anomaly) ---")
    res_low = detector.predict_from_artifact(data_low)
    # 10% anomaly component is (10/100)*40 = 4.0 points.
    print(f"Classification: {res_low['classification']}")
    print(f"Severity: {res_low['severity']}")
    print(f"Risk Score: {res_low['risk_score']}")
    
    if res_low['classification'] != "BENIGN" or res_low['risk_score'] > 30:
        print(f"[FAIL] Low evidence should be BENIGN with score <= 30 (Got {res_low['classification']} - {res_low['risk_score']})")
        success = False
        
    return success

if __name__ == "__main__":
    if test_label_consistency():
        print("\n[SUCCESS] Label consistency verified.")
    else:
        print("\n[FAILURE] Label consistency check failed.")
        sys.exit(1)
