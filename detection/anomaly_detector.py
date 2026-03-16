"""
Anomaly Detection Module (Unsupervised ML)
Uses Isolation Forest to detect anomalous process behavior patterns
Replaces legacy heuristic-based detection
"""

import numpy as np
import joblib
from pathlib import Path
from typing import Dict, List, Optional
import logging
from sklearn.ensemble import IsolationForest
import warnings

# Suppress sklearn warnings about feature names if vectors are unlabeled
warnings.filterwarnings("ignore", category=UserWarning)

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Unsupervised Anomaly Detection using Isolation Forest
    Learns 'normal' behavior from system processes and flags outliers
    """
    
    def __init__(self, model_path: Optional[Path] = None):
        from config import ANOMALY_MODEL_PATH
        self.model_path = model_path or ANOMALY_MODEL_PATH
        self.model = self._load_model()
        
    def _load_model(self) -> Optional[IsolationForest]:
        """Load pre-trained Isolation Forest model"""
        if not self.model_path.exists():
            logger.info("Anomaly model not found (Training required). Defaulting to passive mode.")
            return None
            
        try:
            model = joblib.load(self.model_path)
            logger.info(f"Loaded Isolation Forest model from {self.model_path}")
            return model
        except Exception as e:
            logger.error(f"Error loading anomaly model: {e}")
            return None

    def train_model(self, feature_vectors: List[List[float]]) -> Dict:
        """
        Train the Isolation Forest on a dataset of process features
        
        Args:
            feature_vectors: List of numerical feature vectors from FeatureExtractor
            
        Returns:
            Training summary dictionary
        """
        if not feature_vectors:
            return {'status': 'error', 'message': 'No training data provided'}
            
        try:
            # Check data dimensions
            X = np.array(feature_vectors)
            n_samples, n_features = X.shape
            
            logger.info(f"Training Isolation Forest on {n_samples} samples with {n_features} features...")
            
            # Initialize and fit model
            # contamination=0.05 assumes ~5% of training data might be noise/anomalies (e.g. active malware)
            self.model = IsolationForest(
                n_estimators=100, 
                contamination=0.05, 
                max_samples='auto',
                random_state=42,
                n_jobs=1 # Disable parallelism to prevent thread crash at shutdown
            )
            
            self.model.fit(X)
            
            # Save model
            self.model_path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self.model, self.model_path)
            
            logger.info(f"Model saved to {self.model_path}")
            
            return {
                'status': 'success',
                'samples': n_samples,
                'features': n_features,
                'path': str(self.model_path)
            }
            
        except Exception as e:
            logger.error(f"Training failed: {e}")
            return {'status': 'error', 'message': str(e)}

    def detect_anomalies(self, features: Dict) -> Dict:
        """
        Detect anomalies using the trained Isolation Forest
        
        Args:
            features: Feature dictionary from FeatureExtractor
            
        Returns:
            Anomaly detection results
        """
        # --- TRUSTED PROCESS BYPASS ---
        try:
            # 1. Resolve Process Name
            src_path = str(features.get('metadata', {}).get('source_dump', ''))
            process_name = features.get('process_name', '')
            
            if not process_name and src_path:
                process_name = Path(src_path).name # e.g. "svchost.exe_1234.raw"
            
            # Normalize for checking
            p_name_lower = process_name.lower()
            src_path_lower = src_path.lower()
            
            # 2. Load Config Whitelist
            from config import TRUSTED_PROCESSES
            
            # 3. Hardcoded Critical Whitelist (Safety Net)
            CRITICAL_WHITELIST = [
                "antigravity", "python", "code.exe", "pythonservice.exe", 
                "system", "registry", "smss.exe", "csrss.exe", 
                "amdfendrsr.exe", "searchapp.exe", "msedgewebview2.exe",
                "language_server", "pyrefly.exe"
            ]
            
            # 4. Check logic
            is_trusted = False
            
            # Check A: Config list
            if any(t.lower() in p_name_lower or t.lower() in src_path_lower for t in TRUSTED_PROCESSES):
                is_trusted = True
                
            # Check B: Critical Hardcoded list (overrides config issues)
            if not is_trusted and any(c in p_name_lower for c in CRITICAL_WHITELIST):
                is_trusted = True
                
            if is_trusted:
                logger.debug(f"Anomaly Detection BYPASSED for trusted process: {process_name}")
                return {
                    'is_anomalous': False,
                    'anomaly_score': 0.0,
                    'severity': 'LOW',
                    'detected_anomalies': [],
                    'model_status': 'bypassed (trusted)'
                }
                
        except Exception as e:
            logger.error(f"Error checking trusted process: {e}")
        # ------------------------------

        # Convert artifact to vector using the extractor's logic
        from detection.feature_extractor import FeatureExtractor
        extractor = FeatureExtractor()
        vector = extractor.export_for_ml(features)
        
        # Prepare result structure
        results = {
            'is_anomalous': False,
            'anomaly_score': 0.0,
            'severity': 'LOW',
            'detected_anomalies': [],
            'model_status': 'active' if self.model else 'inactive (needs training)'
        }
        
        if not self.model:
            return results
            
        try:
            # Get expected feature count from model
            expected_features = getattr(self.model, 'n_features_in_', 55)
            actual_features = len(vector)
            
            # Handle dimension mismatch gracefully
            if actual_features < expected_features:
                # Pad with zeros to match expected dimensions
                vector = vector + [0.0] * (expected_features - actual_features)
                logger.debug(f"Padded feature vector from {actual_features} to {expected_features}")
            elif actual_features > expected_features:
                # Truncate to expected dimensions
                vector = vector[:expected_features]
                logger.debug(f"Truncated feature vector from {actual_features} to {expected_features}")
            
            X = np.array(vector).reshape(1, -1)
            
            # Predict: 1 (normal), -1 (anomaly)
            prediction = self.model.predict(X)[0]
            
            # Decision function: < 0 is anomaly, > 0 is normal.
            # Lower is more anomalous.
            raw_score = self.model.decision_function(X)[0]
            
            # Normalize raw score to 0-100 scale for UI
            # Decision function usually ranges -0.5 to 0.5 roughly
            # We want -0.2 -> 100 (Critical), 0.2 -> 0 (Normal)
            # score = (0.2 - raw_score) * 250? Let's map dynamically.
            
            # Simply: smaller raw_score = higher anomaly
            # If raw_score < 0: It's an anomaly.
            
            if prediction == -1:
                results['is_anomalous'] = True
                
                # Calculate severity based on how negative the score is
                # -0.01 to -0.1 : Medium
                # < -0.1 : High/Critical
                
                normalized_score = min(100, max(50, 50 + (abs(min(0, raw_score)) * 200))) 
                results['anomaly_score'] = round(normalized_score, 1)
                
                if normalized_score > 80:
                    results['severity'] = 'CRITICAL'
                    desc = "Extreme deviation from normal system behavior"
                elif normalized_score > 65:
                    results['severity'] = 'HIGH'
                    desc = "High deviation from normal patterns"
                else:
                    results['severity'] = 'MEDIUM'
                    desc = "Statistical outlier detected"
                    
                results['detected_anomalies'].append({
                    'type': 'ML_ISOLATION_FOREST',
                    'severity': results['severity'],
                    'value': f"Score: {raw_score:.3f}",
                    'description': desc
                })
                
            else:
                # Normal
                results['is_anomalous'] = False
                # Map positive score (0 to 0.5) to (50 to 0)
                norm_score = max(0, 50 - (raw_score * 100))
                results['anomaly_score'] = round(norm_score, 1)
                
        except Exception as e:
            logger.error(f"Anomaly detection error: {e}")
            results['error'] = str(e)
            
        return results
