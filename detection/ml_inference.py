"""
Machine Learning Inference Module
Loads pre-trained models and scores JSON artifacts
Provides explainable detection results
"""

import joblib
import numpy as np
from pathlib import Path
from typing import Dict, Optional, List
import logging

logger = logging.getLogger(__name__)


class MLDetector:
    """
    ML-based behavioral malware detection
    Uses pre-trained Random Forest classifier
    """
    
    def __init__(self, model_path: Optional[Path] = None, scaler_path: Optional[Path] = None):
        from config import MODEL_CLASSIFIER_PATH, MODEL_SCALER_PATH
        
        self.model_path = model_path or MODEL_CLASSIFIER_PATH
        self.scaler_path = scaler_path or MODEL_SCALER_PATH
        
        self.model = self._load_model()
        self.scaler = self._load_scaler()
        
        # Feature names for explainability
        self.feature_names = [
            'signature_match',
            'yara_detection_count',
            'matched_rule_count',
            'is_hooked',
            'hook_count',
            'clean_functions',
            'suspicious_api_refs',
            'has_network_activity',
            'network_pattern_count',
            'has_registry_activity',
            'url_count',
            'ip_count',
            'file_path_count',
            'entropy',
            'null_ratio',
            'printable_ratio',
            'unique_bytes',
            'pe_machine',
            'pe_opt_header_size',
            'pe_characteristics',
            'pe_linker_major',
            'pe_code_size',
            'pe_init_data',
            'pe_uninit_data',
            'pe_entry_point',
            'pe_image_base',
            'pe_dll_char'
        ]
    
    def _load_model(self) -> Optional[object]:
        """Load pre-trained ML model"""
        if not self.model_path.exists():
            logger.warning(f"Model not found at {self.model_path}")
            logger.info("ML inference will not be available until model is trained")
            return None
        
        try:
            model = joblib.load(self.model_path)
            logger.info(f"Loaded ML model from {self.model_path}")
            return model
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return None
    
    def _load_scaler(self) -> Optional[object]:
        """Load feature scaler"""
        if not self.scaler_path.exists():
            logger.warning(f"Scaler not found at {self.scaler_path}")
            return None
        
        try:
            scaler = joblib.load(self.scaler_path)
            logger.info(f"Loaded scaler from {self.scaler_path}")
            return scaler
        except Exception as e:
            logger.error(f"Error loading scaler: {e}")
            return None
    
    def predict(self, feature_vector: List[float]) -> Dict:
        """
        Perform ML inference on feature vector
        
        Args:
            feature_vector: Numerical features extracted from memory
            
        Returns:
            Prediction results with confidence scores
        """
        if not self.model:
            return {
                'status': 'unavailable',
                'message': 'ML model not loaded',
                'prediction': None
            }
        
        try:
            # Convert to numpy array and reshape
            # FIX: Slice to first 27 features (Model Training Mismatch Fix)
            # The model was trained on 27 features, but extractor produces 55 (CIC-MalMem compatibility)
            # We must exclude 'total_size' (index 17) which was added later, to realign PE features
            if len(feature_vector) >= 55:
                 # Exclude index 17 and take the rest up to 28 (so we get 27 total items)
                 selected_features = feature_vector[:17] + feature_vector[18:28]
                 X = np.array(selected_features).reshape(1, -1)
                 logger.info(f"DEBUG: Fixed vector shape from {len(feature_vector)} to 27 (Excluded index 17)")
            else:
                 # Fallback for legacy/other vector sizes
                 X = np.array(feature_vector[:27]).reshape(1, -1)
                 logger.info(f"DEBUG: Vector shape {len(feature_vector)} - Sliced to 27")

            
            # Apply scaling if available
            if self.scaler:
                X = self.scaler.transform(X)
            
            # Get prediction and probability
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]

            logger.info(f"DEBUG: ML Prediction: {prediction}, Probs: {probabilities}")
            logger.info(f"DEBUG: Vector Head (First 5): {X[0][:5]}")

            
            # For binary classification: [benign_prob, malware_prob]
            benign_confidence = probabilities[0]
            malware_confidence = probabilities[1]
            
            # Determine classification
            from config import ML_MALWARE_THRESHOLD, ML_HIGH_RISK_THRESHOLD
            
            if malware_confidence >= ML_HIGH_RISK_THRESHOLD:
                classification = "MALICIOUS_HIGH_CONFIDENCE"
                severity = "CRITICAL"
            elif malware_confidence >= ML_MALWARE_THRESHOLD:
                classification = "MALICIOUS_MEDIUM_CONFIDENCE"
                severity = "HIGH"
            elif malware_confidence >= 0.5:
                classification = "SUSPICIOUS"
                severity = "MEDIUM"
            else:
                classification = "BENIGN"
                severity = "LOW"
            
            results = {
                'status': 'completed',
                'prediction': int(prediction),
                'classification': classification,
                'severity': severity,
                'confidence_scores': {
                    'benign': round(float(benign_confidence), 4),
                    'malware': round(float(malware_confidence), 4)
                },
                'is_malicious': bool(prediction == 1),
                'threshold': ML_MALWARE_THRESHOLD
            }
            
            # Add feature importance if available
            if hasattr(self.model, 'feature_importances_'):
                # Use the aligned vector (X is scaled, so we need the raw aligned values)
                if len(feature_vector) >= 55:
                    clean_vector = feature_vector[:17] + feature_vector[18:28]
                else:
                    clean_vector = feature_vector[:27]
                
                results['feature_importance'] = self._explain_prediction(
                    clean_vector, 
                    self.model.feature_importances_
                )
            
            return results
            
        except Exception as e:
            logger.error(f"Error during ML inference: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'prediction': None
            }
    
    def predict_from_artifact(self, artifact_data: Dict) -> Dict:
        """
        Perform prediction directly from JSON artifact using Hybrid Decision Engine.
        Combines ML Confidence with Forensic Risk Scores.
        """
        from detection.feature_extractor import FeatureExtractor
        
        # 1. Extract Features & Get ML Confidence
        extractor = FeatureExtractor()
        feature_vector = extractor.export_for_ml(artifact_data)
        
        base_result = self.predict(feature_vector)
        ml_confidence = base_result['confidence_scores']['malware'] * 100.0 # 0-100
        
        # 2. Heuristic/Forensic Assessment (Unified Engine)
        anomaly_score = artifact_data.get('anomaly_detection', {}).get('anomaly_score', 0)
        
        risk_data = extractor.calculate_weighted_risk(
            artifact_data, 
            anomaly_score=anomaly_score,
            ml_confidence=ml_confidence
        )
        
        final_score = risk_data['risk_score']
        risk_factors = risk_data['risk_factors']
        decision_rationale = []
        
        # 3. THRESHOLD CALIBRATION (Unified)
        # 0-30: BENIGN
        # 31-60: SUSPICIOUS
        # 61-80: HIGH RISK
        # 81-100: MALICIOUS
        
        # [NEW] BOOST: Forensic Override for Critical Evidence (YARA)
        # If we have a critical YARA match, the score should BE high (85+), not just the label.
        if risk_data['components'].get('yara_score', 0) >= 15:
            final_score = max(final_score, 85.0)
            decision_rationale.append("Forensic Override: Critical YARA match detected (Score Boosted).")

        final_score = round(final_score, 1)
        
        if final_score >= 81:
            classification = "MALICIOUS"
            severity = "CRITICAL"
            is_malicious = True
        elif final_score >= 61:
            classification = "HIGH RISK"
            severity = "HIGH"
            is_malicious = True
        elif final_score >= 31:
            classification = "SUSPICIOUS"
            severity = "MEDIUM"
            is_malicious = False
        else:
            classification = "BENIGN"
            severity = "LOW"
            is_malicious = False

        # 4. Construct Result
        from config import ML_MALWARE_THRESHOLD
        
        if risk_factors:
            decision_rationale.extend(risk_factors)
            
        result = {
            'status': 'completed',
            'prediction': 1 if is_malicious else 0,
            'classification': classification,
            'severity': severity,
            'confidence_scores': base_result['confidence_scores'],
            'is_malicious': is_malicious,
            'risk_score': final_score, # Exposed for UI
            'decision_rationale': list(set(decision_rationale)), # Unique rationale
            'components': risk_data['components'], # Debug info
            'threshold': ML_MALWARE_THRESHOLD
        }
        
        return result
    
    def _explain_prediction(self, feature_vector: List[float], importances: np.ndarray) -> Dict:
        """
        Explain ML prediction using feature importance
        
        Args:
            feature_vector: Input features
            importances: Feature importance from model
            
        Returns:
            Explanation dictionary
        """
        # Combine features with their importance and values
        feature_contributions = [
            {
                'name': name,
                'value': float(value),
                'importance': float(importance),
                'contribution': float(value * importance)
            }
            for name, value, importance in zip(self.feature_names, feature_vector, importances)
        ]
        
        # Sort by contribution (absolute value)
        feature_contributions.sort(key=lambda x: abs(x['contribution']), reverse=True)
        
        # Get top 5 contributing features
        top_features = feature_contributions[:5]
        
        return {
            'top_contributing_features': top_features,
            'all_features': feature_contributions
        }
    
    def batch_predict(self, artifact_paths: List[Path]) -> List[Dict]:
        """
        Perform batch prediction on multiple artifacts
        
        Args:
            artifact_paths: List of JSON artifact file paths
            
        Returns:
            List of prediction results
        """
        results = []
        
        import json
        
        for artifact_path in artifact_paths:
            try:
                with open(artifact_path, 'r') as f:
                    artifact_data = json.load(f)
                
                prediction = self.predict_from_artifact(artifact_data)
                prediction['artifact_path'] = str(artifact_path)
                
                results.append(prediction)
                
            except Exception as e:
                logger.error(f"Error processing {artifact_path}: {e}")
                results.append({
                    'artifact_path': str(artifact_path),
                    'status': 'error',
                    'message': str(e)
                })
        
        return results
    
    def model_info(self) -> Dict:
        """Get information about loaded model"""
        if not self.model:
            return {'status': 'not_loaded'}
        
        info = {
            'model_type': type(self.model).__name__,
            'model_path': str(self.model_path),
            'scaler_available': self.scaler is not None,
            'feature_count': len(self.feature_names),
            'feature_names': self.feature_names
        }
        
        # Add model-specific info if available
        if hasattr(self.model, 'n_estimators'):
            info['n_estimators'] = self.model.n_estimators
        if hasattr(self.model, 'max_depth'):
            info['max_depth'] = self.model.max_depth
        
        return info
