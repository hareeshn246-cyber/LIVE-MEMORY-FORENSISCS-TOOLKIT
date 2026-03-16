
import logging
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import os

class AnomalyDetector:
    """
    Statistical Anomaly Detection using Isolation Forest.
    Detects structural deviations from normal behavior based on graph features.
    """
    def __init__(self, contamination=0.1):
        self.logger = logging.getLogger("AnomalyDetector")
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False

    def train(self, feature_matrix):
        """
        Trains the Isolation Forest model on historical feature data.
        feature_matrix: List of feature vectors (e.g. [[in_degree, out_degree, ...], ...])
        """
        if not feature_matrix or len(feature_matrix) == 0:
            self.logger.warning("No data provided for training.")
            return

        try:
            # Scale features
            scaled_features = self.scaler.fit_transform(feature_matrix)
            
            # Train model
            self.model.fit(scaled_features)
            self.is_trained = True
            self.logger.info("Anomaly detection model trained successfully.")
            
        except Exception as e:
            self.logger.error(f"Error training anomaly model: {e}")

    def score(self, feature_vector):
        """
        Returns a normalized anomaly score between 0 and 1.
        Higher score = more anomalous.
        """
        if not self.is_trained:
            self.logger.warning("Model not trained using default score 0.5")
            # Return neutral score if not strictly required to block
            return 0.5

        try:
            # Reshape for single sample
            vector = np.array(feature_vector).reshape(1, -1)
            scaled_vector = self.scaler.transform(vector)
            
            # decision_function returns score: positive (normal) to negative (anomalous)
            # range is roughly -0.5 to 0.5 depending on implementation details
            raw_score = self.model.decision_function(scaled_vector)[0]
            
            # Normalize to [0, 1] where 1 is highly anomalous (very negative raw score)
            # The decision function has an offset (default 0), values < 0 are anomalies.
            # Typical range might be [-0.5, 0.5].
            # We want to map:
            #   Positive values (normal) -> Low risk (close to 0)
            #   Negative values (anomalous) -> High risk (close to 1)
            
            # Sigmoid-like transformation or simple min-max logic
            # Let's use specific logic: invert and scale
            # Max possible anomaly is usually around -0.5 -> We want 1.0
            # Max normality is around 0.5 -> We want 0.0
            
            # Simple linear mapping:
            # score = 0.5 - raw_score
            # If raw_score = 0.5 (very normal) -> 0.0
            # If raw_score = -0.5 (very anomalous) -> 1.0
            # If raw_score = 0 (boundary) -> 0.5
            
            score = 0.5 - raw_score
            
            # Clamp to [0, 1]
            return max(0.0, min(1.0, score))

        except Exception as e:
            self.logger.error(f"Error scoring anomaly: {e}")
            return 0.5

    def save_model(self, filepath):
        """
        Saves the trained model and scaler to a .pkl file.
        """
        if not self.is_trained:
            self.logger.warning("Cannot save untrained model.")
            return

        try:
            directory = os.path.dirname(filepath)
            if not os.path.exists(directory):
                os.makedirs(directory)
                
            data = {
                'model': self.model,
                'scaler': self.scaler,
                'is_trained': self.is_trained
            }
            joblib.dump(data, filepath)
            self.logger.info(f"Model saved to {filepath}")
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")

    def load_model(self, filepath):
        """
        Loads the trained model and scaler from a .pkl file.
        """
        if not os.path.exists(filepath):
            self.logger.warning(f"Model file not found: {filepath}")
            return False

        try:
            data = joblib.load(filepath)
            self.model = data['model']
            self.scaler = data['scaler']
            self.is_trained = data.get('is_trained', True)
            self.logger.info(f"Model loaded from {filepath}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False
