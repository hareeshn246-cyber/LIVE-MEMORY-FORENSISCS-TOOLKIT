
import logging
import statistics
import time

class DriftDetector:
    """
    Detects temporal drift in behavioral metrics by comparing current observations
    against a historical baseline using Z-scores.
    """
    def __init__(self, window_size=50):
        self.logger = logging.getLogger("DriftDetector")
        self.window_size = window_size
        self.history = {} # Maps entity_id -> {metric_name: [values]}

    def update_baseline(self, entity_id, metrics):
        """
        Updates the historical baseline for an entity with new metric values.
        metrics: Dictionary of metric_name -> value
        """
        if entity_id not in self.history:
            self.history[entity_id] = {}

        for metric_name, value in metrics.items():
            if metric_name not in self.history[entity_id]:
                self.history[entity_id][metric_name] = []
            
            self.history[entity_id][metric_name].append(value)
            
            # Maintain sliding window
            if len(self.history[entity_id][metric_name]) > self.window_size:
                self.history[entity_id][metric_name].pop(0)

    def compute_drift(self, entity_id, current_metrics):
        """
        Computes the drift score for an entity based on current metrics vs history.
        Drift Score = Average of normalized Z-scores for each metric.
        Returns a float between 0.0 and 1.0.
        """
        if entity_id not in self.history:
            # No history, can't compute drift. Return neutral/low score.
            return 0.0

        drift_scores = []
        
        for metric_name, current_val in current_metrics.items():
            history_vals = self.history[entity_id].get(metric_name, [])
            
            if len(history_vals) < 2:
                continue # Need at least 2 points for stdev
            
            avg = statistics.mean(history_vals)
            std = statistics.stdev(history_vals)
            
            if std == 0:
                if current_val == avg:
                    z_score = 0.0
                else:
                    z_score = 1.0 # Significant deviation if variance usually 0
            else:
                z_score = abs(current_val - avg) / std
                
            # Normalize Z-score to [0, 1]
            # Z-score > 3 is typically considered an outlier.
            # Map [0, 3] -> [0, 1]
            normalized_score = min(z_score / 3.0, 1.0)
            drift_scores.append(normalized_score)
            
        if not drift_scores:
            return 0.0
            
        # Overall drift is average of individual metric drifts
        avg_drift = sum(drift_scores) / len(drift_scores)
        return avg_drift
