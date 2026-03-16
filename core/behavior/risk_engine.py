
import logging
import os
from .graph_engine import BehaviorGraph
from .anomaly import AnomalyDetector
from .drift import DriftDetector

class RiskScoringEngine:
    """
    Orchestrates the behavioral risk analysis components and computes the final 
    Behavioral Risk Index (BRI).
    """
    def __init__(self):
        self.logger = logging.getLogger("RiskScoringEngine")
        self.graph_engine = BehaviorGraph()
        self.anomaly_detector = AnomalyDetector()
        self.drift_detector = DriftDetector()
        
        # Weights
        self.W_DRIFT = 0.3
        
        # Paths
        self.data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'behavior')
        self.model_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'models', 'behavior')
        
        self.graph_path = os.path.join(self.data_dir, 'graph_data.json')
        self.model_path = os.path.join(self.model_dir, 'anomaly_model.pkl')
        
        # Load state
        self.load_state()

    def load_state(self):
        """Loads graph and models from disk."""
        self.graph_engine.load_graph(self.graph_path)
        self.anomaly_detector.load_model(self.model_path)

    def save_state(self):
        """Saves graph and models to disk."""
        self.graph_engine.save_graph(self.graph_path)
        # Anomaly model is saved within analyze_entity after training, 
        # but we can expose a method if needed.

    def process_event(self, source, target, timestamp):
        """
        Ingests a new event into the graph.
        """
        self.graph_engine.add_event(source, target, timestamp)
        # Auto-save for every event is expensive, but for "not empty folder" req, 
        # let's save. In prod, use a counter or timer.
        # For now, we will assume the caller might call save_state, 
        # OR we force save here to ensure compliance with user request.
        # Let's simple-save.
        self.save_state()

    def analyze_entity(self, entity_id):
        """
        Performs full risk analysis for a specific entity.
        Returns a structured dictionary with scores and explanation.
        """
        # 1. Graph Features
        features = self.graph_engine.get_node_features(entity_id)
        # Compute a simplified "Graph Score" based on centrality for risk (e.g., high pagerank = high influence/risk potential?)
        # For this implementation, let's assume "Graph Score" is a composite of the normalized features
        # or maybe we use the anomaly score as the primary indicator and graph score is just structural importance?
        # User prompt says: "0.4 * Graph Score". 
        # Usually Graph Score implies how 'central' or 'active' the node is.
        # Let's take average of centrality metrics as Graph Score [0,1].
        graph_score = sum(features) / len(features) if features else 0.0

        # 2. Anomaly Score
        # We need to train the model first on available data if not trained
        # In a real system, training happens offline. Here we might need to lazy-train or mock it.
        # Let's assume pre-trained or train on current graph features if needed.
        if not self.anomaly_detector.is_trained:
            # Quick train on current graph (for demo/adaptive purposes)
            all_features = list(self.graph_engine.compute_features().values())
            feature_matrix = [[f["in_degree"], f["out_degree"], f["betweenness"], f["pagerank"], f["clustering"]] for f in all_features]
            if len(feature_matrix) > 5: # Min samples
                self.anomaly_detector.train(feature_matrix)
                self.anomaly_detector.save_model(self.model_path)
        
        anomaly_score = self.anomaly_detector.score(features)

        # 3. Drift Score
        # We need to update baseline with current metrics first? 
        # Or compare current vs history.
        # Let's assume 'features' are the current metrics.
        # Map list to dict for drift detector
        current_metrics = {
            "in_degree": features[0],
            "out_degree": features[1],
            "betweenness": features[2],
            "pagerank": features[3],
            "clustering": features[4]
        }
        # Compute drift BEFORE updating baseline (to catch the change)
        drift_score = self.drift_detector.compute_drift(entity_id, current_metrics)
        
        # Update baseline for next time
        self.drift_detector.update_baseline(entity_id, current_metrics)

        # 4. Behavioral Risk Index (BRI)
        bri = (self.W_GRAPH * graph_score) + \
              (self.W_ANOMALY * anomaly_score) + \
              (self.W_DRIFT * drift_score)
              
        # 5. Risk Category
        if bri < 0.3:
            risk_level = "Low"
            risk_color = "Green"
        elif bri < 0.6:
            risk_level = "Medium"
            risk_color = "Orange"
        elif bri < 0.8:
            risk_level = "High"
            risk_color = "Red"
        else:
            risk_level = "Critical"
            risk_color = "DarkRed"

        # 6. Explanation
        explanation = self._generate_explanation(entity_id, graph_score, anomaly_score, drift_score, current_metrics)

        return {
            "entity_id": entity_id,
            "graph_score": round(graph_score, 4),
            "anomaly_score": round(anomaly_score, 4),
            "drift_score": round(drift_score, 4),
            "behavioral_risk_index": round(bri, 4),
            "risk_level": risk_level,
            "risk_color": risk_color,
            "explanation": explanation
        }

    def _generate_explanation(self, entity_id, graph_score, anomaly_score, drift_score, current_metrics):
        """
        Generates a human-readable explanation for the risk score.
        """
        factors = []
        if graph_score > 0.5:
            factors.append(f"High structural centrality ({graph_score:.2f})")
        if anomaly_score > 0.5:
            factors.append(f"Statistically anomalous behavior ({anomaly_score:.2f})")
        if drift_score > 0.5:
            factors.append(f"Significant behavioral drift ({drift_score:.2f})")
            
        top_metric = max(current_metrics, key=current_metrics.get)
        
        msg = f"Entity {entity_id} is classified as {self._get_risk_level_name(graph_score, anomaly_score, drift_score)}."
        if factors:
            msg += " Key factors: " + ", ".join(factors) + "."
        msg += f" Top metric: {top_metric}."
        
        return msg

    def _get_risk_level_name(self, g, a, d):
        bri = (self.W_GRAPH * g) + (self.W_ANOMALY * a) + (self.W_DRIFT * d)
        if bri < 0.3: return "Low Risk"
        if bri < 0.6: return "Medium Risk"
        if bri < 0.8: return "High Risk"
        return "Critical Risk"
