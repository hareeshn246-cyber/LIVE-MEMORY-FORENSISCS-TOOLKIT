
import sys
import os
import random
import time
import json
import logging

# Ensure project root is in path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TestRiskSystem")

try:
    from core.behavior.risk_engine import RiskScoringEngine
    from core.behavior.anomaly import AnomalyDetector
except ImportError as e:
    logger.error(f"Import failed: {e}")
    sys.exit(1)

def run_test():
    logger.info("Initializing Risk Scoring Engine...")
    engine = RiskScoringEngine()
    
    # 1. Simulate Historical Normal Behavior
    logger.info("Simulating historical behavior (Training Phase)...")
    users = ["User_A", "User_B", "User_C", "User_D", "User_E"]
    resources = ["File_Server", "Database", "Email_Gateway", "HR_Portal"]
    
    # Generate random graph for training
    for _ in range(200):
        u = random.choice(users)
        r = random.choice(resources)
        # Normal pattern: Users mostly access specific resources
        if u == "User_A" and r == "File_Server":
            pass # Frequent
        elif u == "User_B" and r == "Database":
            pass # Frequent
        else:
            if random.random() > 0.8: continue # Rare random access
            
        engine.process_event(u, r, time.time())
        
    # Analyze to trigger "training" / baseline update
    for u in users:
        engine.analyze_entity(u)
        
    logger.info("Historical baseline established.")
    
    # Save the model
    # We can access the anomaly detector directly for testing persistence
    model_path = os.path.join(project_root, "models", "behavior", "test_anomaly_model.pkl")
    engine.anomaly_detector.save_model(model_path)
    
    # 2. Simulate Attack / Anomaly
    logger.info("Simulating attack behavior (Anomalous Phase)...")
    attacker = "User_A" # Compromised account
    
    # Sudden spike in activity to many targets (Out-degree anomaly + Drift)
    targets = ["Admin_Portal", "Backup_Server", "DC_01", "Finance_DB", "Shadow_Copy"]
    
    for t in targets:
        engine.process_event(attacker, t, time.time())
        # Repeat to increase weight/intensity
        engine.process_event(attacker, t, time.time())

    # 3. Analyze and Output
    logger.info(f"Analyzing target entity: {attacker}")
    result = engine.analyze_entity(attacker)
    
    print("\n" + "="*50)
    print("   BEHAVIORAL RISK INTELLIGENCE REPORT   ")
    print("="*50)
    print(json.dumps(result, indent=4))
    print("="*50 + "\n")
    
    # Validation
    if result["risk_level"] in ["High", "Critical"]:
        logger.info("SUCCESS: Attack behavior correctly classified as High/Critical Risk.")
    else:
        logger.warning(f"WARNING: Attack behavior classified as {result['risk_level']}. Model might need tuning.")
        
    # Verify persistence files
    graph_path = os.path.join(project_root, "data", "behavior", "graph_data.json")
    model_path = os.path.join(project_root, "models", "behavior", "anomaly_model.pkl")
    
    if os.path.exists(graph_path):
        logger.info(f"SUCCESS: Graph data persisted at {graph_path}")
    else:
        logger.error(f"FAILURE: Graph data not found at {graph_path}")
        
    if os.path.exists(model_path):
        logger.info(f"SUCCESS: Model file persisted at {model_path}")
    else:
        logger.error(f"FAILURE: Model file not found at {model_path}")

    # Test Reload
    logger.info("Testing auto-load on restart...")
    engine2 = RiskScoringEngine()
    if engine2.graph_engine.graph.number_of_nodes() > 0:
        logger.info(f"SUCCESS: Graph reloaded with {engine2.graph_engine.graph.number_of_nodes()} nodes.")
    else:
        logger.error("FAILURE: Graph failed to reload.")

if __name__ == "__main__":
    run_test()
