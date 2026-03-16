"""
Script to train the Isolation Forest Anomaly Model
Captures features from ALL currently running processes to create a 'Normal' baseline.
"""

import sys
import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import numpy as np

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.acquisition import MemoryAcquisition
from core.lifecycle import EvidenceManager
from detection.yara_engine import YARAEngine
from detection.feature_extractor import FeatureExtractor
from detection.anomaly_detector import AnomalyDetector
from config import MIN_PROCESS_MEMORY_MB, MAX_ANALYSIS_SIZE_MB

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("TrainAnomaly")

def get_process_features(proc, yara_engine, feature_extractor, evidence_mgr):
    """Extract features for a single process"""
    pid = proc['pid']
    name = proc['name']
    
    try:
        # Acquire
        # We need a temp path
        import tempfile
        from pathlib import Path
        temp_dir = Path(tempfile.gettempdir()) / "aura_train"
        temp_dir.mkdir(exist_ok=True)
        dump_path = temp_dir / f"{name}_{pid}.dmp"
        
        acq = MemoryAcquisition()
        try:
             # Fast acquisition (skip large dumps for training speed if needed, but we want full picture)
             # Actually, for training we can skip very large ones to avoid OOM
             if proc.get('memory_mb', 0) > 500: # Limit to 500MB for training speed
                 return None
                 
             acq.acquire_process_memory(pid, dump_path)
        except Exception:
            return None
            
        if not dump_path.exists():
            return None
            
        # Extract matches stats (we can skip full scan for speed and just use empty yara result if we trust system)
        # BUT Isolation Forest needs real feature distribution. We MUST scan.
        # We'll use a dummy YARA result to speed up if YARA is the bottleneck? 
        # No, features depend on YARA matches count. We must scan.
        
        # Meta
        meta = evidence_mgr.create_evidence_metadata(dump_path, {'name': name, 'pid': pid})
        
        # Scan (Timeout fast)
        yara_res = yara_engine.scan_memory_dump(dump_path, meta)
        
        # Features
        features = feature_extractor.extract_features(dump_path, yara_res, {'hooks_detected': []})
        
        # Vectorize
        if 'error' not in features:
            vector = feature_extractor.export_for_ml(features)
        else:
            vector = None
            
        # Cleanup
        try:
            dump_path.unlink()
        except:
            pass
            
        return vector

    except Exception as e:
        logger.warning(f"Failed to process {pid}: {e}")
        return None

def train_from_csv(csv_path: str, detector: AnomalyDetector):
    """Train model from CSV dataset"""
    try:
        import pandas as pd
        logger.info(f"Loading training data from {csv_path}...")
        df = pd.read_csv(csv_path)
        
        # 1. Check for CIC-MalMem-2022 features
        if 'pslist.nproc' in df.columns or 'dlllist.ndlls' in df.columns:
            logger.info("Detected CIC-MalMem-2022 Dataset Schema.")
            logger.info("Mapping CIC features to tool's 27 native features...")
            
            # Filter Benign
            if 'Class' in df.columns:
                df = df[df['Class'] == 'Benign']
            
            # Feature Schema (Must match feature_extractor.py order!)
            # 27 Features
            tool_features = [
                # Signature (3)
                'is_signature_match', 'total_detections', 'matched_rule_count',
                # Integrity (3)
                'is_compromised', 'hooks_detected', 'clean_functions',
                # Behavioral (7)
                'suspicious_apis', 'has_network_activity', 'network_pattern_count', 'has_registry_activity',
                'url_count', 'ip_count', 'file_path_count',
                # Statistical (4)
                'entropy', 'null_ratio', 'printable_ratio', 'unique_bytes',
                # PE (10)
                'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
                'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
                'AddressOfEntryPoint', 'ImageBase', 'DllCharacteristics'
            ]
            
            # Initialize empty DF with correct columns
            X_df = pd.DataFrame(0.0, index=range(len(df)), columns=tool_features)
            
            # --- Map Available Features from CIC ---
            # Using proxies where direct match isn't available
            
            # Signature
            # malfind.ninjections -> is_signature_match proxy
            if 'malfind.ninjections' in df.columns:
                X_df['is_signature_match'] = (df['malfind.ninjections'] > 0).astype(int)
                X_df['total_detections'] = df['malfind.ninjections']
                X_df['matched_rule_count'] = df['malfind.uniqueInjections']
            
            # Integrity
            # ldrmodules.not_in_load -> hooks proxy
            if 'ldrmodules.not_in_load' in df.columns:
                X_df['is_compromised'] = (df['ldrmodules.not_in_load'] > 0).astype(int)
                X_df['hooks_detected'] = df['ldrmodules.not_in_load']
                X_df['clean_functions'] = 50 - df['ldrmodules.not_in_load'] # Assumption
            
            # Behavioral
            # handles.nmutant + nsection -> suspicious apis proxy
            if 'handles.nmutant' in df.columns:
                 X_df['suspicious_apis'] = df['handles.nmutant'] + df.get('handles.nsection', 0)
            
            # Network
            if 'handles.nport' in df.columns:
                X_df['has_network_activity'] = (df['handles.nport'] > 0).astype(int)
                X_df['network_pattern_count'] = df['handles.nport']
            
            # Registry
            if 'handles.nkey' in df.columns:
                X_df['has_registry_activity'] = (df['handles.nkey'] > 0).astype(int)
                
            # Statistical
            # CIC lacks entropy/bytes, use placeholders derived from other metrics
            if 'dlllist.avg_dlls_per_proc' in df.columns:
                # Synthetic entropy proxy
                X_df['entropy'] = (df['dlllist.avg_dlls_per_proc'] / 100) + 4.0 
            
            if 'pslist.avg_threads' in df.columns:
                X_df['unique_bytes'] = df['pslist.avg_threads'] * 10
            
            # Train on mapped features
            logger.info(f"Training on {len(df)} benign samples (Mapped 55->27 features)...")
            X = X_df.values
            
            result = detector.train_model(X.tolist())
            if result.get('status') == 'success':
                logger.info("Training from CIC Dataset Complete!")
                return True
                
        # 2. Check for Native Tool Features
        required_features = [
            'signature_match', 'yara_detection_count', 'matched_rule_count',
            'is_hooked', 'hook_count', 'clean_functions',
            'suspicious_api_refs', 'has_network_activity', 'network_pattern_count', 'has_registry_activity',
            'url_count', 'ip_count', 'file_path_count',
            'entropy', 'null_ratio', 'printable_ratio', 'unique_bytes',
            'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
            'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
            'AddressOfEntryPoint', 'ImageBase', 'DllCharacteristics'
        ]
        
        available_cols = [c for c in required_features if c in df.columns]
        
        if len(available_cols) >= len(required_features) * 0.5:
            # Native Schema
            logger.info("Detected Native Tool Dataset Schema.")
            
            if 'is_malicious' in df.columns:
                df = df[df['is_malicious'] == 0]
                
            logger.info(f"Training on {len(df)} benign samples (Native schema)...")
            X = df[available_cols].fillna(0).values
            
            result = detector.train_model(X.tolist())
            if result.get('status') == 'success':
                logger.info("Training from Native Dataset Complete!")
                return True
        else:
            logger.error("Dataset matches neither CIC-MalMem-2022 nor Native schema.")
            return False
            
    except Exception as e:
        logger.error(f"CSV Training failed: {e}")
        import traceback
        traceback.print_exc()
        
    return False

def main():
    logger.info("Starting Anomaly Model Training...")
    
    detector = AnomalyDetector()
    
    # 1. Try CSV Training first
    from config import DATA_DIR, DATA_RAW_DIR
    csv_candidates = [
        DATA_RAW_DIR / "Obfuscated-MalMem2022.csv",
        DATA_DIR / "Obfuscated-MalMem2022.csv",
        DATA_DIR / "dataset.csv",
        DATA_DIR / "dataset_template.csv" # Fallback to template if it has data
    ]
    
    for csv_path in csv_candidates:
        if csv_path.exists():
            # Check if it has enough data (template might be empty)
            if csv_path.stat().st_size > 1000: 
                if train_from_csv(str(csv_path), detector):
                    return
    
    logger.info("No valid training CSV found. Initializing LIVE system capture...")
    logger.info("Snapshotting system processes to build 'Normal' baseline.")
    
    # 2. Live System Capture
    acq = MemoryAcquisition()
    processes = acq.get_process_list()
    logger.info(f"Refrence processes found: {len(processes)}")
    
    # Extract Features (Parallel)
    vectors = []
    
    # Init engines once
    yara_engine = YARAEngine()
    feature_extractor = FeatureExtractor()
    evidence_mgr = EvidenceManager()
    
    # Use max 4 workers to prevent System lag
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for p in processes:
            futures.append(executor.submit(get_process_features, p, yara_engine, feature_extractor, evidence_mgr))
            
        for i, future in enumerate(as_completed(futures)):
            vec = future.result()
            if vec:
                vectors.append(vec)
            if i % 10 == 0:
                print(f"Processed {i}/{len(processes)}...", end='\r')
                
    logger.info(f"\nSuccessfully extracted {len(vectors)} feature vectors.")
    
    if len(vectors) < 10:
        logger.error("Not enough data points to train model (Need > 10).")
        return
        
    # Train Model
    result = detector.train_model(vectors)
    
    if result.get('status') == 'success':
        logger.info("Training Complete!")
        logger.info(f"Model saved to: {result['path']}")
    else:
        logger.error(f"Training Failed: {result.get('message')}")

if __name__ == "__main__":
    main()
