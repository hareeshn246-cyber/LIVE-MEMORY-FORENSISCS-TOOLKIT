# Windows Memory Forensics Tool
# Training Script for Machine Learning Model

"""
This script demonstrates how to train the ML classifier
Replace with your actual training data and methodology
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
from pathlib import Path

# Feature names (must match feature_extractor.py)
# Feature names (must match feature_extractor.py)
FEATURE_NAMES = [
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
    # PE Features (Kaggle)
    'Machine',
    'SizeOfOptionalHeader',
    'Characteristics',
    'MajorLinkerVersion',
    'SizeOfCode',
    'SizeOfInitializedData',
    'SizeOfUninitializedData',
    'AddressOfEntryPoint',
    'ImageBase',
    'DllCharacteristics'
]

def load_training_dataset(csv_path: Path):
    """
    Load dataset from CSV
    Matches columns to FEATURE_NAMES
    """
    print(f"Loading dataset from {csv_path}...")
    df = pd.read_csv(csv_path)
    
    # Check if this is CIC-MalMem-2022 dataset
    if 'pslist.nproc' in df.columns and 'Class' in df.columns:
        print(" [!] Detected CIC-MalMem-2022 Dataset format")
        print(" [!] Performing heuristic mapping to tool features...")
        
        # Initialize empty feature frame
        X_df = pd.DataFrame(0.0, index=range(len(df)), columns=FEATURE_NAMES)
        
        # --- Heuristic Mapping ---
        # 1. YARA features <- Malfind (injections)
        # Using malfind.ninjections as proxy for signature matches
        X_df['yara_detection_count'] = df['malfind.ninjections']
        X_df['matched_rule_count'] = df['malfind.uniqueInjections']
        X_df['signature_match'] = (df['malfind.ninjections'] > 0).astype(int)
        
        # 2. Hook features <- LdrModules (hidden/unlinked modules)
        # Using ldrmodules.not_in_load as proxy for hooks
        X_df['hook_count'] = df['ldrmodules.not_in_load']
        X_df['is_hooked'] = (df['ldrmodules.not_in_load'] > 0).astype(int)
        X_df['clean_functions'] = 50 - X_df['hook_count'].clip(upper=50) # Assumption
        
        # 3. Behavioral <- Handles & Callbacks
        X_df['suspicious_api_refs'] = df['handles.nmutant'] + df['handles.nsection']
        X_df['has_network_activity'] = (df['handles.nport'] > 0).astype(int)
        X_df['network_pattern_count'] = df['handles.nport']
        X_df['has_registry_activity'] = (df['handles.nkey'] > 0).astype(int)
        
        # 4. Statistical <- Simulated based on Class
        # Examples: Malware typically has higher entropy.
        # We add some synthetic noise based on the label if we know it, 
        # BUT strictly we shouldn't use label for features. 
        # Since CIC lacks entropy, we'll use a placeholder derived from other complexity metrics
        # e.g. dlllist.avg_dlls_per_proc
        X_df['entropy'] = (df['dlllist.avg_dlls_per_proc'] / 100) + 4.0 
        X_df['unique_bytes'] = (df['pslist.avg_threads'] * 10).clip(upper=255)
        
        X = X_df.values
        
        # Map parameters
        y = df['Class'].map({'Benign': 0, 'Malware': 1}).values
        
        return X, y

    # Standard Loading for Tool-Compatible Datasets
    # Fill missing columns with 0
    X_df = pd.DataFrame(0, index=range(len(df)), columns=FEATURE_NAMES)
    
    # Map available columns
    available_cols = [c for c in df.columns if c in FEATURE_NAMES]
    if available_cols:
        X_df[available_cols] = df[available_cols]
    
    X = X_df.values
    
    # Assume target variable is 'is_malicious' or 'class' or last column
    if 'is_malicious' in df.columns:
        y = df['is_malicious'].values
    elif 'class' in df.columns:
        y = df['class'].values
    else:
        # Fallback: assume last column
        y = df.iloc[:, -1].values
        
    return X, y

def create_dummy_hybrid_dataset(n_samples=1000):
    """Create dummy hybrid dataset for demonstration"""
    np.random.seed(42)
    X = np.random.randn(n_samples, len(FEATURE_NAMES))
    y = np.random.randint(0, 2, n_samples)
    return X, y

def train_model(dataset_path=None):
    """Train the Random Forest classifier"""
    
    if dataset_path and Path(dataset_path).exists():
        X, y = load_training_dataset(Path(dataset_path))
    else:
        print("Using dummy hybrid dataset (No CSV provided)...")
        X, y = create_dummy_hybrid_dataset(n_samples=2000)
    
    print(f"Dataset shape: {X.shape}")
    print(f"Malicious samples: {np.sum(y == 1)}")
    print(f"Benign samples: {np.sum(y == 0)}")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Scale features
    print("\nScaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train classifier
    print("\nTraining Random Forest classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1
    )
    
    clf.fit(X_train_scaled, y_train)
    
    # Evaluate
    print("\nEvaluating model...")
    train_score = clf.score(X_train_scaled, y_train)
    test_score = clf.score(X_test_scaled, y_test)
    
    print(f"Training accuracy: {train_score:.4f}")
    print(f"Testing accuracy: {test_score:.4f}")
    
    # Predictions
    y_pred = clf.predict(X_test_scaled)
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))
    
    # Feature importance
    print("\nTop 10 Important Features:")
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    for i in range(min(10, len(FEATURE_NAMES))):
        idx = indices[i]
        print(f"{i+1}. {FEATURE_NAMES[idx]}: {importances[idx]:.4f}")
    
    # Save model and scaler
    models_dir = Path(__file__).parent.parent / 'models'
    models_dir.mkdir(exist_ok=True)
    
    model_path = models_dir / 'mem_classifier.pkl'
    scaler_path = models_dir / 'scaler.pkl'
    
    print(f"\nSaving model to {model_path}")
    joblib.dump(clf, model_path)
    
    print(f"Saving scaler to {scaler_path}")
    joblib.dump(scaler, scaler_path)
    
    print("\n[SUCCESS] Training complete!")

if __name__ == '__main__':
    import sys
    dataset_arg = sys.argv[1] if len(sys.argv) > 1 else None
    train_model(dataset_arg)
