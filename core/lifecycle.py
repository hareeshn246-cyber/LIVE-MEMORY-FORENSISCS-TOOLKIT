"""
Evidence Lifecycle Management Module
Handles hashing, timestamping, and AUTOMATED secure deletion of RAW memory dumps
Manages retention of JSON artifacts
"""

import os
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class NumpyEncoder(json.JSONEncoder):
    """Custom encoder for NumPy data types"""
    def default(self, obj):
        import numpy as np
        if isinstance(obj, (np.int_, np.intc, np.intp, np.int8,
                            np.int16, np.int32, np.int64, np.uint8,
                            np.uint16, np.uint32, np.uint64)):
            return int(obj)
        elif isinstance(obj, (np.float_, np.float16, np.float32, np.float64)):
            return float(obj)
        elif isinstance(obj, (np.bool_)):
            return bool(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return json.JSONEncoder.default(self, obj)

class EvidenceManager:
    """
    Manages the lifecycle of forensic evidence
    - Hashes and timestamps RAW memory dumps
    - Securely deletes RAW dumps after YARA analysis
    - Retains JSON artifacts for long-term analysis
    """
    
    def __init__(self):
        from config import (
            STORAGE_RAW_TEMP_DIR,
            STORAGE_ARTIFACTS_DIR,
            SECURE_DELETE_PASSES
        )
        self.raw_temp_dir = STORAGE_RAW_TEMP_DIR
        self.artifacts_dir = STORAGE_ARTIFACTS_DIR
        self.secure_passes = SECURE_DELETE_PASSES
    
    def compute_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """
        Compute cryptographic hash of file
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, sha1, md5)
            
        Returns:
            Hex digest of hash
        """
        hash_func = hashlib.new(algorithm)
        
        try:
            with open(file_path, 'rb') as f:
                # Read in 64KB chunks for large files
                while chunk := f.read(65536):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
            
        except Exception as e:
            logger.error(f"Error computing hash for {file_path}: {e}")
            return ""
    
    def create_evidence_metadata(self, raw_dump_path: Path, process_info: Dict) -> Dict:
        """
        Create metadata record for RAW memory dump
        
        Args:
            raw_dump_path: Path to raw memory dump
            process_info: Dictionary containing process details
            
        Returns:
            Metadata dictionary with hashes and timestamps
        """
        metadata = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'process_name': process_info.get('name', 'unknown'),
            'pid': process_info.get('pid', 0),
            'raw_dump_path': str(raw_dump_path),
            'file_size_bytes': os.path.getsize(raw_dump_path),
            'file_size_mb': round(os.path.getsize(raw_dump_path) / (1024 * 1024), 2),
            'hashes': {
                'sha256': self.compute_hash(raw_dump_path, 'sha256'),
                'sha1': self.compute_hash(raw_dump_path, 'sha1'),
                'md5': self.compute_hash(raw_dump_path, 'md5')
            },
            'status': 'active',
            'deletion_status': 'pending'
        }
        
        logger.info(f"Created evidence metadata for {raw_dump_path.name}")
        logger.info(f"SHA256: {metadata['hashes']['sha256']}")
        
        return metadata
    
    def secure_delete(self, file_path: Path) -> bool:
        """
        Securely delete file using DoD 5220.22-M standard
        Performs multiple overwrite passes before deletion
        
        Args:
            file_path: Path to file to securely delete
            
        Returns:
            True if deletion successful, False otherwise
        """
        if not file_path.exists():
            logger.warning(f"File {file_path} does not exist, cannot delete")
            return False
        
        try:
            file_size = os.path.getsize(file_path)
            
            logger.info(f"Starting secure deletion of {file_path.name} ({self.secure_passes} passes)")
            
            # Perform multiple overwrite passes
            with open(file_path, 'r+b') as f:
                for pass_num in range(self.secure_passes):
                    f.seek(0)
                    
                    # Pass 1: Write 0x00
                    if pass_num == 0:
                        f.write(b'\x00' * file_size)
                    # Pass 2: Write 0xFF
                    elif pass_num == 1:
                        f.write(b'\xFF' * file_size)
                    # Pass 3: Write random data
                    else:
                        f.write(os.urandom(file_size))
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally, delete the file
            os.remove(file_path)
            
            logger.info(f"Successfully securely deleted {file_path.name}")
            return True
            
        except Exception as e:
            logger.error(f"Error during secure deletion: {e}")
            return False

    def save_artifact(self, artifact_data: Dict, process_name: str, pid: int) -> Path:
        """
        Save JSON artifact to permanent storage
        
        Args:
            artifact_data: Dictionary containing behavioral indicators
            process_name: Name of analyzed process
            pid: Process ID
            
        Returns:
            Path to saved artifact
        """
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        artifact_path = self.artifacts_dir / f"{process_name}_{pid}_{timestamp}.json"
        
        # Add retention metadata
        artifact_data['artifact_metadata'] = {
            'created': datetime.utcnow().isoformat() + 'Z',
            'process_name': process_name,
            'pid': pid,
            'artifact_type': 'behavioral_indicators',
            'version': '1.0'
        }
        
        try:
            with open(artifact_path, 'w', encoding='utf-8') as f:
                json.dump(artifact_data, f, indent=2, cls=NumpyEncoder)
            
            logger.info(f"Saved JSON artifact to {artifact_path}")
            return artifact_path
            
        except Exception as e:
            logger.error(f"Error saving artifact: {e}")
            raise
    
    def link_evidence(self, raw_metadata: Dict, artifact_path: Path) -> Dict:
        """
        Create bidirectional link between RAW dump metadata and JSON artifact
        
        Args:
            raw_metadata: Metadata from RAW dump
            artifact_path: Path to JSON artifact
            
        Returns:
            Complete evidence chain record
        """
        evidence_chain = {
            'raw_dump': {
                'path': raw_metadata.get('raw_dump_path'),
                'sha256': raw_metadata.get('hashes', {}).get('sha256'),
                'timestamp': raw_metadata.get('timestamp'),
                'deletion_status': 'pending'
            },
            'artifact': {
                'path': str(artifact_path),
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            },
            'process': {
                'name': raw_metadata.get('process_name'),
                'pid': raw_metadata.get('pid')
            }
        }
        
        return evidence_chain
    
    def cleanup_old_artifacts(self, retention_days: int) -> int:
        """
        Remove JSON artifacts older than retention period
        
        Args:
            retention_days: Number of days to retain artifacts
            
        Returns:
            Number of artifacts deleted
        """
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        deleted_count = 0
        
        for artifact_file in self.artifacts_dir.glob('*.json'):
            try:
                # Check file modification time
                mtime = datetime.fromtimestamp(os.path.getmtime(artifact_file))
                
                if mtime < cutoff_date:
                    os.remove(artifact_file)
                    deleted_count += 1
                    logger.info(f"Deleted expired artifact: {artifact_file.name}")
            
            except Exception as e:
                logger.error(f"Error deleting {artifact_file}: {e}")
        
        return deleted_count
    
    def automated_raw_wipe(self, raw_dump_path: Path, metadata: Dict) -> Dict:
        """
        AUTOMATED: Securely delete RAW dump after YARA analysis
        This is called automatically by yara_engine.py
        
        Args:
            raw_dump_path: Path to RAW memory dump
            metadata: Evidence metadata dictionary
            
        Returns:
            Updated metadata with deletion status
        """
        logger.info(f"AUTO-WIPE: Initiating secure deletion of {raw_dump_path.name}")
        
        success = self.secure_delete(raw_dump_path)
        
        metadata['deletion_status'] = 'completed' if success else 'failed'
        metadata['deletion_timestamp'] = datetime.utcnow().isoformat() + 'Z'
        metadata['status'] = 'archived' if success else 'error'
        
        return metadata
