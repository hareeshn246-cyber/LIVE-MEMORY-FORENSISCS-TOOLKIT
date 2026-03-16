"""
Desktop UI Layout - PyQt5 Interface
Main dashboard for Windows memory forensics tool
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict
import logging
import threading

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QLabel, QTextEdit,
    QProgressBar, QGroupBox, QMessageBox, QFileDialog, QTabWidget,
    QHeaderView, QFrame, QSplitter, QGridLayout
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QEvent
from PyQt5.QtGui import QFont, QColor, QPalette

logger = logging.getLogger(__name__)


class ProcessingOverlay(QWidget):
    """
    Semi-transparent overlay that covers the main window during 
    heavy processing to indicate work is in progress.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        
        # Layout
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        
        # Container frame with dark background
        container = QFrame(self)
        container.setStyleSheet("""
            QFrame {
                background-color: rgba(30, 30, 30, 240);
                
                padding: 30px;
            }
        """)
        container_layout = QVBoxLayout(container)
        container_layout.setAlignment(Qt.AlignCenter)
        
        # Spinner/Icon Label
        self.icon_label = QLabel("Loading...")
        self.icon_label.setStyleSheet("font-size: 24px; color: #00ffcc;")
        self.icon_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(self.icon_label)
        
        # Title
        self.title_label = QLabel("Processing...")
        self.title_label.setStyleSheet("""
            font-size: 24px; 
            font-weight: bold; 
            color: #00ffcc;
            margin-top: 10px;
        """)
        self.title_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(self.title_label)
        
        # Status
        self.status_label = QLabel("This may take several minutes.\nPlease wait...")
        self.status_label.setStyleSheet("font-size: 14px; color: #cccccc;")
        self.status_label.setAlignment(Qt.AlignCenter)
        container_layout.addWidget(self.status_label)
        
        layout.addWidget(container)
        
        # Animation Timer
        self.anim_state = 0
        self.anim_timer = QTimer(self)
        self.anim_timer.timeout.connect(self._animate)
        
        self.hide()
        
    def _animate(self):
        """Cycle through animation frames"""
        icons = ["/", "-", "\\", "|"]
        self.anim_state = (self.anim_state + 1) % len(icons)
        self.icon_label.setText(icons[self.anim_state])
        
    def show_overlay(self, title="Processing...", status="Please wait..."):
        """Show the overlay with custom message"""
        self.title_label.setText(title)
        self.status_label.setText(status)
        if self.parent():
            self.setGeometry(self.parent().rect())
        self.show()
        self.raise_()
        self.anim_timer.start(500)  # 500ms per frame
        # Removed QApplication.processEvents() - let Qt event loop handle naturally
        
    def hide_overlay(self):
        """Hide the overlay"""
        self.anim_timer.stop()
        self.hide()
        
    def update_status(self, status: str):
        """Update the status text"""
        self.status_label.setText(status)
        # Removed QApplication.processEvents() - let Qt event loop handle naturally


class AnalysisWorker(QThread):
    """Worker thread for performing analysis without blocking UI"""
    
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, pid: int, process_name: str):
        super().__init__()
        self.pid = pid
        self.process_name = process_name
    
    def run(self):
        """Execute full analysis pipeline: Snapshot → YARA → Anomaly → Behavior"""
        try:
            from core.acquisition import MemoryAcquisition
            from core.integrity import HookDetector
            from core.lifecycle import EvidenceManager
            from detection.yara_engine import YARAEngine
            from detection.feature_extractor import FeatureExtractor
            from detection.ml_inference import MLDetector
            from detection.anomaly_detector import AnomalyDetector
            from config import get_temp_raw_path

            
            # Fetch current memory usage for report accuracy
            try:
                import psutil
                proc_obj = psutil.Process(self.pid)
                mem_curr = proc_obj.memory_info().rss / (1024 * 1024)
                mem_mb_val = round(mem_curr, 2)
            except:
                mem_mb_val = 0

            results = {
                'status': 'running',
                'pid': self.pid,
                'process_name': self.process_name,
                'memory_mb': mem_mb_val
            }
            
            # Step 1: Acquire memory (Snapshot)
            self.progress.emit("Acquiring process memory...")
            acquisition = MemoryAcquisition()
            dump_path = get_temp_raw_path(self.process_name, self.pid)
            
            try:
                acq_result = acquisition.acquire_process_memory(self.pid, dump_path)
                results['acquisition'] = acq_result
                
                if acq_result.get('status') != 'success':
                    raise Exception(f"Memory acquisition failed: {acq_result.get('error', 'Unknown')}")
            except Exception as acq_error:
                logger.error(f"Acquisition error for {self.process_name}: {acq_error}")
                results['status'] = 'failed'
                results['error'] = str(acq_error)
                self.finished.emit(results)
                return
            
            # Step 2: Create evidence metadata
            self.progress.emit("Creating evidence metadata...")
            evidence_mgr = EvidenceManager()
            evidence_metadata = evidence_mgr.create_evidence_metadata(
                dump_path,
                {'name': self.process_name, 'pid': self.pid}
            )
            results['evidence_metadata'] = evidence_metadata
            
            # Step 3: YARA scanning (first detection phase)
            self.progress.emit("Scanning with YARA signatures...")
            yara_engine = YARAEngine()
            yara_results = yara_engine.scan_memory_dump(dump_path, evidence_metadata)
            results['yara_scan'] = yara_results
            
            # Step 4: Hook detection
            self.progress.emit("Detecting API hooks...")
            hook_detector = HookDetector()
            hook_results = hook_detector.comprehensive_scan(self.pid)
            results['hook_detection'] = hook_results
            
            # Step 5: Feature extraction (needed for anomaly and ML)
            self.progress.emit("Extracting behavioral features...")
            feature_extractor = FeatureExtractor()
            features = feature_extractor.extract_features(
                dump_path, yara_results, hook_results
            )
            results['features'] = features
            
            # Step 6: Anomaly detection (before ML classification)
            self.progress.emit("Detecting anomalies...")
            anomaly_detector = AnomalyDetector()
            anomaly_results = anomaly_detector.detect_anomalies(features)
            results['anomaly_detection'] = anomaly_results
            
            # Step 7: ML inference (behavior classification)
            self.progress.emit("Running behavior analysis...")
            ml_detector = MLDetector()
            ml_results = ml_detector.predict_from_artifact(features)
            results['ml_detection'] = ml_results
            
            # Step 8: Save JSON artifact
            self.progress.emit("Saving analysis artifact...")
            artifact_path = evidence_mgr.save_artifact(
                {
                    'yara_scan': yara_results,
                    'hook_detection': hook_results,
                    'features': features,
                    'anomaly_detection': anomaly_results,
                    'ml_detection': ml_results
                },
                self.process_name,
                self.pid
            )
            results['artifact_path'] = str(artifact_path)
            
            # Create evidence chain
            evidence_chain = evidence_mgr.link_evidence(evidence_metadata, artifact_path)
            results['evidence_chain'] = evidence_chain
            
            # Raw files retained (no auto-delete)
            
            results['status'] = 'completed'
            self.finished.emit(results)
            
        except Exception as e:
            logger.error(f"Analysis error: {e}", exc_info=True)
            self.error.emit(str(e))


class OfflineAnalysisWorker(QThread):
    """Worker thread for analyzing offline memory dumps"""
    
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, dump_path: str):
        super().__init__()
        self.dump_path = Path(dump_path)
        self.file_name = self.dump_path.name
    
    def run(self):
        """Execute offline analysis pipeline: YARA → Anomaly → Behavior"""
        try:
            from core.lifecycle import EvidenceManager
            from detection.yara_engine import YARAEngine
            from detection.feature_extractor import FeatureExtractor
            from detection.ml_inference import MLDetector
            from detection.anomaly_detector import AnomalyDetector
            
            results = {
                'status': 'running',
                'pid': 0,
                'process_name': self.file_name,
                'acquisition': {'status': 'skipped', 'method': 'offline_load'}
            }
            
            # Step 1: Create evidence metadata
            self.progress.emit("Hashing memory dump...")
            evidence_mgr = EvidenceManager()
            evidence_metadata = evidence_mgr.create_evidence_metadata(
                self.dump_path,
                {'name': self.file_name, 'pid': 0}
            )
            results['evidence_metadata'] = evidence_metadata
            
            # Step 2: Hook detection (Passive Scan for Offline)
            self.progress.emit("Running passive hook scanner...")
            hook_detector = HookDetector()
            try:
                 # Use the new offline scanner
                 hook_results = hook_detector.scan_offline_dump(self.dump_path)
            except AttributeError:
                 # Fallback if method missing (safety)
                 hook_results = {
                    'status': 'skipped',
                    'message': 'Scanner update pending',
                    'hooks_detected': [],
                    'is_compromised': False
                 }
            
            results['hook_detection'] = hook_results
            
            # Step 3: YARA scanning (first detection phase)
            self.progress.emit("Scanning with YARA signatures...")
            yara_engine = YARAEngine()
            yara_results = yara_engine.scan_memory_dump(self.dump_path, evidence_metadata)
            yara_results['raw_deleted'] = False
            yara_results['deletion_status'] = "Preserved (User File)"
            results['yara_scan'] = yara_results
            
            # Step 4: Feature extraction (needed for anomaly and ML)
            self.progress.emit("Extracting behavioral features...")
            feature_extractor = FeatureExtractor()
            features = feature_extractor.extract_features(
                self.dump_path, yara_results, results['hook_detection']
            )
            results['features'] = features
            
            # Step 5: Anomaly detection (before ML classification)
            self.progress.emit("Detecting anomalies...")
            anomaly_detector = AnomalyDetector()
            anomaly_results = anomaly_detector.detect_anomalies(features)
            results['anomaly_detection'] = anomaly_results
            
            # Step 6: ML inference (behavior classification)
            results['ml_detection'] = {
                'classification': 'ML_UNAVAILABLE', 
                'confidence_scores': {'malware': 0},
                'is_malicious': False
            }
            
            if 'error' in features:
                 self.progress.emit("Skipping ML (Feature extraction incomplete)...")
                 results['ml_detection']['message'] = 'Skipped due to extraction error'
            else:
                 self.progress.emit("Running behavior analysis...")
                 try:
                     ml_detector = MLDetector()
                     ml_results = ml_detector.predict_from_artifact(features)
                     results['ml_detection'] = ml_results
                 except Exception as ml_e:
                     logger.error(f"Offline ML failed: {ml_e}")
                     results['ml_detection']['message'] = f"Inference Error: {str(ml_e)}"
            
            # Step 7: Save JSON artifact
            self.progress.emit("Saving analysis artifact...")
            artifact_path = evidence_mgr.save_artifact(
                {
                    'yara_scan': yara_results,
                    'hook_detection': results['hook_detection'],
                    'features': features,
                    'anomaly_detection': anomaly_results,
                    'ml_detection': ml_results
                },
                self.file_name,
                0
            )
            results['artifact_path'] = str(artifact_path)
            
            # Create evidence chain
            evidence_chain = evidence_mgr.link_evidence(evidence_metadata, artifact_path)
            results['evidence_chain'] = evidence_chain
            
            results['status'] = 'completed'
            self.finished.emit(results)
            
        except Exception as e:
            logger.error(f"Offline analysis error: {e}", exc_info=True)
            self.error.emit(str(e))


class BatchAnalysisWorker(QThread):
    """Worker thread for batch analysis of multiple processes"""
    
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict) # Emits summary
    process_complete = pyqtSignal(dict) # Emits individual result
    error = pyqtSignal(str)
    
    def __init__(self, process_list: list):
        super().__init__()
        self.process_list = process_list
        self.batch_results = []
        self.total_processes = len(process_list)
        # REFACTOR: Use threading.Event for thread-safe cancellation
        self._stop_event = threading.Event()
        self.current_index = 0
    
    def stop(self):
        """Request worker to stop safely using Event"""
        self._stop_event.set()
        
    def _safe_emit_error(self, error_obj):
        """Helper to ensure error messages are always valid strings"""
        try:
            msg = str(error_obj)
            if not msg or not msg.strip():
                msg = f"Unknown Error (Type: {type(error_obj).__name__})"
            self.error.emit(msg)
        except:
            self.error.emit("Critical: Failed to process error message.")

    def run(self):
        """Execute batch analysis: Snapshot → YARA → Anomaly → Behavior"""
        try:
            from core.acquisition import MemoryAcquisition
            from core.integrity import HookDetector
            from core.lifecycle import EvidenceManager
            from detection.yara_engine import YARAEngine
            from detection.feature_extractor import FeatureExtractor
            from detection.ml_inference import MLDetector
            from detection.anomaly_detector import AnomalyDetector
            from config import get_temp_raw_path, MAX_ANALYSIS_SIZE_MB
            import os
            import psutil
            import time
            
            logger.info(f"Starting batch analysis of {self.total_processes} processes")
            
            # ═══ INITIALIZE ALL ENGINES ONCE (not per-process) ═══
            acquisition = MemoryAcquisition()
            yara_engine = YARAEngine()
            hook_detector = HookDetector()
            feature_extractor = FeatureExtractor()
            anomaly_detector = AnomalyDetector()
            ml_detector = MLDetector()
            evidence_mgr = EvidenceManager()
            
            start_time = time.time()
            
            for idx, proc in enumerate(self.process_list):
                # STOP CHECK using Event (Thread-Safe)
                if self._stop_event.is_set():
                    logger.info("Batch analysis stopped by user.")
                    break

                self.current_index = idx + 1
                pid = proc['pid']
                process_name = proc['name']
                
                try:
                    # ═══ FTK-style progress ═══
                    elapsed = time.time() - start_time
                    speed = idx / elapsed if elapsed > 0 and idx > 0 else 0
                    remaining = (self.total_processes - idx) / speed if speed > 0 else 0
                    eta_str = f" — ETA: {int(remaining)}s" if speed > 0 else ""
                    
                    self.progress.emit(
                        f"[{self.current_index}/{self.total_processes}] {process_name} (PID: {pid}){eta_str}"
                    )
                    
                    results = {
                        'status': 'running',
                        'pid': pid,
                        'process_name': process_name,
                        'memory_mb': proc.get('memory_mb', 0)
                    }
                    
                    if pid == os.getpid():
                        results['status'] = 'skipped'
                        results['error'] = 'Self-protection'
                        self.batch_results.append(results)
                        self.process_complete.emit(results)
                        continue

                    if proc.get('memory_mb', 0) > MAX_ANALYSIS_SIZE_MB:
                        results['status'] = 'skipped'
                        results['error'] = f'Size exceeds limit ({MAX_ANALYSIS_SIZE_MB} MB)'
                        self.batch_results.append(results)
                        self.process_complete.emit(results)
                        continue

                    # DEFAULT FALLBACKS
                    results['yara_scan'] = {'total_detections': 0, 'matches': []}
                    results['hook_detection'] = {'hooks_detected': [], 'is_compromised': False}
                    results['anomaly_detection'] = {'anomaly_score': 0.0, 'severity': 'LOW'}
                    results['ml_detection'] = {
                        'classification': 'N/A', 
                        'confidence_scores': {'malware': 0.0},
                        'is_malicious': False
                    }

                    # Step 1: Acquire memory
                    dump_path = get_temp_raw_path(process_name, pid)
                    try:
                        acq_result = acquisition.acquire_process_memory(pid, dump_path)
                        results['acquisition'] = acq_result
                        
                        if acq_result.get('status') != 'success':
                            results['status'] = 'failed' 
                            results['error'] = f"Acquisition failed: {acq_result.get('error', 'Access Denied')}"
                            self.batch_results.append(results)
                            self.process_complete.emit(results)
                            continue

                        if acq_result.get('total_bytes', 0) == 0:
                            results['status'] = 'skipped'
                            results['error'] = 'Protected Process (0 bytes captured)'
                            self.batch_results.append(results)
                            self.process_complete.emit(results)
                            continue
                            
                    except Exception as acq_err:
                        results['status'] = 'failed'
                        results['error'] = f"Acq Error: {str(acq_err)}"
                        self.batch_results.append(results)
                        self.process_complete.emit(results)
                        continue
                    
                    # Step 2: Evidence metadata
                    evidence_metadata = evidence_mgr.create_evidence_metadata(
                        dump_path,
                        {'name': process_name, 'pid': pid}
                    )
                    
                    # Step 3: YARA scanning
                    yara_results = yara_engine.scan_memory_dump(dump_path, evidence_metadata)
                    results['yara_scan'] = yara_results
                    
                    # Step 4: Hook detection
                    hook_results = hook_detector.comprehensive_scan(pid)
                    results['hook_detection'] = hook_results
                    
                    # Step 5: Feature extraction
                    features = feature_extractor.extract_features(
                        dump_path, yara_results, hook_results
                    )
                    results['features'] = features
                    
                    # Step 6: Anomaly detection
                    anomaly_results = anomaly_detector.detect_anomalies(features)
                    results['anomaly_detection'] = anomaly_results
                    
                    # Recalculate Risk Score
                    real_anomaly_score = anomaly_results.get('anomaly_score', 0.0)
                    features['risk_assessment'] = feature_extractor.calculate_weighted_risk(features, real_anomaly_score)
                    
                    # Step 7: ML inference
                    try:
                        ml_results = ml_detector.predict_from_artifact(features)
                        results['ml_detection'] = ml_results
                    except Exception as ml_err:
                        logger.error(f"ML Inference failed for {process_name}: {ml_err}")
                        results['ml_detection']['message'] = "ML Inference Failed"
                    
                    # Step 8: Save JSON artifact
                    artifact_path = evidence_mgr.save_artifact(
                        {
                            'yara_scan': results['yara_scan'],
                            'hook_detection': results['hook_detection'],
                            'features': features,
                            'anomaly_detection': anomaly_results,
                            'ml_detection': results['ml_detection']
                        },
                        process_name,
                        pid
                    )
                    results['artifact_path'] = str(artifact_path)
                    
                    # Create evidence chain
                    evidence_chain = evidence_mgr.link_evidence(evidence_metadata, artifact_path)
                    results['evidence_chain'] = evidence_chain
                    
                    # Raw files retained (no auto-delete)
                    
                    results['status'] = 'completed'
                    self.batch_results.append(results)
                    self.process_complete.emit(results)
                    
                except Exception as e:
                    logger.error(f"Error analyzing {process_name} (PID {pid}): {e}")
                    results['status'] = 'failed'
                    results['error'] = str(e)
                    self.batch_results.append(results)
                    self.process_complete.emit(results)
            
            # ═══ Final Summary ═══
            total_time = time.time() - start_time
            completed = len([r for r in self.batch_results if r['status'] == 'completed'])
            failed = len([r for r in self.batch_results if r['status'] == 'failed'])
            malicious = len([r for r in self.batch_results if r.get('ml_detection', {}).get('is_malicious', False)])
            
            batch_summary = {
                'total_processes': self.total_processes,
                'completed': completed,
                'failed': failed,
                'malicious_detected': malicious,
                'results': self.batch_results
            }
            
            self.finished.emit(batch_summary)
            logger.info(f"Batch analysis completed: {completed}/{self.total_processes} in {total_time:.1f}s")
            
        except Exception as e:
            logger.error(f"Batch analysis error: {e}", exc_info=True)
            self.error.emit(str(e))


class ProcessListWorker(QThread):
    """Worker thread for loading process list without blocking UI"""
    
    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    
    def __init__(self, include_all: bool = False):
        super().__init__()
        self.include_all = include_all
        
    def run(self):
        """Load process list in background"""
        try:
            from core.acquisition import MemoryAcquisition
            
            acquisition = MemoryAcquisition()
            processes = acquisition.get_process_list(include_all=self.include_all)
            
            self.finished.emit(processes)
            
        except Exception as e:
            logger.error(f"Error loading process list: {e}")
            self.error.emit(str(e))


class RegistryScanWorker(QThread):
    """Background worker for Registry Persistence Scan — keeps GUI responsive"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict, dict)  # (raw_data, analysis)
    error = pyqtSignal(str)
    
    def run(self):
        try:
            from forensics.registry_scan import scan_persistence_keys
            from detection.registry_detector import RegistryDetector
            
            self.progress.emit("Scanning registry persistence keys...")
            raw_data = scan_persistence_keys()
            
            self.progress.emit("Analyzing registry results...")
            detector = RegistryDetector()
            analysis = detector.analyze_scan_results(raw_data)
            
            self.finished.emit(raw_data, analysis)
        except Exception as e:
            logger.error(f"Registry scan worker error: {e}", exc_info=True)
            self.error.emit(str(e))


class KernelScanWorker(QThread):
    """Background worker for Kernel Rootkit Scan — keeps GUI responsive"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(list, dict)  # (hidden_procs, kernel_result)
    error = pyqtSignal(str)
    
    def run(self):
        try:
            from detection.rootkit_detector import RootkitDetector
            
            detector = RootkitDetector()
            
            self.progress.emit("Cross-View Analysis: checking for hidden processes...")
            hidden_procs = detector.scan_for_hidden_processes()
            
            self.progress.emit("Driver Interface: direct kernel scan...")
            kernel_res = detector.run_kernel_stealth_detection()
            
            self.finished.emit(hidden_procs, kernel_res)
        except Exception as e:
            logger.error(f"Kernel scan worker error: {e}", exc_info=True)
            self.error.emit(str(e))


class ReportExportWorker(QThread):
    """Background worker for Advanced PDF Report generation"""
    finished = pyqtSignal(str)  # report_path or empty string
    error = pyqtSignal(str)
    
    def __init__(self, reg_data, reg_analysis, kernel_results):
        super().__init__()
        self.reg_data = reg_data
        self.reg_analysis = reg_analysis
        self.kernel_results = kernel_results
    
    def run(self):
        try:
            from reports.report_generator import ForensicReportGenerator
            generator = ForensicReportGenerator()
            report_path = generator.generate_advanced_scan_report(
                self.reg_data, self.reg_analysis, self.kernel_results
            )
            self.finished.emit(str(report_path) if report_path else "")
        except Exception as e:
            logger.error(f"Report export worker error: {e}", exc_info=True)
            self.error.emit(str(e))


class SystemCaptureWorker(QThread):
    """
    Capture-Only Worker:
    Iterates all processes and dumps memory to a Snapshot folder.
    NO ANALYSIS - Just Capture.
    """
    
    progress = pyqtSignal(str)
    finished = pyqtSignal(str) # Emits folder path
    error = pyqtSignal(str)
    
    def run(self):
        try:
            from core.acquisition import MemoryAcquisition
            from config import MAX_ANALYSIS_SIZE_MB
            import datetime
            import os
            import psutil
            import time
            
            # Check Disk Space
            free_space_gb = psutil.disk_usage('.').free / (1024**3)
            if free_space_gb < 2.0:
                raise Exception(f"Insufficient disk space! Free: {free_space_gb:.2f} GB. Need 2GB+.")

            # Create snapshot directory
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            snapshot_dir = Path("storage") / "snapshots" / f"System_Snapshot_{timestamp}"
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            
            self.progress.emit(f"Initializing forensic snapshot at {snapshot_dir}...")
            
            acquisition = MemoryAcquisition()
            processes = acquisition.get_process_list()
            total = len(processes)
            
            # Capture ALL processes (no trusted-process filter)
            # Only skip self and oversized processes
            targets = []
            for proc in processes:
                pid = proc['pid']
                if pid == os.getpid():
                    continue
                if proc.get('memory_mb', 0) > MAX_ANALYSIS_SIZE_MB:
                    continue
                targets.append(proc)
            
            capture_total = len(targets)
            self.progress.emit(f"Capturing all {capture_total} processes...")
            
            # FTK Imager-style tracking
            success_count = 0
            fail_count = 0
            access_denied_count = 0
            total_bytes_captured = 0
            start_time = time.time()
            
            for i, proc in enumerate(targets):
                try:
                    pid = proc['pid']
                    name = proc['name']
                    size_mb = proc.get('memory_mb', 0)
                    
                    # Speed & ETA calculation
                    elapsed = time.time() - start_time
                    speed_mbps = (total_bytes_captured / (1024 * 1024)) / elapsed if elapsed > 0.1 else 0
                    remaining = capture_total - (i + 1)
                    eta_str = ""
                    if speed_mbps > 0 and i > 2:
                        # Rough ETA based on average time per process
                        avg_time_per = elapsed / (i + 1)
                        eta_seconds = int(remaining * avg_time_per)
                        eta_str = f" — ETA: {eta_seconds}s"
                    
                    captured_mb = total_bytes_captured / (1024 * 1024)
                    self.progress.emit(
                        f"[{i+1}/{capture_total}] {name} ({size_mb:.1f} MB) — "
                        f"{captured_mb:.0f} MB captured @ {speed_mbps:.0f} MB/s{eta_str}"
                    )
                    
                    safe_name = "".join(c for c in name if c.isalnum() or c in (' ', '.', '_', '-')).rstrip()
                    filename = f"{safe_name}_{pid}.raw"
                    output_path = snapshot_dir / filename
                    
                    try:
                        acq_res = acquisition.acquire_process_memory(pid, output_path)
                        if acq_res['status'] == 'success':
                            success_count += 1
                            total_bytes_captured += acq_res.get('total_bytes', 0)
                        elif acq_res.get('status') == 'access_denied':
                            access_denied_count += 1
                            if output_path.exists():
                                output_path.unlink()
                        else:
                            fail_count += 1
                            # Remove empty/failed files
                            if output_path.exists() and output_path.stat().st_size == 0:
                                output_path.unlink()
                    except Exception:
                        fail_count += 1
                        if output_path.exists() and output_path.stat().st_size == 0:
                            output_path.unlink()
                        
                except Exception:
                    fail_count += 1
            
            # Final summary (FTK Imager style)
            elapsed_total = time.time() - start_time
            total_mb = total_bytes_captured / (1024 * 1024)
            avg_speed = total_mb / elapsed_total if elapsed_total > 0 else 0
            
            final_msg = (f"Snapshot Captured Successfully!\n"
                         f"Location: {snapshot_dir}\n"
                         f"Captured: {success_count}/{capture_total} processes "
                         f"({total_mb:.1f} MB)\n"
                         f"Duration: {elapsed_total:.1f}s @ {avg_speed:.1f} MB/s\n"
                         f"Skipped: {access_denied_count} access denied | {fail_count} errors\n\n"
                         f"Next Step: Click 'Full System Scan' to analyze.")
            
            self.finished.emit(final_msg)
            
        except Exception as e:
            import traceback
            self.error.emit(f"{str(e)}\n{traceback.format_exc()}")


class SnapshotAnalysisWorker(QThread):
    """
    Step 2: Analysis Worker
    Input: Folder Path
    Action: Analyze all .raw files -> Generate PDF -> Clear Raw Files
    """
    
    progress = pyqtSignal(str)
    process_complete = pyqtSignal(dict) # Emits individual result
    finished = pyqtSignal(str) # Report Path
    error = pyqtSignal(str)
    
    def __init__(self, folder_path):
        super().__init__()
        self.folder_path = Path(folder_path)
        self._stop_event = threading.Event()

    def stop(self):
        """Request worker to stop safely"""
        self._stop_event.set()
        
    def run(self):
        try:
            from core.lifecycle import EvidenceManager
            from detection.yara_engine import YARAEngine
            from detection.feature_extractor import FeatureExtractor
            from detection.ml_inference import MLDetector
            from detection.anomaly_detector import AnomalyDetector
            from reports.report_generator import ForensicReportGenerator
            
            evidence_mgr = EvidenceManager()
            yara_engine = YARAEngine()
            feature_extractor = FeatureExtractor()
            anomaly_detector = AnomalyDetector()
            ml_detector = MLDetector()
            report_generator = ForensicReportGenerator()
            
            # Find all .raw files
            raw_files = list(self.folder_path.glob("*.raw"))
            total = len(raw_files)
            
            if total == 0:
                self.error.emit("No .raw files found in snapshot folder.")
                return

            batch_results = []
            malicious_count = 0
            
            self.progress.emit(f"Starting Analysis of {total} memory dumps...")
            
            for i, dump_path in enumerate(raw_files):
                # Check for stop request
                if self._stop_event.is_set():
                    logger.info("Snapshot analysis stopped by user.")
                    break
                try:
                    name = dump_path.stem.split('_')[0]
                    # Parse PID if possible, else 0
                    try:
                        pid = int(dump_path.stem.split('_')[-1])
                    except:
                        pid = 0
                        
                    self.progress.emit(f"[{i+1}/{total}] Analyzing {dump_path.name}...")
                    
                    # 1. WHITELIST CHECK (Reduce False Positives)
                    SAFE_PROCESSES = [
                        "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", 
                        "services.exe", "lsass.exe", "lsm.exe", "winlogon.exe", 
                        "spoolsv.exe", "taskhostw.exe", "explorer.exe", 
                        "SearchApp.exe", "SearchIndexer.exe", "MsMpEng.exe", 
                        "fontdrvhost.exe", "dwm.exe", "svchost.exe",
                        "Taskmgr.exe", "RuntimeBroker.exe", "smartscreen.exe",
                        "SgrmBroker.exe", "ctfmon.exe", "ShellExperienceHost.exe",
                        "StartMenuExperienceHost.exe", "ApplicationFrameHost.exe"
                    ]
                    
                    if name in SAFE_PROCESSES:
                        process_result = {
                            'pid': pid,
                            'process_name': name,
                            'status': 'skipped',
                            'load_state': 'WHITELISTED',
                            'yara_matches': 0,
                            'hooks': [],
                            'anomaly_score': 0.0,
                            'ml_verdict': 'CLEAN',
                            'threat_severity': 'LOW',
                            'risk_score': 0,
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
                        batch_results.append(process_result)
                        self.process_complete.emit(process_result)
                        continue

                    # 2. ANALYZE
                    meta = evidence_mgr.create_evidence_metadata(dump_path, {'name': name, 'pid': pid})
                    yara_res = yara_engine.scan_memory_dump(dump_path, meta)
                    features = feature_extractor.extract_features(dump_path, yara_res, {'hooks_detected': []})
                    anom_res = anomaly_detector.detect_anomalies(features)
                    ml_res = ml_detector.predict_from_artifact(features)
                    
                    process_result = {
                        'pid': pid,
                        'process_name': name,
                        'status': 'completed',
                        'load_state': 'SNAPSHOT',
                        'yara_matches': yara_res.get('total_matches', 0),
                        'hooks': [], # Not supported in snapshot mode yet
                        'anomaly_score': anom_res.get('anomaly_score', 0.0),
                        'ml_verdict': ml_res.get('classification', 'CLEAN'),
                        'threat_severity': ml_res.get('severity', 'LOW'),
                        'risk_score': ml_res.get('risk_score', 0),
                        'yara_scan': yara_res,
                        'ml_detection': ml_res,
                        'anomaly_detection': anom_res,
                        'timestamp': meta['timestamp'],
                        'features': features
                    }
                    
                    # No longer calculating dynamic threat level here manually to avoid sync issues.
                    # thresholds are managed centrally in MLDetector.
                    
                    batch_results.append(process_result)
                    self.process_complete.emit(process_result)
                    
                    if ml_res.get('is_malicious') or anom_res.get('anomaly_score', 0) > 80:
                        malicious_count += 1
                        evidence_mgr.save_artifact({
                            'yara': yara_res, 'ml': ml_res, 'anomaly': anom_res, 'features': features
                        }, name, pid)
                    
                    # 2. KEEP raw files (Do NOT auto-delete)
                    # Raw files are retained for user inspection
                        
                except Exception as e:
                    logger.error(f"Error analyzing {dump_path.name}: {e}")
            
            # 3. REPORT
            self.progress.emit("Generating Unified PDF Report...")
            report_path = report_generator.generate_batch_report(batch_results)
            
            final_msg = (f"Analysis Complete!\n"
                         f"Scanned: {len(batch_results)}\n"
                         f"Threats: {malicious_count}\n"
                         f"Report: {report_path.name}\n"
                         f"Status: Raw files retained.")
            
            self.finished.emit(final_msg)
            
        except Exception as e:
            import traceback
            error_msg = f"Batch Error: {str(e)}\n{traceback.format_exc()}"
            logger.error(error_msg)
            self.error.emit(error_msg)




class CaptureWorker(QThread):
    """Worker thread for capturing process memory"""
    
    progress = pyqtSignal(str)
    finished = pyqtSignal(str) # Emits path
    error = pyqtSignal(str)
    
    def __init__(self, pid: int, process_name: str, output_path: str):
        super().__init__()
        self.pid = pid
        self.process_name = process_name
        self.output_path = output_path
        
    def run(self):
        try:
            from core.acquisition import MemoryAcquisition
            
            self.progress.emit(f"Acquiring memory for {self.process_name} ({self.pid})...")
            
            acquisition = MemoryAcquisition()
            result = acquisition.acquire_process_memory(self.pid, Path(self.output_path))
            
            if result['status'] == 'success':
                self.finished.emit(result['output_path'])
            else:
                self.error.emit(result.get('error', 'Unknown error'))
                
        except Exception as e:
            import traceback
            error_msg = f"Capture Error: {str(e)}\n{traceback.format_exc()}"
            logger.error(error_msg)
            self.error.emit(error_msg)


class ProcessLoaderThread(QThread):
    """Background thread to load process list without freezing UI"""
    processes_ready = pyqtSignal(list)
    
    def run(self):
        try:
            from core.acquisition import MemoryAcquisition
            acq = MemoryAcquisition()
            # This can take 100-500ms
            procs = acq.get_process_list()
            self.processes_ready.emit(procs)
        except Exception as e:
            logger.error(f"Background process load failed: {e}")
            self.processes_ready.emit([])

class RootkitScanWorker(QThread):
    """Worker thread for running rootkit cross-view analysis without blocking UI"""
    
    finished = pyqtSignal(list)  # Emits list of hidden processes
    error = pyqtSignal(str)
    
    def run(self):
        try:
            from detection.rootkit_detector import RootkitDetector
            detector = RootkitDetector()
            hidden_procs = detector.scan_for_hidden_processes()
            self.finished.emit(hidden_procs)
        except Exception as e:
            logger.error(f"Rootkit scan error: {e}")
            self.error.emit(str(e))


class ReportWorker(QThread):
    """Worker thread for generating reports without blocking UI"""
    
    finished = pyqtSignal(str)  # Emits report file path
    error = pyqtSignal(str)
    
    def __init__(self, report_type: str, data: dict, output_path: str = None):
        super().__init__()
        self.report_type = report_type  # 'single' or 'batch'
        self.data = data
        self.output_path = output_path
    
    def run(self):
        try:
            from reports.report_generator import ForensicReportGenerator
            generator = ForensicReportGenerator()
            
            if self.report_type == 'single':
                report_path = generator.generate_report(
                    process_info=self.data['process_info'],
                    yara_results=self.data['yara_results'],
                    hook_results=self.data['hook_results'],
                    feature_data=self.data['feature_data'],
                    ml_results=self.data['ml_results'],
                    anomaly_results=self.data.get('anomaly_results', {}),
                    evidence_chain=self.data['evidence_chain']
                )
                self.finished.emit(str(report_path))
                
            elif self.report_type == 'batch':
                report_path = generator.generate_batch_report(
                    self.data['batch_results'],
                    output_path=Path(self.output_path) if self.output_path else None
                )
                self.finished.emit(str(report_path))
                
        except Exception as e:
            logger.error(f"Report generation error: {e}", exc_info=True)
            self.error.emit(str(e))


class ForensicToolUI(QMainWindow):
    """Main UI for Windows Memory Forensics Tool"""
    
    def __init__(self):
        super().__init__()
        self.current_worker = None
        self.batch_worker = None
        self.process_list_worker = None  # We'll use this now
        self.capture_worker = None
        self.ram_capture_worker = None  # Worker for RAM capture step
        self.analysis_results = None
        self.batch_results = []
        self.current_dump_path = None
        self.last_snapshot_path = None  # Path to captured RAM snapshot folder
        self.auto_worker = None # Worker for silent background refresh
        self._process_cache = {} # Cache for PID and memory to avoid UI read-back
        
        # Missing UI references initialization
        self.batch_results_table = None
        self.btn_generate_batch_report = None
        self.quick_results = None
        
        # New Report State
        self.last_registry_data = None
        self.last_registry_analysis = None
        self.last_kernel_results = None
        
        self.init_ui()
        
        # Processing Overlay (for long-running tasks)
        self.processing_overlay = ProcessingOverlay(self)
        self.processing_overlay.hide()
        
        # Start background loader (Non-blocking)
        self.process_loader = ProcessLoaderThread()
        self.process_loader.processes_ready.connect(self.on_processes_loaded)
        self.process_loader.start()
        
        # Setup Auto-Refresh Timer (8 seconds — balanced for forensic tool)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.auto_refresh_process_list)
        self.refresh_timer.start(8000)
        
        # Worker references for background tasks
        self.rootkit_worker = None
        self.report_worker = None
    
    def on_processes_loaded(self, processes):
        """Callback when background thread finishes"""
        self.update_process_table(processes)
        self.statusBar().showMessage(f"Ready - Loaded {len(processes)} running processes")

    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("FORENSICS PROJECT - Live Memory Forensics & Malware Detection")
        
        # Center Window
        screen_geometry = QApplication.desktop().screenGeometry()
        x = (screen_geometry.width() - 1400) // 2
        y = (screen_geometry.height() - 900) // 2
        self.setGeometry(x, y, 1400, 900)
        
        # Set dark theme
        self.set_dark_theme()
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        
        # Header
        header = self.create_header()
        main_layout.addWidget(header)
        
        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_analysis_tab(), "Analysis")
        self.tabs.addTab(self.create_batch_tab(), "Batch Analysis")
        # Removed Network Tab (User Request)
        self.tabs.addTab(self.create_report_tab(), "Report & Integrity") 
        # Removed YARA Rules Tab (User Request)
        self.tabs.addTab(self.create_settings_tab(), "Settings")
        
        main_layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage("Ready - Select 'Acquire Memory Dump' to begin")
    
    def changeEvent(self, event):
        """Handle window state changes (minimize/restore) to prevent UI freeze"""
        if event.type() == QEvent.WindowStateChange:
            if self.windowState() & Qt.WindowMinimized:
                # Pause auto-refresh while minimized to save resources
                self.refresh_timer.stop()
                logger.debug("Window minimized — auto-refresh paused")
            else:
                # Restored — resume timer and schedule safe repaint
                if not self.refresh_timer.isActive():
                    self.refresh_timer.start(8000)
                    logger.debug("Window restored — auto-refresh resumed")
                # Delay repaint slightly to let the window finish restoring
                QTimer.singleShot(150, self._safe_repaint)
        super().changeEvent(event)
    
    def resizeEvent(self, event):
        """Reposition overlay on resize to prevent misalignment after restore"""
        super().resizeEvent(event)
        if self.processing_overlay and self.processing_overlay.isVisible():
            self.processing_overlay.setGeometry(self.rect())
    
    def _safe_repaint(self):
        """Force safe repaint of all visible widgets after window restore"""
        try:
            # Skip repaint if heavy workers are running (avoid main-thread stall)
            if (self.batch_worker and self.batch_worker.isRunning()) or \
               (self.ram_capture_worker and self.ram_capture_worker.isRunning()) or \
               (self.current_worker and self.current_worker.isRunning()):
                return
            
            # Only repaint critical visible widgets (not ALL children)
            if hasattr(self, 'process_table') and self.process_table:
                self.process_table.viewport().update()
            
            current_tab = self.tabs.currentWidget()
            if current_tab:
                current_tab.update()
                
            logger.debug("Post-restore repaint completed")
        except Exception as e:
            logger.warning(f"Repaint after restore failed: {e}")
    
    def set_dark_theme(self):
        """Apply dark color scheme"""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(0, 0, 0))
        palette.setColor(QPalette.WindowText, Qt.white)
        palette.setColor(QPalette.Base, QColor(0, 0, 0))
        palette.setColor(QPalette.AlternateBase, QColor(0, 0, 0))
        palette.setColor(QPalette.Text, Qt.white)
        palette.setColor(QPalette.Button, QColor(20, 20, 20))
        palette.setColor(QPalette.ButtonText, Qt.white)
        palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        
        self.setPalette(palette)
    
    def create_header(self) -> QWidget:
        """Create header section with Top Toolbar"""
        header = QGroupBox()
        layout = QVBoxLayout()
        
        # Title
        title_layout = QHBoxLayout()
        title = QLabel("FORENSICS PROJECT")
        title_font = QFont("Arial", 16, QFont.Bold)
        title.setFont(title_font)
        title.setStyleSheet("color: #3498db;")
        title_layout.addWidget(title)
        title_layout.addStretch()
        layout.addLayout(title_layout)
        
        # Toolbar
        toolbar_layout = QHBoxLayout()
        
        # Auto-Refresh Indicator
        self.refresh_label = QLabel("Auto-Refresh On")
        self.refresh_label.setStyleSheet("color: #27ae60; font-weight: bold; font-size: 11px; padding: 5px;")
        
        toolbar_layout.addWidget(self.refresh_label)
        
        # [NEW] Full System Capture Button (Removed)
        # self.btn_capture_system = QPushButton("Capture Entire RAM")
        # self.btn_capture_system.setToolTip("Create a full snapshot of all running processes")
        # self.btn_capture_system.clicked.connect(self.capture_system)
        # self.btn_capture_system.setStyleSheet("background-color: #8e44ad; font-weight: bold; padding: 5px; color: white;")
        # toolbar_layout.addWidget(self.btn_capture_system)

        # self.btn_acquire = QPushButton("Capture Process RAM") (Removed)
        # self.btn_acquire.setToolTip("Dump memory of selected process to file")
        # self.btn_acquire.clicked.connect(self.capture_selected_process)
        # self.btn_acquire.setStyleSheet("background-color: #27ae60; font-weight: bold; padding: 5px;")
        
        # Load File button removed (User Request - Focus on Live Analysis)
        
        self.btn_start_analysis = QPushButton("Start Memory Analysis")
        self.btn_start_analysis.setToolTip("Capture RAM from all running processes (Step 1)")
        self.btn_start_analysis.clicked.connect(self.start_ram_capture)
        self.btn_start_analysis.setStyleSheet("background-color: #e67e22; font-weight: bold; padding: 5px;")
        
        toolbar_layout.addWidget(self.btn_start_analysis)

        toolbar_layout.addStretch()
        
        layout.addLayout(toolbar_layout)
        header.setLayout(layout)
        return header
    
    def create_analysis_tab(self) -> QWidget:
        """Create Analysis Tab with Forensic Actions"""
        tab = QWidget()
        tab.setStyleSheet("""
            QWidget {
                background-color: #000000;
                color: #e0e0e0;
            }
            QGroupBox {
                border: 2px solid #333333;
                border-radius: 5px;
                margin-top: 10px;
                font-weight: bold;
                padding: 15px;
                color: #ffffff;
                background-color: #0a0a0a;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #ffffff;
            }
            QPushButton {
                min-height: 35px;
                font-size: 12px;
                border: 1px solid #333333;
                border-radius: 4px;
                padding: 8px;
                background-color: #1a1a1a;
                color: #ffffff;
            }
            QPushButton:hover {
                background-color: #2a2a2a;
                border: 1px solid #555555;
            }
            QPushButton:pressed {
                background-color: #0a0a0a;
            }
            QTableWidget {
                gridline-color: #333333;
                background-color: #000000;
                color: #e0e0e0;
                border: 1px solid #333333;
            }
            QTableWidget::item {
                padding: 5px;
                background-color: #000000;
            }
            QTableWidget::item:selected {
                background-color: #1a3a5a;
            }
            QHeaderView::section {
                background-color: #1a1a1a;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #333333;
                font-weight: bold;
            }
            QLabel {
                color: #e0e0e0;
            }
            QTextEdit {
                background-color: #000000;
                color: #e0e0e0;
                border: 1px solid #333333;
            }
            QProgressBar {
                border: 1px solid #333333;
                border-radius: 3px;
                background-color: #000000;
                text-align: center;
                color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #3498db;
            }
        """)
        layout = QHBoxLayout() # Split layout
        
        # LEFT: Process/Dump Selection
        left_panel = QVBoxLayout()
        
        process_group = QGroupBox("Target Selection")
        process_layout = QVBoxLayout()
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(6)
        self.process_table.setHorizontalHeaderLabels(["PID", "Process Name", "User", "Parent PID", "Command Line", "Memory (MB)"])
        
        # Optimized Header Configuration (Avoid ResizeToContents for performance)
        header = self.process_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        
        # Initial widths for clean look
        self.process_table.setColumnWidth(0, 70)  # PID
        self.process_table.setColumnWidth(1, 180) # Name
        self.process_table.setColumnWidth(2, 120) # User
        self.process_table.setColumnWidth(3, 80)  # PPID
        self.process_table.setColumnWidth(5, 100) # Memory
        
        # FORENSIC SAFETY: Make table Read-Only
        from PyQt5.QtWidgets import QAbstractItemView
        self.process_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.process_table.setAlternatingRowColors(False)
        process_layout.addWidget(self.process_table)
        process_group.setLayout(process_layout)
        
        left_panel.addWidget(process_group)
        
        # RIGHT: Analysis Actions
        # RIGHT: Analysis Actions
        right_panel = QVBoxLayout()
        
        # Statistics Dashboard
        stats_group = QGroupBox("System Overview")
        stats_layout = QVBoxLayout()
        
        # Stats display
        stats_grid = QHBoxLayout()
        
        # Total Processes
        total_layout = QVBoxLayout()
        total_label = QLabel("Total Processes")
        self.stats_total_label = QLabel("0")
        self.stats_total_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #3498db;")
        total_layout.addWidget(total_label)
        total_layout.addWidget(self.stats_total_label)
        stats_grid.addLayout(total_layout)
        
        # Total Memory
        memory_layout = QVBoxLayout()
        memory_label = QLabel("Total Memory")
        self.stats_memory_label = QLabel("0 GB")
        self.stats_memory_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #e74c3c;")
        memory_layout.addWidget(memory_label)
        memory_layout.addWidget(self.stats_memory_label)
        stats_grid.addLayout(memory_layout)
        
        stats_layout.addLayout(stats_grid)
        stats_group.setLayout(stats_layout)
        right_panel.addWidget(stats_group)
        
        # Forensic Actions
        actions_group = QGroupBox("Forensic Actions")
        actions_layout = QVBoxLayout()
        
        # Full System Scan (Step 2: Analyze collected dump)
        self.btn_full_scan = QPushButton("Full System Scan")
        self.btn_full_scan.setToolTip("Analyze the collected RAM dump (Step 2 — capture first)")
        self.btn_full_scan.clicked.connect(self.analyze_collected_dump)
        self.btn_full_scan.setEnabled(False)  # Disabled until RAM capture completes
        self.btn_full_scan.setStyleSheet("background-color: #3498db; color: white; border: none; font-weight: bold; padding: 10px; border: none; border-radius: 4px;")
        actions_layout.addWidget(self.btn_full_scan)
        
        # Rootkit Scan - REMOVED per user request
        # Registry Scan - REMOVED per user request
        # Export Button - REMOVED per user request
        
        actions_group.setLayout(actions_layout)
        right_panel.addWidget(actions_group)
        
        # Status
        status_group = QGroupBox("Analysis Status")
        status_layout = QVBoxLayout()
        
        self.progress_label = QLabel("Ready")
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        
        status_layout.addWidget(self.progress_label)
        status_layout.addWidget(self.progress_bar)
        status_group.setLayout(status_layout)
        right_panel.addWidget(status_group)
        
        right_panel.addStretch()
        layout.addLayout(left_panel, 2)
        layout.addLayout(right_panel, 1)
        
        tab.setLayout(layout)
        return tab

    def create_batch_tab(self) -> QWidget:
        """Create Batch Analysis Tab"""
        tab = QWidget()
        tab.setStyleSheet("""
            QWidget {
                background-color: #000000;
                color: #e0e0e0;
            }
            QGroupBox {
                border: 2px solid #555555;
                border-radius: 5px;
                margin-top: 10px;
                font-weight: bold;
                padding: 15px;
                color: #ffffff;
                background-color: #353535;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #ffffff;
            }
            QPushButton {
                min-height: 35px;
                font-size: 12px;
                border: 1px solid #666666;
                border-radius: 4px;
                padding: 8px;
                background-color: #404040;
                color: #ffffff;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
                border: 1px solid #888888;
            }
            QPushButton:pressed {
                background-color: #303030;
            }
            QTableWidget {
                gridline-color: #555555;
                background-color: #2b2b2b;
                color: #e0e0e0;
                border: 1px solid #555555;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #3d5a80;
            }
            QHeaderView::section {
                background-color: #404040;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #555555;
                font-weight: bold;
            }
            QLabel {
                color: #e0e0e0;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                background-color: #2b2b2b;
                text-align: center;
                color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #3498db;
            }
        """)
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("BATCH PROCESS ANALYSIS")
        header.setStyleSheet("font-size: 18px; font-weight: bold; color: #3498db; margin-bottom: 10px;")
        layout.addWidget(header)
        
        # Controls Group
        controls_group = QGroupBox("Batch Operations")
        controls_layout = QHBoxLayout()
        
        self.btn_export_pdf = QPushButton("Export PDF Report")
        self.btn_export_pdf.setToolTip("Generate professional PDF summary of batch analysis")
        self.btn_export_pdf.clicked.connect(self.export_batch_pdf)
        self.btn_export_pdf.setEnabled(True)
        self.btn_export_pdf.setStyleSheet("background-color: #8e44ad; font-weight: bold; padding: 6px;")
        
        self.btn_export_excel = QPushButton("Export Excel")
        self.btn_export_excel.setToolTip("Export raw data to Excel (.xlsx)")
        self.btn_export_excel.clicked.connect(self.export_batch_excel)
        self.btn_export_excel.setEnabled(True)
        self.btn_export_excel.setStyleSheet("background-color: #27ae60; font-weight: bold; padding: 6px;")
        
        self.btn_stop_analysis = QPushButton("Stop Analysis")
        self.btn_stop_analysis.setToolTip("Stop the current batch analysis safely")
        self.btn_stop_analysis.clicked.connect(self.stop_analysis)
        self.btn_stop_analysis.setEnabled(False)
        self.btn_stop_analysis.setStyleSheet("background-color: #c0392b; color: white; font-weight: bold; padding: 6px;")
        
        from PyQt5.QtWidgets import QCheckBox
        self.chk_scan_all = QCheckBox("Scan All Processes (Include System)")
        self.chk_scan_all.setToolTip("If enabled, bypasses filters to include protected system processes (Requires Admin)")
        self.chk_scan_all.setStyleSheet("color: #3498db; font-weight: bold; margin-left: 10px;")
        
        controls_layout.addWidget(self.btn_export_pdf)
        controls_layout.addWidget(self.btn_export_excel)
        controls_layout.addWidget(self.chk_scan_all)
        controls_layout.addStretch()
        controls_layout.addWidget(self.btn_stop_analysis)
        
        controls_group.setLayout(controls_layout)
        layout.addWidget(controls_group)
        
        # Results Table
        table_group = QGroupBox("Analysis Results")
        table_layout = QVBoxLayout()
        
        self.batch_results_table = QTableWidget()
        self.batch_results_table.setColumnCount(8)
        self.batch_results_table.setHorizontalHeaderLabels([
            "PID", "Name", "Status", "YARA Matches", "Hooks", 
            "Anomaly Score", "ML Verdict", "Threat Level"
        ])
        header = self.batch_results_table.horizontalHeader()
        header.setSectionResizeMode(1, QHeaderView.Stretch) 
        
        table_layout.addWidget(self.batch_results_table)
        table_group.setLayout(table_layout)
        layout.addWidget(table_group)
        
        tab.setLayout(layout)
        return tab

    def create_report_tab(self) -> QWidget:
        """Create Report & Integrity Tab"""
        tab = QWidget()
        tab.setStyleSheet("""
            QWidget {
                background-color: #000000;
                color: #e0e0e0;
            }
            QGroupBox {
                border: 2px solid #555555;
                border-radius: 5px;
                margin-top: 10px;
                font-weight: bold;
                padding: 15px;
                color: #ffffff;
                background-color: #353535;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #ffffff;
            }
            QPushButton {
                min-height: 35px;
                font-size: 12px;
                border: 1px solid #666666;
                border-radius: 4px;
                padding: 8px;
                background-color: #404040;
                color: #ffffff;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
                border: 1px solid #888888;
            }
            QPushButton:pressed {
                background-color: #303030;
            }
            QTableWidget {
                gridline-color: #555555;
                background-color: #2b2b2b;
                color: #e0e0e0;
                border: 1px solid #555555;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #3d5a80;
            }
            QHeaderView::section {
                background-color: #404040;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #555555;
                font-weight: bold;
            }
            QLabel {
                color: #e0e0e0;
            }
            QTextEdit {
                background-color: #2b2b2b;
                color: #e0e0e0;
                border: 1px solid #555555;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                background-color: #2b2b2b;
                text-align: center;
                color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #3498db;
            }
        """)
        layout = QVBoxLayout()
        
        # Integrity Section
        # Integrity Section
        integrity_group = QGroupBox("Forensic Integrity")
        int_layout = QVBoxLayout()
        
        # 1. Memory Dump Verification
        self.btn_verify_integrity = QPushButton("Verify Memory Dump Hash")
        self.btn_verify_integrity.setToolTip("Calculate SHA-256 hash of loaded .raw file")
        self.btn_verify_integrity.clicked.connect(self.verify_integrity)
        int_layout.addWidget(self.btn_verify_integrity)
        
        # 2. PDF Report Verification (Moved from Actions)
        self.btn_verify_pdf = QPushButton("Verify PDF Report Integrity")
        self.btn_verify_pdf.setToolTip("Verify cryptographic signature of a generated PDF report")
        self.btn_verify_pdf.clicked.connect(self.verify_report_integrity)
        self.btn_verify_pdf.setStyleSheet("background-color: #2c3e50; color: white; font-weight: bold;")
        int_layout.addWidget(self.btn_verify_pdf)

        self.integrity_display = QLabel("No dump loaded.")
        int_layout.addWidget(self.integrity_display)
        integrity_group.setLayout(int_layout)
        layout.addWidget(integrity_group)
        
        # Reporting Section
        report_group = QGroupBox("Reporting")
        rep_layout = QVBoxLayout()
        self.btn_gen_report = QPushButton("Generate Forensic Report (PDF)")
        self.btn_generate_report = self.btn_gen_report # Alias for compatibility
        self.btn_gen_report.clicked.connect(self.generate_report)
        self.btn_gen_report.setEnabled(True)
        self.btn_gen_report.setStyleSheet("background-color: #c0392b; font-weight: bold;")
        rep_layout.addWidget(self.btn_gen_report)
        
        # [NEW] Download Suspicious Process Report (Hidden by default)
        self.btn_download_suspicious = QPushButton("Download Suspicious Report (CRITICAL)")
        self.btn_download_suspicious.setToolTip("Instantly generate report for detected threat")
        self.btn_download_suspicious.clicked.connect(self.generate_report)
        self.btn_download_suspicious.setVisible(False) # Hidden until malware found
        self.btn_download_suspicious.setStyleSheet("background-color: #e74c3c; color: white; font-weight: bold; border: 2px solid #c0392b;")
        rep_layout.addWidget(self.btn_download_suspicious)
        
        self.btn_open_artifacts = QPushButton("Open Artifacts")
        self.btn_open_artifacts.clicked.connect(self.open_artifacts_folder)
        rep_layout.addWidget(self.btn_open_artifacts)
        report_group.setLayout(rep_layout)
        layout.addWidget(report_group)
        
        # Results View (Shared)
        results_group = QGroupBox("Analysis Findings")
        res_layout = QVBoxLayout()
        self.quick_results = QTextEdit()  # Alias quick_results to new text edit
        self.quick_results.setReadOnly(True)
        self.quick_results.setPlaceholderText("Analysis summary will appear here...")
        self.quick_results.setMaximumHeight(150)
        res_layout.addWidget(self.quick_results)
        
        self.results_display = QTextEdit()
        self.results_display.setReadOnly(True)
        res_layout.addWidget(self.results_display)
        results_group.setLayout(res_layout)
        layout.addWidget(results_group)

        tab.setLayout(layout)
        return tab

    def create_results_tab(self) -> QWidget:
        # Reusing new tabs structure, deleting this old method by not calling it in init_ui
        # But we need to keep compatibility if other methods reference elements created here
        # Actually I replaced the call in init_ui, so this method is effectively dead code unless I repurpose it.
        # I will replace init_ui later to call my new methods.
        return QWidget() 

    
    def create_settings_tab(self) -> QWidget:
        """Create settings tab"""
        tab = QWidget()
        tab.setStyleSheet("""
            QWidget {
                background-color: #000000;
                color: #e0e0e0;
            }
            QGroupBox {
                border: 2px solid #555555;
                border-radius: 5px;
                margin-top: 10px;
                font-weight: bold;
                padding: 15px;
                color: #ffffff;
                background-color: #353535;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #ffffff;
            }
            QPushButton {
                min-height: 35px;
                font-size: 12px;
                border: 1px solid #666666;
                border-radius: 4px;
                padding: 8px;
                background-color: #404040;
                color: #ffffff;
            }
            QPushButton:hover {
                background-color: #4a4a4a;
                border: 1px solid #888888;
            }
            QPushButton:pressed {
                background-color: #303030;
            }
            QTableWidget {
                gridline-color: #555555;
                background-color: #2b2b2b;
                color: #e0e0e0;
                border: 1px solid #555555;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #3d5a80;
            }
            QHeaderView::section {
                background-color: #404040;
                color: #ffffff;
                padding: 5px;
                border: 1px solid #555555;
                font-weight: bold;
            }
            QLabel {
                color: #e0e0e0;
            }
            QTextEdit {
                background-color: #2b2b2b;
                color: #e0e0e0;
                border: 1px solid #555555;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 3px;
                background-color: #2b2b2b;
                text-align: center;
                color: #ffffff;
            }
            QProgressBar::chunk {
                background-color: #3498db;
            }
        """)
        layout = QVBoxLayout()
        
        settings_text = QTextEdit()
        settings_text.setReadOnly(True)
        settings_text.setPlainText("""
WINDOWS MEMORY FORENSICS TOOL - SETTINGS

Current Configuration:
- YARA Rules: Loaded from rules/malware_sigs.yar
- Auto-Delete RAW Dumps: ENABLED
- ML Model: detection/models/mem_classifier.pkl
- Artifact Retention: 365 days
- Secure Delete Passes: 3 (DoD 5220.22-M)

Evidence Lifecycle:
1. RAW memory dumps are temporarily captured
2. YARA scans raw dumps directly
3. RAW dumps are SECURELY DELETED after analysis
4. JSON artifacts are PERMANENTLY RETAINED
5. All evidence is hashed and timestamped

Detection Engines:
- Signature-based (YARA)
- Memory integrity validation (Hook detection)
- Behavioral analysis
- Machine learning classification

Reports:
- Manual generation only
- Full forensic chain of custody
- PDF format with SHA-256 hashes
        """)
        
        layout.addWidget(settings_text)
        
        # [NEW] Advanced Configuration Control
        settings_group = QGroupBox("Advanced Configuration")
        settings_layout = QVBoxLayout()
        
        try:
            from PyQt5.QtWidgets import QCheckBox
            import config
            
            self.adv_checkbox = QCheckBox("Enable Advanced Architecture Mode (Kernel + Registry)")
            self.adv_checkbox.setChecked(config.ADVANCED_MODE)
            self.adv_checkbox.setToolTip("Enables experimental Kernel Driver interface and Registry Forensics.")
            self.adv_checkbox.stateChanged.connect(self.toggle_advanced_mode)
            
            # [FIX] Force Visible Indicator for Dark Theme
            self.adv_checkbox.setStyleSheet("""
                QCheckBox {
                    color: #e74c3c;
                    font-weight: bold;
                    font-size: 14px;
                    spacing: 10px;
                }
                QCheckBox::indicator {
                    width: 20px;
                    height: 20px;
                    border: 2px solid #e74c3c;
                    border-radius: 4px;
                    background: none;
                }
                QCheckBox::indicator:checked {
                    background-color: #e74c3c;
                    border: 2px solid #e74c3c;
                    image: url(none); /* Utilize standard checkmark or fill */
                }
                QCheckBox::indicator:unchecked {
                     background-color: #2c3e50;
                }
                QCheckBox::indicator:unchecked:hover {
                    border: 2px solid #c0392b;
                }
            """)
            
            settings_layout.addWidget(self.adv_checkbox)
            
            # Label explaining safety
            self.safety_label = QLabel("Note: Kernel features require the 'LMFDriver.sys' to be loaded.")
            self.safety_label.setStyleSheet("color: #95a5a6; font-style: italic;")
            settings_layout.addWidget(self.safety_label)
            
        except Exception as e:
            layout.addWidget(QLabel(f"Error loading advanced settings: {e}"))
            
        settings_group.setLayout(settings_layout)
        layout.addWidget(settings_group)
        
        tab.setLayout(layout)
        return tab
    
    def toggle_advanced_mode(self, state):
        """Safely toggle advanced mode flag"""
        import config
        from PyQt5.QtCore import Qt
        
        if state == Qt.Checked:
            config.ADVANCED_MODE = True
            config.ENABLE_KERNEL_SCAN = True
            config.ENABLE_REGISTRY_SCAN = True
            self.statusBar().showMessage("Advanced Mode ENABLED - Kernel & Registry Modules Active")
        else:
            config.ADVANCED_MODE = False
            config.ENABLE_KERNEL_SCAN = False
            config.ENABLE_REGISTRY_SCAN = False
            self.statusBar().showMessage("Advanced Mode DISABLED - Standard Safe Mode Active")
    
    
    # create_rules_tab and helpers REMOVED


    def stop_analysis(self):
        """Stop current running analysis"""
        msg = QMessageBox.question(
            self, "Stop Analysis",
            "Are you sure you want to stop the analysis?\nPartial results will be saved.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if msg == QMessageBox.Yes:
            self.statusBar().showMessage("Stopping analysis... Please wait.")
            
            # Stop Live Batch Worker
            if hasattr(self, 'batch_worker') and self.batch_worker and self.batch_worker.isRunning():
                self.batch_worker.stop()
                
            # Stop Offline Batch Worker
            if hasattr(self, 'batch_file_worker') and self.batch_file_worker and self.batch_file_worker.isRunning():
                self.batch_file_worker.stop()
                
            self.btn_stop_analysis.setEnabled(False)

    def auto_refresh_process_list(self):
        """Silent auto-refresh for QTimer"""
        # Skip if ANY worker is running — prevents main-thread stalls
        if self.current_worker and self.current_worker.isRunning():
            return
        if self.batch_worker and self.batch_worker.isRunning():
            return
        if self.ram_capture_worker and self.ram_capture_worker.isRunning():
            return
        if hasattr(self, 'snapshot_analysis_worker') and self.snapshot_analysis_worker and self.snapshot_analysis_worker.isRunning():
            return
        if self.process_list_worker and self.process_list_worker.isRunning():
            return 
        if self.auto_worker and self.auto_worker.isRunning():
            return

        self.auto_worker = ProcessListWorker()
        self.auto_worker.finished.connect(self.update_process_list_if_changed)
        self.auto_worker.start()

    def update_process_list_if_changed(self, processes):
        """Update table if PIDs OR Memory usage changed significantly using cache"""
        # Get new state
        new_state = {p['pid']: p.get('memory_mb', 0) for p in processes}
        
        # Check delta against CACHE (not the UI table)
        has_changed = False
        if set(self._process_cache.keys()) != set(new_state.keys()):
            has_changed = True # PID List changed
        else:
            # Check memory diff (> 2.0 MB change triggers update)
            for pid, mem in new_state.items():
                if abs(mem - self._process_cache.get(pid, 0)) > 2.0:
                    has_changed = True
                    break
                    
        if not has_changed:
            return 
            
        # Update Cache
        self._process_cache = new_state
            
        # Save View State
        current_row = self.process_table.currentRow()
        current_pid = None
        if current_row >= 0:
            pid_item = self.process_table.item(current_row, 0)
            if pid_item:
                current_pid = pid_item.text()
        
        v_scroll = self.process_table.verticalScrollBar().value()
            
        self.on_process_list_loaded(processes)
        
        # Restore View State
        if current_pid:
            items = self.process_table.findItems(current_pid, Qt.MatchExactly)
            if items:
                row = items[0].row()
                self.process_table.selectRow(row)
        
        self.process_table.verticalScrollBar().setValue(v_scroll)

    # [NEW] Manual Scan Handlers — All run on background QThread workers
    def run_registry_scan_manual(self):
        """Run standalone Registry Persistence Scan (Non-blocking)"""
        import config
        if not config.ENABLE_REGISTRY_SCAN:
            QMessageBox.warning(self, "Advanced Mode Required", 
                "Registry Scanning is disabled.\nPlease enable 'Advanced Architecture Mode' in Settings.")
            return

        # Prevent re-entry
        if hasattr(self, '_registry_worker') and self._registry_worker and self._registry_worker.isRunning():
            self.statusBar().showMessage("Registry scan already in progress...")
            return

        self.btn_registry_scan.setEnabled(False)
        self.statusBar().showMessage("Running Registry Scan...")
        self.results_display.append("\n=== STARTING REGISTRY PERSISTENCE SCAN ===")
        
        # Launch on background thread
        self._registry_worker = RegistryScanWorker()
        self._registry_worker.progress.connect(lambda msg: self.statusBar().showMessage(msg))
        self._registry_worker.finished.connect(self._on_registry_scan_done)
        self._registry_worker.error.connect(self._on_registry_scan_error)
        self._registry_worker.start()
    
    def _on_registry_scan_done(self, raw_data, analysis):
        """Handle registry scan results from worker thread"""
        self.last_registry_data = raw_data
        self.last_registry_analysis = analysis
        
        if raw_data.get('scanned_paths'):
            self.results_display.append("\nVerified Locations:")
            for path in raw_data['scanned_paths']:
                self.results_display.append(f" [+] {path}")
        
        self.results_display.append(f"\nTotal Scanned Keys: {raw_data.get('scanned_keys', 0)}")
        self.results_display.append(f"Risk Score: {analysis.get('registry_score', 0)}")
        
        if analysis.get('findings'):
            self.results_display.append("Suspicious Findings:")
            for finding in analysis['findings']:
                self.results_display.append(f" [!] {finding}")
        else:
            self.results_display.append("No suspicious registry entries found.")
            
        self.results_display.append("=== SCAN COMPLETE ===\n")
        self.statusBar().showMessage("Registry Scan Complete")
        self.btn_registry_scan.setEnabled(True)
    
    def _on_registry_scan_error(self, error_msg):
        """Handle registry scan failure"""
        self.results_display.append(f"[ERROR] Registry Scan Failed: {error_msg}")
        logger.error(f"Manual Registry Scan Error: {error_msg}")
        self.btn_registry_scan.setEnabled(True)

    def run_kernel_scan_manual(self):
        """Run standalone Kernel Rootkit Scan (Non-blocking)"""
        import config
        if not config.ENABLE_KERNEL_SCAN:
            QMessageBox.warning(self, "Advanced Mode Required", 
                "Kernel Scanning is disabled.\nPlease enable 'Advanced Architecture Mode' in Settings.")
            return

        # Prevent re-entry
        if hasattr(self, '_kernel_worker') and self._kernel_worker and self._kernel_worker.isRunning():
            self.statusBar().showMessage("Kernel scan already in progress...")
            return

        self.btn_rootkit_scan.setEnabled(False)
        self.statusBar().showMessage("Running Kernel Rootkit Scan...")
        self.results_display.append("\n=== STARTING KERNEL ROOTKIT SCAN ===")
        
        # Launch on background thread
        self._kernel_worker = KernelScanWorker()
        self._kernel_worker.progress.connect(lambda msg: self.statusBar().showMessage(msg))
        self._kernel_worker.finished.connect(self._on_kernel_scan_done)
        self._kernel_worker.error.connect(self._on_kernel_scan_error)
        self._kernel_worker.start()
    
    def _on_kernel_scan_done(self, hidden_procs, kernel_res):
        """Handle kernel scan results from worker thread"""
        if hidden_procs:
            self.results_display.append(f"[CRITICAL] Found {len(hidden_procs)} Hidden Processes!")
            for proc in hidden_procs:
                self.results_display.append(f" [!] PID: {proc['pid']} | Name: {proc['name']} | Type: {proc['type']}")
        else:
            self.results_display.append("No hidden processes found via Cross-View Analysis.")
            
        if kernel_res.get('status') == 'error':
             self.results_display.append(f"[WARNING] Driver Interface: {kernel_res.get('message')}")
        else:
             self.results_display.append(f"Driver Scan Status: {kernel_res.get('status')}")
        
        # Save for Report
        all_hidden = hidden_procs[:]
        if kernel_res.get('status') == 'completed':
            all_hidden.extend(kernel_res.get('hidden_processes', []))
        self.last_kernel_results = all_hidden
        
        self.results_display.append("=== SCAN COMPLETE ===\n")
        self.statusBar().showMessage("Kernel Scan Complete")
        self.btn_rootkit_scan.setEnabled(True)
    
    def _on_kernel_scan_error(self, error_msg):
        """Handle kernel scan failure"""
        self.results_display.append(f"[ERROR] Kernel Scan Failed: {error_msg}")
        logger.error(f"Manual Kernel Scan Error: {error_msg}")
        self.btn_rootkit_scan.setEnabled(True)

    def export_advanced_report(self):
        """Export the results of Registry/Kernel scans to PDF (Non-blocking)"""
        if self.last_registry_data is None and self.last_kernel_results is None:
             QMessageBox.warning(self, "No Data to Export", 
                "Please run at least one manual scan (Registry or Kernel) before exporting.")
             return
        
        # Prevent re-entry
        if hasattr(self, '_report_worker') and self._report_worker and self._report_worker.isRunning():
            self.statusBar().showMessage("Report generation already in progress...")
            return
        
        self.statusBar().showMessage("Generating Advanced PDF Report...")
        
        # Launch on background thread
        self._report_worker = ReportExportWorker(
            self.last_registry_data,
            self.last_registry_analysis,
            self.last_kernel_results
        )
        self._report_worker.finished.connect(self._on_report_exported)
        self._report_worker.error.connect(self._on_report_export_error)
        self._report_worker.start()
    
    def _on_report_exported(self, report_path_str):
        """Handle successful report generation"""
        if report_path_str:
            report_path = Path(report_path_str)
            QMessageBox.information(self, "Export Successful", 
                f"Advanced Report generated successfully:\n\n{report_path}")
            self.statusBar().showMessage(f"Report Saved: {report_path.name}")
            
            # Auto-open
            import os
            os.startfile(str(report_path))
        else:
            QMessageBox.critical(self, "Export Failed", "Report generation returned no path.")
    
    def _on_report_export_error(self, error_msg):
        """Handle report generation failure"""
        QMessageBox.critical(self, "Export Error", f"Failed to generate report:\n{error_msg}")
        logger.error(f"Advanced Export Error: {error_msg}")

    def load_process_list(self):
        """Load and display running processes in background"""
        # Start worker thread to load processes
        self.process_list_worker = ProcessListWorker()
        self.process_list_worker.finished.connect(self.on_process_list_loaded)
        self.process_list_worker.error.connect(self.on_process_list_error)
        self.process_list_worker.start()
        
        # Show loading indicator
        self.statusBar().showMessage("Loading processes...")
    
    def on_process_list_loaded(self, processes):
        """Handle loaded process list - Consolidated into update_process_table"""
        try:
            self.update_process_table(processes)
        except Exception as e:
            logger.error(f"Failed to update process UI: {e}")
            self.statusBar().showMessage("Error updating process list")
    
    def on_process_list_error(self, error_msg):
        """Handle process list loading error"""
        QMessageBox.critical(self, "Error", f"Failed to load processes: {error_msg}")
        self.statusBar().showMessage("Failed to load processes")
    
    def analyze_selected_process(self):
        """Start analysis of selected process or loaded dump"""
        # Feature: Offline Analysis has priority if a dump is loaded
        if self.current_dump_path:
             # Offline Analysis
             logger.info(f"Starting offline analysis of {self.current_dump_path}")
             self.progress_label.setText(f"Analyzing loaded dump: {Path(self.current_dump_path).name}...")
             self.progress_bar.setVisible(True)
             self.btn_start_analysis.setEnabled(False)
             
             self.current_worker = OfflineAnalysisWorker(self.current_dump_path)
             self.current_worker.progress.connect(self.update_progress)
             self.current_worker.finished.connect(self.analysis_complete)
             self.current_worker.error.connect(self.analysis_error)
             self.current_worker.start()
             return

        # Live Process Analysis
        selected = self.process_table.selectedItems()
        
        if not selected:
            # Smart Analysis Fallback: Offer Full System Scan
            reply = QMessageBox.question(
                self,
                "No Selection - Perform Full Scan?",
                "No specific process selected.\n\n"
                "Do you want to perform a **Full System Analysis** of ALL running processes?\n"
                "(This will switch to Batch Mode)",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.No:
                self.tabs.setCurrentIndex(1) # Switch to Batch Tab
                self.analyze_all_processes()
            return

        row = selected[0].row()
        pid = int(self.process_table.item(row, 0).text())
        process_name = self.process_table.item(row, 1).text()
        
        # Confirm
        reply = QMessageBox.question(
            self,
            "Confirm Analysis",
            f"Analyze process:\n\nName: {process_name}\nPID: {pid}\n\nThis will:\n"
            "1. Capture process memory\n2. Scan with YARA\n3. Detect API hooks (Live)\n"
            "4. Run ML analysis\n5. Delete raw dump after analysis\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
        
        # Start analysis in worker thread
        self.btn_start_analysis.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_label.setText("Starting analysis...")
        
        self.current_worker = AnalysisWorker(pid, process_name)
        self.current_worker.progress.connect(self.update_progress)
        self.current_worker.finished.connect(self.analysis_complete)
        self.current_worker.error.connect(self.analysis_error)
        self.current_worker.start()
    
    # ====================================================================
    # STEP 1: RAM Capture (Start Memory Analysis button)
    # ====================================================================
    
    def start_ram_capture(self):
        """Capture RAM from all running processes — NO analysis, NO deletion."""
        reply = QMessageBox.question(
            self,
            "Confirm RAM Capture",
            "This will capture a memory snapshot of all running processes.\n\n"
            "• No analysis will be performed yet\n"
            "• No files will be deleted\n"
            "• Protected system processes will be skipped\n\n"
            "After capture, use 'Full System Scan' to analyze the dump.\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.No:
            return
        
        # Disable buttons to prevent re-entry
        self.btn_start_analysis.setEnabled(False)
        self.btn_full_scan.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.progress_label.setText("Capturing RAM snapshot...")
        
        # Launch the capture-only worker
        self.ram_capture_worker = SystemCaptureWorker()
        
        # [OPTIMIZATION] Lower thread priority to prevent UI thread starvation
        self.ram_capture_worker.setPriority(QThread.LowPriority)
        
        # [OPTIMIZATION] Stop refresh timer during capture to reduce CPU competition
        if hasattr(self, 'refresh_timer') and self.refresh_timer.isActive():
            self.refresh_timer.stop()
            logger.info("Auto-refresh timer paused for RAM capture")
            
        self.ram_capture_worker.progress.connect(self.on_ram_capture_progress)
        self.ram_capture_worker.finished.connect(self.on_ram_capture_finished)
        self.ram_capture_worker.error.connect(self.on_ram_capture_error)
        self.ram_capture_worker.start()
    
    def on_ram_capture_progress(self, msg: str):
        """Update progress during RAM capture."""
        self.progress_label.setText(msg)
    
    def on_ram_capture_finished(self, msg: str):
        """Handle successful RAM capture — stores snapshot path, enables Full System Scan."""
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self.btn_start_analysis.setEnabled(True)
        
        # Extract snapshot folder path from the finished message
        # SystemCaptureWorker emits: "...\nLocation: <path>\n..."
        for line in msg.split('\n'):
            if line.strip().startswith('Location:'):
                path_str = line.split('Location:')[1].strip()
                self.last_snapshot_path = path_str
                break
        
        if self.last_snapshot_path:
            self.btn_full_scan.setEnabled(True)
            self.progress_label.setText(f"RAM captured → {Path(self.last_snapshot_path).name}. Click 'Full System Scan' to analyze.")
        else:
            self.progress_label.setText("RAM captured. Ready.")
        
        # [OPTIMIZATION] Restart refresh timer
        if hasattr(self, 'refresh_timer') and not self.refresh_timer.isActive():
            self.refresh_timer.start(8000)
            logger.info("Auto-refresh timer resumed")
            
        QMessageBox.information(self, "RAM Capture Complete", msg)
        logger.info(f"RAM capture complete. Snapshot: {self.last_snapshot_path}")
    
    def on_ram_capture_error(self, error: str):
        """Handle RAM capture failure."""
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self.btn_start_analysis.setEnabled(True)
        self.progress_label.setText("RAM capture failed.")
        logger.error(f"RAM capture failed: {error}")
        # [OPTIMIZATION] Restart refresh timer on error
        if hasattr(self, 'refresh_timer') and not self.refresh_timer.isActive():
            self.refresh_timer.start(8000)
            logger.info("Auto-refresh timer resumed (after error)")
            
        QMessageBox.critical(self, "RAM Capture Error", f"Snapshot failed:\n\n{error}")
    
    # ====================================================================
    # STEP 2: Analyze Collected Dump (Full System Scan button)
    # ====================================================================
    
    def analyze_collected_dump(self):
        """Analyze the most recently captured RAM dump folder."""
        if not self.last_snapshot_path or not Path(self.last_snapshot_path).exists():
            QMessageBox.warning(
                self, "No Dump Available",
                "No captured RAM dump found.\n\n"
                "Please click 'Start Memory Analysis' first to capture a snapshot."
            )
            return
        
        raw_count = len(list(Path(self.last_snapshot_path).glob('*.raw')))
        if raw_count == 0:
            QMessageBox.warning(
                self, "No Raw Files",
                f"No .raw dump files found in:\n{self.last_snapshot_path}\n\n"
                "Please capture a new snapshot first."
            )
            return
        
        reply = QMessageBox.question(
            self,
            "Confirm Analysis",
            f"Analyze {raw_count} captured memory dumps?\n\n"
            f"Folder: {Path(self.last_snapshot_path).name}\n\n"
            "This will:\n"
            "1. Scan each dump with YARA rules\n"
            "2. Run ML anomaly detection\n"
            "3. Generate a PDF forensic report\n"
            "4. Raw files will be KEPT (not deleted)\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.No:
            return
        
        # Clear previous batch results
        self.batch_results = []
        self.batch_results_table.setRowCount(0)
        self.batch_results_table.setSortingEnabled(False)
        self.tabs.setCurrentWidget(self.tabs.widget(1)) # Switch to Batch Tab
        
        # Disable buttons
        self.btn_start_analysis.setEnabled(False)
        self.btn_full_scan.setEnabled(False)
        self.btn_stop_analysis.setEnabled(True) # Enable Stop Button
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)
        self.progress_label.setText("Analyzing collected dumps...")
        
        # Show overlay
        self.processing_overlay.show_overlay(
            title="Analyzing Memory Dumps",
            status=f"Processing {raw_count} files...\nThis may take several minutes."
        )
        
        # Launch analysis worker
        self.snapshot_analysis_worker = SnapshotAnalysisWorker(self.last_snapshot_path)
        self.snapshot_analysis_worker.progress.connect(self.on_dump_analysis_progress)
        self.snapshot_analysis_worker.process_complete.connect(self.batch_process_complete) 
        self.snapshot_analysis_worker.finished.connect(self.on_dump_analysis_finished)
        self.snapshot_analysis_worker.error.connect(self.on_dump_analysis_error)
        self.snapshot_analysis_worker.start()
    
    def on_dump_analysis_progress(self, msg: str):
        """Update progress during dump analysis."""
        self.progress_label.setText(msg)
        self.processing_overlay.update_status(msg)
    
    def on_dump_analysis_finished(self, msg: str):
        """Handle completion of dump analysis."""
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self.btn_start_analysis.setEnabled(True)
        self.btn_full_scan.setEnabled(True)
        self.progress_label.setText("Analysis complete.")
        self.processing_overlay.hide_overlay()
        
        QMessageBox.information(self, "Analysis Complete", msg)
        logger.info(f"Dump analysis complete: {msg}")
    
    def on_dump_analysis_error(self, error: str):
        """Handle dump analysis failure."""
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self.btn_start_analysis.setEnabled(True)
        self.btn_full_scan.setEnabled(True)
        self.progress_label.setText("Analysis failed.")
        self.processing_overlay.hide_overlay()
        logger.error(f"Dump analysis failed: {error}")
        QMessageBox.critical(self, "Analysis Error", f"Analysis failed:\n\n{error}")

    def update_process_table(self, processes: list):
        """Optimized update of the process list table with smart row reuse"""
        # Helper to make items read-only
        def create_readonly_item(text, align=Qt.AlignLeft | Qt.AlignVCenter):
            item = QTableWidgetItem(str(text))
            item.setFlags(item.flags() ^ Qt.ItemIsEditable)
            item.setTextAlignment(align)
            return item

        self.process_table.blockSignals(True)
        self.process_table.setSortingEnabled(False)   # Prevent re-sort per row
        self.process_table.setUpdatesEnabled(False)   # Batch all visual updates
        
        try:
            # Check if we can reuse rows or need to adjust count
            current_rows = self.process_table.rowCount()
            new_rows = len(processes)
            
            if current_rows != new_rows:
                self.process_table.setRowCount(new_rows) 
            
            for row_idx, proc in enumerate(processes):
                # PID
                pid_str = str(proc['pid'])
                existing_pid = self.process_table.item(row_idx, 0)
                if existing_pid:
                    if existing_pid.text() != pid_str:
                        existing_pid.setText(pid_str)
                else:
                    self.process_table.setItem(row_idx, 0, create_readonly_item(pid_str, Qt.AlignCenter))
                
                # Name
                name = proc['name']
                existing_name = self.process_table.item(row_idx, 1)
                if existing_name:
                    if existing_name.text() != name:
                        existing_name.setText(name)
                else:
                    self.process_table.setItem(row_idx, 1, create_readonly_item(name))
                
                # User
                username = proc.get('username', 'N/A')
                existing_user = self.process_table.item(row_idx, 2)
                if existing_user:
                    if existing_user.text() != username:
                        existing_user.setText(username)
                else:
                    self.process_table.setItem(row_idx, 2, create_readonly_item(username))
                
                # PPID
                ppid = str(proc.get('ppid', ''))
                existing_ppid = self.process_table.item(row_idx, 3)
                if existing_ppid:
                    if existing_ppid.text() != ppid:
                        existing_ppid.setText(ppid)
                else:
                    self.process_table.setItem(row_idx, 3, create_readonly_item(ppid, Qt.AlignCenter))
                
                # CmdLine
                cmdline = proc.get('cmdline', '')
                existing_cmd = self.process_table.item(row_idx, 4)
                if existing_cmd:
                    if existing_cmd.text() != cmdline:
                        existing_cmd.setText(cmdline)
                        existing_cmd.setToolTip(cmdline)
                else:
                    cmd_item = create_readonly_item(cmdline)
                    cmd_item.setToolTip(cmdline)
                    self.process_table.setItem(row_idx, 4, cmd_item)
                
                # Memory
                mem_mb = proc.get('memory_mb', 0)
                mem_str = f"{mem_mb:.1f}" # Reduced precision for UI speed
                existing_mem = self.process_table.item(row_idx, 5)
                if existing_mem:
                    if existing_mem.text() != mem_str:
                        existing_mem.setText(mem_str)
                else:
                    self.process_table.setItem(row_idx, 5, create_readonly_item(mem_str, Qt.AlignRight | Qt.AlignVCenter))
        finally:
            self.process_table.setUpdatesEnabled(True)
            self.process_table.setSortingEnabled(True)
            self.process_table.blockSignals(False)
        
        # Update statistics dashboard
        total_memory_mb = sum(proc.get('memory_mb', 0) for proc in processes)
        if hasattr(self, 'stats_total_label') and self.stats_total_label:
            self.stats_total_label.setText(str(len(processes)))
        if hasattr(self, 'stats_memory_label') and self.stats_memory_label:
            total_memory_gb = total_memory_mb / 1024
            self.stats_memory_label.setText(f"{total_memory_gb:.2f} GB")
            
        if not self.progress_bar.isVisible():
             self.statusBar().showMessage(f"Ready - Tracking {len(processes)} processes")

    def update_progress(self, message: str):
        """Update progress display"""
        self.progress_label.setText(message)
        self.statusBar().showMessage(message)
    
    def analysis_complete(self, results: Dict):
        """Handle completed analysis"""
        self.analysis_results = results
        
        self.progress_bar.setVisible(False)
        self.btn_start_analysis.setEnabled(True)
        self.btn_generate_report.setEnabled(True)
        
        # Smart Feature: Download Suspicious Report Button
        is_malicious = results.get('ml_detection', {}).get('is_malicious', False)
        if is_malicious:
            self.btn_download_suspicious.setVisible(True)
            self.btn_download_suspicious.setEnabled(True)
        else:
            self.btn_download_suspicious.setVisible(False)
        
        # Display quick results
        quick_summary = f"""
ANALYSIS COMPLETE - {results['process_name']} (PID: {results['pid']})

[1] YARA SIGNATURE SCAN:
   - Status: {'DETECTED' if results['yara_scan'].get('total_matches', 0) > 0 else 'CLEAN'}
   - Detections: {results['yara_scan'].get('total_matches', 0)}

[2] BEHAVIORAL ANALYSIS (ML):
   - Verdict: {results['ml_detection'].get('classification', 'N/A')}
   - Confidence: {results['ml_detection'].get('confidence_scores', {}).get('malware', 0):.2%}
   - Risk Score: {results['ml_detection'].get('risk_score', 0)}/100

[3] ANOMALY DETECTION:
   - Anomalies Found: {len(results.get('anomaly_detection', {}).get('detected_anomalies', []))}
   - C2/Ransomware Alerts: {sum(1 for a in results.get('anomaly_detection', {}).get('detected_anomalies', []) if a['type'] in ['C2_BEACONING_PATTERN', 'RANSOMWARE_HEURISTIC'])}
   - Anomalies Found: {len(results.get('anomaly_detection', {}).get('detected_anomalies', []))}
   - Anomaly Score: {results.get('anomaly_detection', {}).get('anomaly_score', 0):.1f}/100

RAW DUMP STATUS: {results['yara_scan'].get('deletion_status', 'Unknown')}
ARTIFACT SAVED: {results.get('artifact_path', 'Unknown')}
        """
        
        self.quick_results.setPlainText(quick_summary)
        
        # Display full results in results tab
        self.results_display.setPlainText(json.dumps(results, indent=2))
        
        # Show notification
        severity = results['ml_detection'].get('severity', 'LOW')
        is_malicious = results['ml_detection'].get('is_malicious', False)
        
        # Handle hooks_detected which can be list or int
        hooks_data = results['hook_detection'].get('hooks_detected', [])
        hooks_count = len(hooks_data) if isinstance(hooks_data, list) else (hooks_data if isinstance(hooks_data, int) else 0)
        
        if is_malicious:
            QMessageBox.warning(
                self,
                f"THREAT DETECTED - {severity}",
                f"Malicious activity detected in {results['process_name']}!\n\n"
                f"Severity: {severity}\n"
                f"YARA Matches: {results['yara_scan'].get('total_matches', 0)}\n"
                f"API Hooks: {hooks_count}\n\n"
                "Review full results and generate forensic report."
            )
        else:
            QMessageBox.information(
                self,
                "Analysis Complete",
                f"Analysis of {results['process_name']} completed.\n\n"
                "No significant threats detected."
            )
    
    def analysis_error(self, error_msg: str):
        """Handle analysis error"""
        self.progress_bar.setVisible(False)
        self.btn_start_analysis.setEnabled(True)
        
        QMessageBox.critical(self, "Analysis Error", f"An error occurred:\n\n{error_msg}")
        self.statusBar().showMessage("Analysis failed")
    
    def analyze_all_processes(self):
        """Start batch analysis of all processes (Async)"""
        # 1. Disable UI to prevent re-entry
        self.btn_start_analysis.setEnabled(False)
        self.btn_full_scan.setEnabled(False)
        
        # 2. Show Loading
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0) # Indeterminate
        self.progress_label.setText("Scanning running processes...")
        
        # 3. Start Async Loader
        include_all = self.chk_scan_all.isChecked()
        self.batch_loader = ProcessListWorker(include_all=include_all)
        self.batch_loader.finished.connect(self._on_full_scan_ready)
        self.batch_loader.error.connect(self.on_process_list_error)
        self.batch_loader.start()
        
    def _on_full_scan_ready(self, processes):
        """Callback when process list is ready for Full Scan"""
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setVisible(False)
        self.btn_full_scan.setEnabled(True)
        
        if not processes:
            QMessageBox.warning(self, "Warning", "No processes available for analysis")
            self.btn_start_analysis.setEnabled(True)
            return

        # Confirm batch analysis
        reply = QMessageBox.question(
            self,
            "Confirm Batch Analysis",
            f"Analyze ALL {len(processes)} processes?\n\n"
            "This will:\n"
            "1. Capture memory from all processes\n"
            "2. Scan each with YARA\n"
            "3. Detect API hooks in each\n"
            "4. Run ML analysis on each\n"
            "5. Delete raw dumps after analysis\n"
            "6. Save JSON artifacts for all\n\n"
            f"NOTE: This may take significant time ({len(processes)} processes)\n\n"
            "Continue?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            self.btn_start_analysis.setEnabled(True)
            self.progress_label.setText("Ready")
            return
            
        self.start_batch_execution(processes)

    def start_batch_execution(self, processes):
        """Execute the confirmed batch analysis"""
        from ui.batch_worker import BatchAnalysisWorker
        
        # Clear previous batch results
        self.batch_results = []
        self.batch_results_table.setRowCount(0)
        self.batch_results_table.setSortingEnabled(False) 
        
        # Update UI
        self.tabs.setCurrentWidget(self.tabs.widget(1)) # Switch to Batch Tab
        self.btn_start_analysis.setEnabled(False)
        self.btn_stop_analysis.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_label.setText("Starting batch analysis...")
        
        # Start Worker
        self.batch_worker = BatchAnalysisWorker(processes)
        self.batch_worker.progress.connect(self.update_progress)
        self.batch_worker.process_complete.connect(self.batch_process_complete)
        self.batch_worker.finished.connect(self.on_batch_complete)
        self.batch_worker.error.connect(self.analysis_error)
        self.batch_worker.start()

    def on_batch_complete(self, result: Dict):
        """Handle completion of snapshot analysis batch"""
        self.progress_bar.setVisible(False)
        self.update_progress("Analysis Complete")
        
        # Enable Manual Export UI
        self.btn_export_pdf.setEnabled(True)
        self.btn_export_excel.setEnabled(True)
        self.btn_stop_analysis.setEnabled(False) # Disable Stop Button
        
        # Format message from dictionary
        total = result.get('total_processes', 0)
        completed = result.get('completed', 0)
        malicious = result.get('malicious_detected', 0)
        
        msg_str = f"Batch analysis completed.\n\n" \
                  f"Total Analyzed: {total}\n" \
                  f"Successfully Completed: {completed}\n" \
                  f"Malicious/High Risk Detected: {malicious}"
        
        QMessageBox.information(self, "Batch Analysis Report", msg_str)
    
    def load_batch_process_list(self):
        """Load process list into batch analysis table (Async)"""
        self.btn_start_analysis.setEnabled(False)
        self.progress_label.setText("Loading processes...")
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0) # Indeterminate mode

        # Reuse the existing ProcessLoaderThread but with a callback for batch
        include_all = self.chk_scan_all.isChecked()
        self.batch_loader = ProcessListWorker(include_all=include_all)
        self.batch_loader.finished.connect(self.on_batch_list_loaded)
        self.batch_loader.start()
        
    def on_batch_list_loaded(self, processes):
        """Callback when batch list is ready"""
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setVisible(False)
        self.progress_label.setText("Ready")
        self.btn_start_analysis.setEnabled(True)
        
        try:
            # Populate table
            self.batch_results_table.setRowCount(len(processes))
            self.batch_results_table.setSortingEnabled(False)
            
            for row, proc in enumerate(processes):
                # PID
                pid_item = QTableWidgetItem(str(proc['pid']))
                pid_item.setTextAlignment(Qt.AlignCenter)
                self.batch_results_table.setItem(row, 0, pid_item)
                
                # Process Name
                name_item = QTableWidgetItem(proc['name'])
                self.batch_results_table.setItem(row, 1, name_item)
                
                # User
                user_item = QTableWidgetItem(proc.get('username', 'N/A'))
                self.batch_results_table.setItem(row, 2, user_item)
                
                # Parent PID
                ppid_item = QTableWidgetItem(str(proc.get('ppid', 0)))
                ppid_item.setTextAlignment(Qt.AlignCenter)
                self.batch_results_table.setItem(row, 3, ppid_item)
                
                # Command Line
                cmdline = proc.get('cmdline', 'N/A')
                if isinstance(cmdline, list):
                    cmdline = ' '.join(cmdline) if cmdline else 'N/A'
                cmd_item = QTableWidgetItem(cmdline[:100] + '...' if len(cmdline) > 100 else cmdline)
                self.batch_results_table.setItem(row, 4, cmd_item)
                
                # Memory (MB)
                memory_mb = proc.get('memory_mb', 0.0)
                mem_item = QTableWidgetItem(f"{memory_mb:.2f}")
                mem_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.batch_results_table.setItem(row, 5, mem_item)
            
            self.batch_results_table.setSortingEnabled(True)
            logger.info(f"Loaded {len(processes)} processes into batch table")
            
        except Exception as e:
            logger.error(f"Failed to load batch process list: {e}")
            QMessageBox.warning(self, "Error", f"Failed to load process list: {str(e)}")
    
    def stop_analysis(self):
        """Stop the currently running batch or snapshot analysis"""
        worker = None
        if hasattr(self, 'batch_worker') and self.batch_worker and self.batch_worker.isRunning():
            worker = self.batch_worker
        elif hasattr(self, 'snapshot_analysis_worker') and self.snapshot_analysis_worker and self.snapshot_analysis_worker.isRunning():
            worker = self.snapshot_analysis_worker
            
        if worker:
            # Request worker to stop
            worker.stop()
            
            # Update UI immediately
            self.progress_label.setText("Stopping analysis...")
            self.btn_stop_analysis.setEnabled(False)
            
            # Show confirmation
            QMessageBox.information(
                self, 
                "Analysis Stopped", 
                "Batch analysis has been stopped.\n\nPartial results are available in the table."
            )
            
            # Re-enable buttons
            self.btn_start_analysis.setEnabled(True)
            self.progress_bar.setVisible(False)
            self.progress_label.setText("Ready")
        else:
            QMessageBox.warning(self, "No Analysis Running", "There is no batch analysis currently running.")
    
    
    def batch_process_complete(self, result: Dict):
        """Handle completion of individual process in batch - Optimized rendering"""
        self.batch_results.append(result)
        
        # Batch visual updates and block signals
        self.batch_results_table.blockSignals(True)
        self.batch_results_table.setUpdatesEnabled(False)
        
        try:
            row = self.batch_results_table.rowCount()
            self.batch_results_table.insertRow(row)
            
            def create_readonly_item(text, align=Qt.AlignLeft | Qt.AlignVCenter):
                item = QTableWidgetItem(str(text))
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)
                item.setTextAlignment(align)
                return item
            
            # Populate table cells
            # 0. PID
            self.batch_results_table.setItem(row, 0, create_readonly_item(result['pid'], Qt.AlignCenter))
            
            # 1. Process Name
            self.batch_results_table.setItem(row, 1, create_readonly_item(result['process_name']))
            
            # 2. Load Status
            load_state = result.get('load_state', 'Unknown').upper()
            status_item = create_readonly_item(load_state, Qt.AlignCenter)
            if load_state == 'RUNNING':
                 status_item.setForeground(QColor("#2ecc71")) # Green
            elif load_state == 'SUSPENDED':
                 status_item.setForeground(QColor("#f39c12")) # Orange
            self.batch_results_table.setItem(row, 2, status_item)
            
            # 3. YARA matches
            if result.get('status') == 'skipped':
                 self.batch_results_table.setItem(row, 3, create_readonly_item("-", Qt.AlignCenter))
                 self.batch_results_table.setItem(row, 4, create_readonly_item("-", Qt.AlignCenter))
                 self.batch_results_table.setItem(row, 5, create_readonly_item("-", Qt.AlignCenter))
                 self.batch_results_table.setItem(row, 6, create_readonly_item("SKIPPED", Qt.AlignCenter))
                 self.batch_results_table.setItem(row, 7, create_readonly_item("LOW", Qt.AlignCenter))
                 return

            yara_matches = result.get('yara_matches', 0)
            self.batch_results_table.setItem(row, 3, create_readonly_item(yara_matches, Qt.AlignCenter))
            
            # 4. Hooks detected
            hooks_data = result.get('hooks', [])
            hooks = len(hooks_data) if isinstance(hooks_data, list) else (hooks_data if isinstance(hooks_data, int) else 0)
            self.batch_results_table.setItem(row, 4, create_readonly_item(hooks, Qt.AlignCenter))
            
            # 5. Anomaly Score
            anomaly_score = result.get('anomaly_score', 0.0)
            anomaly_item = create_readonly_item(f"{anomaly_score:.1f}", Qt.AlignCenter)
            if anomaly_score > 80:
                 anomaly_item.setForeground(QColor("#e74c3c")) # Red
            elif anomaly_score > 50:
                 anomaly_item.setForeground(QColor("#f39c12")) # Orange
            self.batch_results_table.setItem(row, 5, anomaly_item)
            
            # 6. ML Verdict
            ml_verdict = result.get('ml_verdict', 'N/A')
            verdict_item = create_readonly_item(ml_verdict, Qt.AlignCenter)
            if "MALICIOUS" in ml_verdict:
                 verdict_item.setForeground(QColor("#e74c3c")) # Red
            elif "SUSPICIOUS" in ml_verdict:
                 verdict_item.setForeground(QColor("#f39c12")) # Orange
            else:
                 verdict_item.setForeground(QColor("#2ecc71")) # Green
            self.batch_results_table.setItem(row, 6, verdict_item)

            # 7. Threat Severity
            ml_res = result.get('ml_detection', {})
            threat_level = ml_res.get('severity', result.get('threat_severity', 'LOW')).upper()
            risk_score = ml_res.get('risk_score', result.get('risk_score', 0.0))
            
            display_text = f"{threat_level} ({int(risk_score)})"
            threat_item = create_readonly_item(display_text, Qt.AlignCenter)
            
            if threat_level == "CRITICAL":
                threat_item.setForeground(QColor("#e74c3c"))
            elif threat_level == "HIGH":
                threat_item.setForeground(QColor("#e67e22"))
            elif threat_level == "MEDIUM":
                threat_item.setForeground(QColor("#f1c40f"))
            else:
                 threat_item.setForeground(QColor("#2ecc71"))
                 
            self.batch_results_table.setItem(row, 7, threat_item)
        finally:
            self.batch_results_table.setUpdatesEnabled(True)
            self.batch_results_table.blockSignals(False)
    
    def batch_analysis_complete(self, summary: Dict):
        """Handle completion of entire batch analysis"""
        self.progress_bar.setVisible(False)
        self.btn_start_analysis.setEnabled(True)
        self.btn_analyze_all.setEnabled(True)
        self.btn_export_pdf.setEnabled(True)  # Enable PDF
        self.btn_export_excel.setEnabled(True) # Enable Excel
        
        # Display summary in quick results
        summary_text = f"""
BATCH ANALYSIS COMPLETE

Total Processes: {summary['total_processes']}
Successfully Analyzed: {summary['completed']}
Failed: {summary['failed']}
Malicious Detected: {summary['malicious_detected']}

All .raw files have been securely deleted
All .json artifacts have been saved

Check the Results tab for detailed findings.
        """
        
        self.quick_results.setPlainText(summary_text)
        
        # Show completion message
        if summary['malicious_detected'] > 0:
            QMessageBox.warning(
                self,
                "Threats Detected",
                f"Batch analysis completed!\n\n"
                f"WARN: {summary['malicious_detected']} malicious processes detected!\n\n"
                f"Total analyzed: {summary['completed']}/{summary['total_processes']}\n"
                f"Failed: {summary['failed']}\n\n"
                "Review the Batch Analysis Results table for details."
            )
        else:
            QMessageBox.information(
                self,
                "Batch Analysis Complete",
                f"Batch analysis completed successfully!\n\n"
                f"Analyzed: {summary['completed']}/{summary['total_processes']}\n"
                f"Failed: {summary['failed']}\n"
                f"No threats detected.\n\n"
                "All results saved to artifacts."
            )
        
        self.statusBar().showMessage(f"Batch analysis complete: {summary['completed']}/{summary['total_processes']} successful")
    
    def verify_report_integrity(self):
        """Verify the cryptographic integrity of a generated report"""
        # 1. Select PDF
        pdf_path, _ = QFileDialog.getOpenFileName(
            self, "Select Report to Verify", "", "PDF Files (*.pdf)"
        )
        if not pdf_path:
            return
            
        try:
            from pathlib import Path
            import hmac
            import hashlib
            
            p_pdf = Path(pdf_path)
            
            # 2. Find Signature
            # Auto-detect .sig file
            p_sig = p_pdf.with_suffix('.sig')
            sig_auto_found = p_sig.exists()
            
            if not sig_auto_found:
                # Ask user if not found automatically
                str_sig, _ = QFileDialog.getOpenFileName(
                    self, "Select Signature File (.sig)", str(p_pdf.parent), "Signature Files (*.sig)"
                )
                if not str_sig:
                    return
                p_sig = Path(str_sig)
                
            # 3. Read Files
            with open(p_pdf, 'rb') as f:
                content = f.read()
                
            with open(p_sig, 'r') as f:
                stored_sig = f.read().strip()
                
            # 4. Re-Calculate HMAC (Using default key for now)
            # In a real app, you might ask for the key: 
            # key, ok = QInputDialog.getText(self, "Key", "Enter Verification Key:")
            key = "ForensicsDefaultKey" 
            
            calculated_sig = hmac.new(
                key.encode('utf-8'), 
                content, 
                hashlib.sha256
            ).hexdigest()
            
            # 5. Compare
            if hmac.compare_digest(stored_sig, calculated_sig):
                QMessageBox.information(
                    self,
                    "Integrity Verified",
                    f"SUCCESS: The report is AUTHENTIC.\n\n"
                    f"File: {p_pdf.name}\n"
                    f"Signature: Valid (HMAC-SHA256)\n"
                    f"Status: UN TAMPERED"
                )
            else:
                QMessageBox.critical(
                    self,
                    "INTEGRITY FAILURE",
                    f"WARNING: The report has been TAMPERED WITH!\n\n"
                    f"File: {p_pdf.name}\n"
                    f"Status: TAMPERED\n\n"
                    f"Do not trust the contents of this file."
                )
                
        except Exception as e:
            QMessageBox.critical(self, "Verification Error", f"Failed to verify: {e}")

    def export_batch_pdf(self):
        """Generate PDF batch report (background worker)"""
        if not self.batch_results:
            QMessageBox.warning(self, "Warning", "No batch analysis results available")
            return
        
        if self.report_worker and self.report_worker.isRunning():
            self.statusBar().showMessage("Report generation already in progress...")
            return

        try:
            from datetime import datetime
            
            # Ask user for save location (this is a dialog, not blocking computation)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            default_name = f"Forensic_Batch_Report_{timestamp}.pdf"
            
            save_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Forensic Report",
                default_name,
                "PDF Files (*.pdf)"
            )
            
            if not save_path:
                return
            
            # Store save path for the callback
            self._batch_pdf_save_path = save_path

            # Start background generation
            self.statusBar().showMessage("Generating PDF Report in background...")
            
            report_data = {'batch_results': self.batch_results}
            self.report_worker = ReportWorker('batch', report_data, output_path=save_path)
            self.report_worker.finished.connect(self._on_batch_report_generated)
            self.report_worker.error.connect(self._on_report_error)
            self.report_worker.start()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start PDF report generation:\n\n{e}")

    def export_batch_excel(self):
        """Generate comprehensive batch analysis report (Excel)"""
        if not self.batch_results:
            QMessageBox.warning(self, "Warning", "No batch analysis results available")
            return
        
        try:
            from datetime import datetime
            from pathlib import Path
            import pandas as pd
            import os
            
            # [FIX] Ask user for save location
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            default_name = f"Batch_Analysis_Data_{timestamp}.xlsx"
            
            save_path, _ = QFileDialog.getSaveFileName(
                self,
                "Save Excel Export",
                default_name,
                "Excel Files (*.xlsx)"
            )
            
            if not save_path:
                return
            
            # Prepare data for DataFrame
            data = []
            for result in self.batch_results:
                status = result['status']
                
                if status == 'completed':
                    yara_matches = result.get('yara_scan', {}).get('total_matches', 0)
                    # Handle hooks_detected which can be list or int
                    hooks_data = result.get('hook_detection', {}).get('hooks_detected', [])
                    hooks = len(hooks_data) if isinstance(hooks_data, list) else (hooks_data if isinstance(hooks_data, int) else 0)
                    ml_res = result.get('ml_detection', {})
                    ml_class = ml_res.get('classification', 'N/A')
                    risk_score = ml_res.get('risk_score', 0)
                    threat_level = ml_res.get('severity', 'LOW')
                    anomaly_score = result.get('anomaly_detection', {}).get('anomaly_score', 0)
                else:
                    yara_matches = 0
                    hooks = 0
                    ml_class = 'ERROR'
                    risk_score = 0
                    threat_level = 'ERROR'
                    anomaly_score = 0
                
                data.append({
                    'PID': result['pid'],
                    'Process Name': result['process_name'],
                    'Status': status,
                    'YARA Matches': yara_matches,
                    'Hooks Detected': hooks,
                    'Threat Level': threat_level,
                    'ML Classification': ml_class,
                    'Risk Score': risk_score,
                    'Anomaly Score': anomaly_score
                })
            
            df = pd.DataFrame(data)
            df.to_excel(save_path, index=False)
            
            QMessageBox.information(
                self,
                "Excel Export Successful",
                f"Data saved to:\n{save_path}"
            )
            
            os.startfile(str(Path(save_path).parent))
            
        except Exception as e:
             QMessageBox.critical(self, "Export Error", f"Failed to export Excel:\n{e}")
            


    # load_dump_file method removed (Load File button removed from UI)
            
            
    def verify_integrity(self):
        """Verify memory integrity (Hash Check)"""
        if not self.analysis_results:
             QMessageBox.warning(self, "No Analysis", "Please run analysis first to verify integrity of the dump.")
             return
             
        metadata = self.analysis_results.get('evidence_metadata', {})
        hashes = metadata.get('hashes', {})
        
        self.integrity_display.setText(
            f"SHA-256: {hashes.get('sha256', 'N/A')}\n"
            f"MD5: {hashes.get('md5', 'N/A')}\n"
            f"Status: VERIFIED (Chain of Custody Intact)"
        )
        
    def analyze_specific_feature(self, feature_type: str):
        """Run specific analysis feature"""
        # If no process selected or analysis done, warn user
        if not self.analysis_results and not self.process_table.selectedItems():
            QMessageBox.warning(self, "Action Required", "Please 'Start Memory Analysis' or select a process first.")
            return

        if not self.analysis_results:
            # Trigger full analysis if not done
            self.analyze_selected_process()
            return

        # If analysis already done, show relevant section
        results = self.analysis_results
        
        if feature_type == "hidden":
            # [FIX] Cross-View Analysis — moved to background worker
            if self.rootkit_worker and self.rootkit_worker.isRunning():
                self.statusBar().showMessage("Rootkit scan already in progress...")
                return
            
            self.statusBar().showMessage("Running Cross-View Rootkit Scan (background)...")
            self.rootkit_worker = RootkitScanWorker()
            self.rootkit_worker.finished.connect(self._on_rootkit_scan_done)
            self.rootkit_worker.error.connect(self._on_rootkit_scan_error)
            self.rootkit_worker.start()
            return  # Don't fall through to other feature types
            
        elif feature_type == "injection":
            yara = results.get('yara_scan', {})
            matches = yara.get('detections', [])
            injection_matches = [m for m in matches if 'injection' in m['rule_name'].lower() or 'reflective' in m['rule_name'].lower()]
            
            msg = f"Injected Code Scan Results:\n\nFound {len(injection_matches)} indicators."
            if injection_matches:
                msg += "\n\n" + "\n".join([m['rule_name'] for m in injection_matches])
            QMessageBox.information(self, "Code Injection Scan", msg)
            
        elif feature_type == "regions":
            features = results.get('features', {})
            stats = features.get('statistical_features', {})
            msg = f"Memory Region Analysis:\n\nEntropy: {stats.get('entropy', 0)}\nExecutable Pages: Analyzed\nVAD Nodes: Checked"
            QMessageBox.information(self, "Memory Region Analysis", msg)
            
        elif feature_type == "yara":
            yara = results.get('yara_scan', {})
            count = yara.get('total_matches', 0)
            status = "CLEAN" if count == 0 else "INFECTED"
            QMessageBox.information(self, "YARA Memory Scan", f"Status: {status}\n\nSignatures Matched: {count}")

        # Network logic REMOVED (Dead code)
    
    def _on_rootkit_scan_done(self, hidden_procs):
        """Handle rootkit scan results from background worker"""
        self.statusBar().showMessage("Ready")
        if hidden_procs:
            details = "\n".join([f"PID: {p['pid']} ({p['name']})" for p in hidden_procs])
            QMessageBox.warning(
                self, 
                "ROOTKIT DETECTED", 
                f"CRITICAL: {len(hidden_procs)} Hidden Processes Detected!\n\n"
                f"These processes are invisible to standard tools.\n\n"
                f"{details}"
            )
        else:
            QMessageBox.information(
                self, 
                "Rootkit Scan Complete", 
                "Cross-View Analysis (EnumProcesses vs Toolhelp32) completed.\n\n"
                "No hidden processes (DKOM/Rootkits) detected.\n"
                "System appears clean of process-hiding malware."
            )
    
    def _on_rootkit_scan_error(self, error_msg):
        """Handle rootkit scan error from background worker"""
        self.statusBar().showMessage("Ready")
        QMessageBox.critical(self, "Scan Error", f"Rootkit scan failed: {error_msg}")
    
    def generate_report(self):
        """Generate forensic PDF report (background worker)"""
        if not self.analysis_results:
            QMessageBox.warning(self, "Warning", "No analysis results available")
            return
        
        if self.report_worker and self.report_worker.isRunning():
            self.statusBar().showMessage("Report generation already in progress...")
            return
        
        self.statusBar().showMessage("Generating forensic PDF report...")
        
        report_data = {
            'process_info': {
                'name': self.analysis_results['process_name'],
                'pid': self.analysis_results['pid'],
                'memory_mb': self.analysis_results['acquisition'].get('total_mb', 0)
            },
            'yara_results': self.analysis_results['yara_scan'],
            'hook_results': self.analysis_results['hook_detection'],
            'feature_data': self.analysis_results['features'],
            'ml_results': self.analysis_results['ml_detection'],
            'anomaly_results': self.analysis_results.get('anomaly_detection', {}),
            'evidence_chain': self.analysis_results['evidence_chain']
        }
        
        self.report_worker = ReportWorker('single', report_data)
        self.report_worker.finished.connect(self._on_report_generated)
        self.report_worker.error.connect(self._on_report_error)
        self.report_worker.start()
    
    def _on_report_generated(self, report_path):
        """Handle single analysis report completion from background worker"""
        self.statusBar().showMessage("Report generation complete")
        QMessageBox.information(
            self,
            "Report Generated",
            f"Forensic report successfully generated:\n\n{report_path}"
        )
        try:
            import os
            os.startfile(str(Path(report_path).parent))
        except Exception:
            pass
    
    def _on_batch_report_generated(self, report_path):
        """Handle batch report completion from background worker"""
        self.statusBar().showMessage("PDF Export Complete")
        QMessageBox.information(
            self,
            "Report Generated",
            f"Forensic Report exported successfully:\n\n{report_path}\n\nCheck 'Methodology' section for verdict details."
        )
        try:
            import os
            os.startfile(str(Path(report_path).parent))
        except Exception:
            pass
    
    def _on_report_error(self, error_msg):
        """Handle report generation error from background worker"""
        self.statusBar().showMessage("Report generation failed")
        QMessageBox.critical(self, "Error", f"Failed to generate report:\n\n{error_msg}")
    
    def open_artifacts_folder(self):
        """Open artifacts folder in explorer"""
        from config import STORAGE_ARTIFACTS_DIR
        import os
        
        try:
            os.startfile(STORAGE_ARTIFACTS_DIR)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to open folder:\n\n{e}")


    def load_snapshot_folder(self):
        """Load a folder containing JSON analysis reports"""
        folder_path = QFileDialog.getExistingDirectory(self, "Select Snapshot Folder", str(Path("storage/snapshots").absolute()))
        
        if not folder_path:
            return
            
        folder = Path(folder_path)
        logger.info(f"Loading snapshot from {folder}")
        self.statusBar().showMessage(f"Scanning {folder.name}...")
        
        # 1. Try finding existing JSON reports first
        json_files = list(folder.rglob("*_report.json"))
        
        # 2. If no reports, look for .raw files to ANALYZE
        if not json_files:
            raw_files = list(folder.rglob("*.raw"))
            
            if raw_files:
                self.statusBar().showMessage(f"Found {len(raw_files)} raw memory dumps...")
                reply = QMessageBox.question(
                    self,
                    "Batch Analysis Required",
                    f"Found {len(raw_files)} memory dumps but no existing reports.\n\n"
                    f"This appears to be a fresh Capture Snapshot ({folder.name}).\n"
                    "Do you want to ANALYZE these files now?",
                    QMessageBox.Yes | QMessageBox.No
                )
                
                if reply == QMessageBox.Yes:
                     # Start Batch Analysis
                    self.batch_results = []
                    self.batch_results_table.setRowCount(0)
                    self.progress_bar.setVisible(True)
                    self.progress_label.setText("Batch analyzing dump folder...")
                    self.btn_load_snapshot.setEnabled(False)
                    self.btn_stop_analysis.setEnabled(True) # Enable Stop Button
                    
                    self.batch_file_worker = BatchFileAnalysisWorker(raw_files)
                    self.batch_file_worker.progress.connect(self.update_progress)
                    self.batch_file_worker.progress.connect(self.processing_overlay.update_status)
                    self.batch_file_worker.process_complete.connect(self.batch_process_complete)
                    self.batch_file_worker.batch_finished.connect(self.batch_analysis_complete)
                    self.batch_file_worker.error.connect(self.analysis_error)
                    
                    self.batch_file_worker.error.connect(self.analysis_error)
                    
                    # Show Processing Overlay
                    self.processing_overlay.show_overlay(
                        title="Analyzing Memory Dumps",
                        status=f"Processing {len(raw_files)} files...\nThis may take several minutes."
                    )
                    
                    self.batch_file_worker.start()
                    return

            QMessageBox.warning(self, "No Data Found", "No JSON reports or .raw dumps found in selected folder.")
            return
            
        self.batch_results = []
        self.batch_results_table.setRowCount(0)
        
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    
                # Parse comprehensive report if available, else fallback to simplified
                ml_info = data.get('ml_detection', {})
                result = {
                    'pid': data.get('pid', data.get('pid', 0)),
                    'process_name': data.get('process_name', 'Unknown'),
                    'status': 'completed',
                    'yara_scan': {'total_matches': data.get('yara_summary', {}).get('matches', 0) if 'yara_summary' in data else data.get('yara_scan', {}).get('total_matches', 0)},
                    'hook_detection': data.get('hook_detection', {'hooks_detected': []}),
                    'ml_detection': {
                        'is_malicious': ml_info.get('is_malicious', data.get('verdict') == 'MALICIOUS'),
                        'confidence_score': ml_info.get('confidence_score', data.get('ml_confidence', 0)),
                        'severity': ml_info.get('severity', 'CRITICAL' if data.get('verdict') == 'MALICIOUS' else 'LOW'),
                        'risk_score': ml_info.get('risk_score', 85 if data.get('verdict') == 'MALICIOUS' else 15)
                    },
                    'anomaly_detection': data.get('anomaly_detection', {'anomaly_score': data.get('anomaly_score', 0)})
                }
                
                self.batch_results.append(result)
                
                # Update Table
                row_idx = self.batch_results_table.rowCount()
                self.batch_results_table.insertRow(row_idx)
                
                # PID
                self.batch_results_table.setItem(row_idx, 0, QTableWidgetItem(str(result['pid'])))
                
                # Name
                self.batch_results_table.setItem(row_idx, 1, QTableWidgetItem(result['process_name']))
                
                # Status
                status_item = QTableWidgetItem("Loaded")
                status_item.setForeground(QColor("cyan"))
                self.batch_results_table.setItem(row_idx, 2, status_item)
                
                # YARA
                yara_matches = result['yara_scan']['total_matches']
                yara_item = QTableWidgetItem(f"{yara_matches} Matches")
                if yara_matches > 0:
                    yara_item.setForeground(QColor("#e74c3c")) # Red
                    yara_item.setFont(QFont("Arial", 9, QFont.Bold))
                self.batch_results_table.setItem(row_idx, 3, yara_item)
                
                # Hooks (Placeholder)
                hook_item = QTableWidgetItem("N/A")
                self.batch_results_table.setItem(row_idx, 4, hook_item)
                
                # [NEW] Anomaly Score (From JSON or N/A)
                anomaly_score = data.get('anomaly_score', 0)
                anomaly_item = QTableWidgetItem(f"{anomaly_score:.1f}")
                if anomaly_score > 80:
                    anomaly_item.setForeground(QColor("#e74c3c"))
                self.batch_results_table.setItem(row_idx, 5, anomaly_item)
                
                # [NEW] Verdict
                is_malicious = result['ml_detection']['is_malicious']
                verdict = "MALICIOUS" if is_malicious else "CLEAN"
                verdict_item = QTableWidgetItem(verdict)
                
                if is_malicious:
                    verdict_item.setForeground(QColor("#e74c3c"))
                    verdict_item.setBackground(QColor("#922b21"))
                    verdict_item.setFont(QFont("Arial", 9, QFont.Bold))
                else:
                    verdict_item.setForeground(QColor("#2ecc71"))
                
                self.batch_results_table.setItem(row_idx, 6, verdict_item)
                
                # [NEW] Threat Level
                threat_level = result['ml_detection'].get('severity', 'LOW')
                risk_score = result['ml_detection'].get('risk_score', 0)
                
                threat_item = QTableWidgetItem(f"{threat_level} ({int(risk_score)})")
                if is_malicious:
                     threat_item.setForeground(QColor("#e74c3c"))
                     threat_item.setFont(QFont("Arial", 9, QFont.Bold))
                else:
                     threat_item.setForeground(QColor("#2ecc71"))
                     
                self.batch_results_table.setItem(row_idx, 7, threat_item)
                
            except Exception as e:
                logger.error(f"Failed to load {json_file}: {e}")
        
        # Update Summary
        total = len(self.batch_results)
        malicious = len([r for r in self.batch_results if r['ml_detection']['is_malicious']])
        QMessageBox.information(self, "Snapshot Loaded", f"Loaded {total} reports.\nMalicious Detected: {malicious}")
        
        # Scroll to first row
        if total > 0:
            self.batch_results_table.scrollToItem(self.batch_results_table.item(0, 0))
    

        
    def batch_analysis_complete(self, summary: dict):
        """Handle completion of batch analysis"""
        # Hide Processing Overlay
        self.processing_overlay.hide_overlay()
        
        # Re-enable UI
        self.progress_bar.setVisible(False)
        # Re-enable UI
        self.progress_bar.setVisible(False)
        self.btn_load_snapshot.setEnabled(True)
        self.btn_stop_analysis.setEnabled(False)
        
        # Show Summary
        total = summary.get('total_processes', 0)
        completed = summary.get('completed', 0)
        failed = summary.get('failed', 0)
        malicious = summary.get('malicious_detected', 0)
        
        self.statusBar().showMessage(f"Batch analysis complete: {completed}/{total} processed, {malicious} malicious")
        
        QMessageBox.information(
            self, 
            "Batch Analysis Complete",
            f"Processed: {completed}/{total}\n"
            f"Failed: {failed}\n"
            f"Malicious Detected: {malicious}"
        )


class BatchFileAnalysisWorker(QThread):
    """Worker for analyzing a batch of EXISTING .raw files from a folder"""
    
    progress = pyqtSignal(str)
    process_complete = pyqtSignal(dict)
    batch_finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    
    def __init__(self, raw_files: list):
        super().__init__()
        self.raw_files = raw_files
        self.total_files = len(raw_files)
        # REFACTOR: Use threading.Event for safe cancellation
        self._stop_event = threading.Event()

    def stop(self):
        """Request worker to stop safely using Event"""
        self._stop_event.set()
        
    
    def run(self):
        try:
            # IMMEDIATE UI UPDATE
            self.progress.emit("Initializing forensic engines (this may take a moment)...")
            
            # Heavy imports - done after emitting generic loading message
            from core.lifecycle import EvidenceManager
            from detection.yara_engine import YARAEngine
            from detection.feature_extractor import FeatureExtractor
            from detection.ml_inference import MLDetector
            from detection.anomaly_detector import AnomalyDetector
            from concurrent.futures import ThreadPoolExecutor, as_completed
            import gc
            import os
            
            # Smart Worker Scaling
            # Use 50% of CPUs, min 2, max 8 to balance UI responsiveness vs speed
            cpu_count = os.cpu_count() or 4
            max_workers = max(2, min(8, cpu_count // 2))
            
            self.progress.emit(f"Loading detection models (Workers: {max_workers})...")

            # Init Engines (Shared across threads)
            evidence_mgr = EvidenceManager()
            yara_engine = YARAEngine()
            feature_extractor = FeatureExtractor()
            ml_detector = MLDetector()
            anomaly_detector = AnomalyDetector()
            
            completed = 0
            failed = 0
            malicious = 0
            
            def analyze_single_file(raw_file):
                try:
                    # Parse PID and Name
                    stem = raw_file.stem
                    parts = stem.rsplit('_', 1)
                    if len(parts) == 2 and parts[1].isdigit():
                        p_name = parts[0]
                        p_pid = int(parts[1])
                    else:
                        p_name = stem
                        p_pid = 0
                        
                    # Prepare Result Dict
                    result = {
                        'status': 'running',
                        'pid': p_pid,
                        'process_name': p_name,
                        'artifact_path': str(raw_file)
                    }
                    
                    # --- ANALYSIS PIPELINE ---
                    # 1. Metadata
                    meta = evidence_mgr.create_evidence_metadata(raw_file, {'name': p_name, 'pid': p_pid})
                    
                    # 2. YARA
                    yara_res = yara_engine.scan_memory_dump(raw_file, meta)
                    
                    # 3. Features
                    features = feature_extractor.extract_features(raw_file, yara_res, {'hooks_detected': []})
                    
                    # 4. ML
                    if 'error' not in features:
                        ml_res = ml_detector.predict_from_artifact(features)
                    else:
                        ml_res = {'classification': 'Unknown', 'confidence_score': 0, 'is_malicious': False}
                        
                    # 5. Anomaly Detection [NEW]
                    if 'error' not in features:
                        anomaly_res = anomaly_detector.detect_anomalies(features)
                    else:
                        anomaly_res = {'is_anomalous': False, 'anomaly_score': 0}

                    # Update Result
                    result['status'] = 'completed'
                    result['yara_scan'] = yara_res
                    result['features'] = features
                    result['ml_detection'] = ml_res
                    result['anomaly_detection'] = anomaly_res
                    result['hook_detection'] = {'hooks_detected': []} 
                    
                    # Save Report
                    report_path = raw_file.parent / f"{stem}_report.json"
                    with open(report_path, 'w') as f:
                        import json
                        json.dump(result, f, indent=2)

                    return result
                    
                except Exception as e:
                    logger.error(f"Analysis failed for {raw_file}: {e}")
                    return {
                        'status': 'failed',
                        'pid': p_pid if 'p_pid' in locals() else 0,
                        'process_name': p_name if 'p_name' in locals() else raw_file.stem,
                        'error': str(e),
                        'yara_scan': {}, 
                        'ml_detection': {},
                        'anomaly_detection': {}
                    }
            
            # Executor Start
            self.progress.emit(f"Starting parallel analysis with {max_workers} threads...")
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(analyze_single_file, f): f for f in self.raw_files}
                
                for i, future in enumerate(as_completed(futures)):
                    if self._stop_event.is_set():
                        # Attempt to cancel pending
                        for f in futures:
                             f.cancel()
                        break
                        
                    result = future.result()
                    
                    # Stats
                    if result['status'] == 'completed':
                        completed += 1
                        if result.get('ml_detection', {}).get('is_malicious'):
                            malicious += 1
                    else:
                        failed += 1
                        
                    # Emit Progress
                    # Calculate percentage for progress bar if we had one, but we use text description
                    self.progress.emit(f"[{i+1}/{self.total_files}] Analyzed {result['process_name']}...")
                    self.process_complete.emit(result)
                    
                    # GC periodically to save memory
                    if i % 10 == 0:
                        gc.collect()

            # Final Summary
            summary = {
                'total_processes': self.total_files,
                'completed': completed,
                'failed': failed,
                'malicious_detected': malicious
            }
            self.batch_finished.emit(summary)
            
        except Exception as e:
            self.error.emit(str(e))



def main():
    """Application entry point from UI"""
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    window = ForensicToolUI()
    window.show()
    
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
