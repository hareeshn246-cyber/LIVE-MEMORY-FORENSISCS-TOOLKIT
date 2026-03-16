import os
import time
import psutil
import threading
import gc
from PyQt5.QtCore import QThread, pyqtSignal, QRunnable, QThreadPool, QObject

# Import core modules
from core.acquisition import MemoryAcquisition
from core.integrity import HookDetector
from detection.yara_engine import YARAEngine
from detection.feature_extractor import FeatureExtractor
from detection.ml_inference import MLDetector
from detection.anomaly_detector import AnomalyDetector
from config import get_temp_raw_path, MAX_ANALYSIS_SIZE_MB
import config
import logging

logger = logging.getLogger(__name__)

class AnalysisSignals(QObject):
    """Signals for threaded analysis tasks"""
    complete = pyqtSignal(dict)
    error = pyqtSignal(str)

class ProcessAnalysisTask(QRunnable):
    """
    QRunnable for analyzing a single process dump.
    Allows parallel analysis of multiple dumps.
    """
    def __init__(self, proc_data, results_base, engines):
        super().__init__()
        self.proc = proc_data
        self.results = results_base
        self.engines = engines
        self.signals = AnalysisSignals()
        
    def run(self):
        try:
            pid = self.proc['pid']
            process_name = self.proc['name']
            dump_path = self.results.get('dump_path')
            
            yara_engine = self.engines['yara']
            feature_extractor = self.engines['feature_extractor']
            anomaly_detector = self.engines['anomaly_detector']
            ml_detector = self.engines['ml_detector']
            
            # 3. YARA Scan
            yara_res = yara_engine.scan_memory_dump(dump_path, {})
            self.results['yara_matches'] = yara_res.get('total_matches', 0)
            
            # 4. Feature Extraction
            features = feature_extractor.extract_features(dump_path, yara_res, {'hooks_detected': self.results['hooks']})
            features['metadata'] = {'exe_path': self.results.get('exe_path', '')}
            self.results['features'] = features
            
            # 5. Anomaly Detection
            anomaly_res = anomaly_detector.detect_anomalies(features)
            self.results['anomaly_score'] = anomaly_res.get('anomaly_score', 0.0)
            
            # 6. ML Inference (UNIFIED SCORING)
            ml_res = ml_detector.predict_from_artifact(features)
            
            self.results['ml_verdict'] = ml_res.get('classification', 'UNKNOWN')
            self.results['risk_score'] = ml_res.get('risk_score', 0.0)
            self.results['threat_score'] = f"{self.results['risk_score']}/100"
            self.results['threat_severity'] = ml_res.get('severity', 'LOW')
            self.results['risk_factors'] = ml_res.get('risk_factors', [])
            
            self.results['status'] = 'completed'
            
        except Exception as e:
            logger.error(f"Analysis failed for {self.proc['name']}: {e}")
            self.results['status'] = 'partial_error'
            self.results['error'] = str(e)
        finally:
            # Signal completion
            self.signals.complete.emit(self.results)
            # Cleanup memory
            gc.collect()

class BatchAnalysisWorker(QThread):
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict) # Emits summary
    process_complete = pyqtSignal(dict) # Emits individual result
    error = pyqtSignal(str)
    
    def __init__(self, process_list: list):
        super().__init__()
        self.process_list = process_list
        self.batch_results = []
        self.total_processes = len(process_list)
        self._stop_event = threading.Event()
        self.current_index = 0
        
        # Concurrency management
        self.thread_pool = QThreadPool.globalInstance()
        # Cap threads to prevent CPU/IO thrashing (e.g., 4 or CPU count)
        self.thread_pool.setMaxThreadCount(min(os.cpu_count() or 4, 4))
        
        # Acquisition Semaphore (Limit simultaneous captures)
        self.acq_semaphore = threading.Semaphore(2) 
        
        self.completed_tasks = 0
        self.active_tasks = 0
        self._results_mutex = threading.Lock()
    
    def stop(self):
        """Request worker to stop safely using Event"""
        self._stop_event.set()
    
    def on_task_complete(self, results):
        """Handle result from a parallel analysis task"""
        with self._results_mutex:
            self.batch_results.append(results)
            self.completed_tasks += 1
            self.active_tasks -= 1
            self.process_complete.emit(results)
            
            # If everything is done, emit finished
            if self.completed_tasks == self.total_processes or self._stop_event.is_set():
                self._emit_finished()

    def _emit_finished(self):
        completed_count = len([r for r in self.batch_results if r['status'] == 'completed'])
        failed_count = len([r for r in self.batch_results if r['status'] in ('error', 'failed')])
        malicious_count = len([r for r in self.batch_results if r.get('ml_verdict', 'CLEAN') in ('MALICIOUS', 'MALICIOUS_HIGH_CONFIDENCE', 'MALICIOUS_MEDIUM_CONFIDENCE', 'HIGH RISK')])
        
        self.finished.emit({
            'total_processes': self.total_processes,
            'completed': completed_count,
            'processed': len(self.batch_results),
            'failed': failed_count,
            'malicious_detected': malicious_count,
            'results': self.batch_results
        })

    def run(self):
        logger.info(f"Starting optimized batch analysis of {self.total_processes} processes")
        
        # Initialize Analysis Engines
        try:
            acquisition = MemoryAcquisition()
            yara_engine = YARAEngine()
            feature_extractor = FeatureExtractor()
            ml_detector = MLDetector()
            anomaly_detector = AnomalyDetector()
            hook_detector = HookDetector()

            engines = {
                'acquisition': acquisition,
                'yara': yara_engine,
                'feature_extractor': feature_extractor,
                'ml_detector': ml_detector,
                'anomaly_detector': anomaly_detector,
                'hook_detector': hook_detector
            }
            
            # Pre-checks
            if not yara_engine.rules:
                logger.warning("YARA rules not loaded")

            # [NEW] Advanced Mode Imports
            if config.ADVANCED_MODE:
                from forensics.registry_scan import scan_persistence_keys
                from detection.registry_detector import RegistryDetector
                from core.advanced_aggregator import calculate_advanced_risk

        except Exception as e:
            logger.error(f"Failed to initialize analysis engines: {e}")
            self.error.emit(f"Engine Initialization Failed: {e}")
            return

        for idx, proc in enumerate(self.process_list):
            if self._stop_event.is_set():
                break

            self.current_index = idx + 1
            pid = proc['pid']
            process_name = proc['name']
            
            self.progress.emit(f"[{self.current_index}/{self.total_processes}] Preparing {process_name} (PID: {pid})")
            
            results = {
                'status': 'starting',
                'pid': pid,
                'process_name': process_name,
                'memory_mb': proc.get('memory_mb', 0),
                'risk_score': 0.0,
                'ml_verdict': 'PENDING',
                'threat_severity': 'LOW',
                'exe_path': proc.get('exe_path', ''),
                'hooks': []
            }

            # 1. Quick Checks (Skipping etc.)
            if pid == os.getpid():
                results.update({'status': 'skipped', 'error': 'Self Analysis', 'ml_verdict': 'CLEAN'})
                self.on_task_complete(results)
                continue

            if proc.get('memory_mb', 0) > MAX_ANALYSIS_SIZE_MB:
                results.update({'status': 'skipped', 'error': f'Size > {MAX_ANALYSIS_SIZE_MB}MB', 'ml_verdict': 'SKIPPED'})
                self.on_task_complete(results)
                continue

            # 2. Sequential Acquisition (Limited by Semaphore)
            with self.acq_semaphore:
                if self._stop_event.is_set(): break
                
                self.progress.emit(f"[{self.current_index}/{self.total_processes}] Acquiring memory for {process_name}")
                
                # 2a. Live Hook Detection
                try:
                    hook_res = engines['hook_detector'].comprehensive_scan(pid)
                    results['hooks'] = hook_res.get('hooks_detected', [])
                except Exception as e:
                    logger.error(f"Hook scan error for {process_name}: {e}")
                    results['hooks'] = []

                # 2b. Memory Acquisition
                dump_path = get_temp_raw_path(process_name, pid)
                acq_res = engines['acquisition'].acquire_process_memory(pid, dump_path)
                
                if acq_res.get('status') != 'success':
                    results['status'] = 'error'
                    results['error'] = acq_res.get('error', 'Access Denied')
                    results['ml_verdict'] = 'ACCESS_DENIED'
                    if results['hooks']: 
                        results['risk_score'] = 10.0
                        results['threat_severity'] = 'SUSPICIOUS'
                    self.on_task_complete(results)
                    continue
                
                results['dump_path'] = dump_path

            # 3. Parallel Deep Analysis
            task = ProcessAnalysisTask(proc, results, engines)
            task.signals.complete.connect(self.on_task_complete)
            
            with self._results_mutex:
                self.active_tasks += 1
            
            self.thread_pool.start(task)

        # Wait for all parallel tasks to finish if we exited the loop
        if not self._stop_event.is_set():
            while True:
                with self._results_mutex:
                    if self.completed_tasks >= self.total_processes:
                        break
                time.sleep(0.5)
        else:
            # Stop pool if cancelled
            self.thread_pool.clear()
            # Ensure finished signal is emitted if cancelled mid-way
            self._emit_finished()
