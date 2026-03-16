import sys
import os
import time
import logging
from PyQt5.QtWidgets import QApplication
from ui.batch_worker import BatchAnalysisWorker

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TestParallel")

def test_parallel_batch():
    app = QApplication(sys.argv)
    
    # Use real processes but limit to 3 for fast verification
    import psutil
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            mem_mb = p.info['memory_info'].rss / (1024 * 1024)
            if mem_mb > 1 and mem_mb < 50: # Smaller processes for test
                procs.append({'pid': p.info['pid'], 'name': p.info['name'], 'memory_mb': mem_mb})
            if len(procs) >= 3:
                break
        except: continue

    print(f"[*] Testing BatchAnalysisWorker with {len(procs)} processes")
    worker = BatchAnalysisWorker(procs)
    
    results_received = []
    
    def on_complete(res):
        print(f"[+] Result received for {res['process_name']} (PID: {res['pid']}) - Status: {res['status']}")
        results_received.append(res)
        
    def on_finished(summary):
        print(f"\n[*] Batch Finished!")
        print(f"    Total: {summary['total_processes']}")
        print(f"    Completed: {summary['completed']}")
        print(f"    Failed: {summary['failed']}")
        app.quit()

    worker.process_complete.connect(on_complete)
    worker.finished.connect(on_finished)
    worker.error.connect(lambda e: print(f"[!] Worker Error: {e}"))
    
    start_time = time.time()
    worker.start()
    
    app.exec_()
    
    end_time = time.time()
    print(f"\n[*] Total Time: {end_time - start_time:.2f}s")
    
    return len(results_received) == len(procs)

if __name__ == "__main__":
    if test_parallel_batch():
        print("\n[SUCCESS] Parallel Batch Analysis verified.")
        sys.exit(0)
    else:
        print("\n[FAILURE] Verification failed.")
        sys.exit(1)
