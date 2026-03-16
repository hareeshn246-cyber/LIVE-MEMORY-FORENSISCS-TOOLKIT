import time
import os
import sys
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).resolve().parent))

from core.acquisition import MemoryAcquisition

def benchmark_acquisition():
    print("[*] Starting Performance Benchmark for MemoryAcquisition.get_process_list()")
    acq = MemoryAcquisition()
    
    # Warm up
    acq.get_process_list(include_all=True)
    
    iterations = 5
    total_time = 0
    
    for i in range(iterations):
        start = time.time()
        processes = acq.get_process_list(include_all=True)
        end = time.time()
        elapsed = end - start
        total_time += elapsed
        print(f"  Iteration {i+1}: {elapsed:.4f}s ({len(processes)} processes)")
        
    avg_time = total_time / iterations
    print(f"\n[+] Average Acquisition Time: {avg_time:.4f}s")
    
    if avg_time > 0.5:
        print("[!] WARNING: Acquisition is slow (> 0.5s). Optimization recommended.")
    else:
        print("[+] SUCCESS: Acquisition is fast (< 0.5s).")

if __name__ == "__main__":
    benchmark_acquisition()
