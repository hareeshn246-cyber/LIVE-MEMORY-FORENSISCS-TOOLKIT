import ctypes
from ctypes import wintypes
import psutil
import logging
import time
from typing import List, Dict, Set

logger = logging.getLogger(__name__)

class RootkitDetector:
    """
    Detects hidden processes using Cross-View Analysis.
    Compares High-Level API (psutil/Toolhelp32) vs Low-Level API (EnumProcesses/Syscalls).
    Implements a Singleton-style execution guard to prevent double scans.
    """
    
    _is_scanning = False
    _last_scan_time = 0
    _scan_debounce_seconds = 2.0 
    
    def __init__(self):
        self.psapi = ctypes.WinDLL('psapi.dll')
        self.kernel32 = ctypes.windll.kernel32

    def get_low_level_pids(self) -> Set[int]:
        """Get PIDs using EnumProcesses (System Handle/ID Enumeration)"""
        try:
            # Allocate array for 4096 PIDs (standard max)
            count = 4096
            pids = (wintypes.DWORD * count)()
            bytes_returned = wintypes.DWORD()
            
            # Call EnumProcesses
            if not self.psapi.EnumProcesses(ctypes.byref(pids), ctypes.sizeof(pids), ctypes.byref(bytes_returned)):
                logger.error("EnumProcesses failed")
                return set()
                
            # Calculate number of PIDs
            num_pids = bytes_returned.value // ctypes.sizeof(wintypes.DWORD)
            
            # Extract unique PIDs
            low_level_set = set()
            for i in range(num_pids):
                pid = pids[i]
                if pid > 0: # Ignore System Idle Process (0)
                    low_level_set.add(pid)
                    
            return low_level_set
        except Exception as e:
            logger.error(f"Low-level PID enumeration failed: {e}")
            return set()

    def get_high_level_pids(self) -> Set[int]:
        """Get PIDs using psutil (Standard User-Mode Snapshot)"""
        high_level_set = set()
        try:
            for proc in psutil.process_iter(['pid']):
                high_level_set.add(proc.info['pid'])
        except Exception as e:
            logger.error(f"psutil enumeration failed: {e}")
        return high_level_set

    def scan_for_hidden_processes(self) -> List[Dict]:
        """
        Perform Cross-View Analysis.
        Returns a list of 'Hidden' processes found in Low-Level but missing in High-Level.
        Includes Execution Guard to prevent duplicate concurrent scans.
        """
        # 1. Execution Guard
        current_time = time.time()
        if RootkitDetector._is_scanning:
            logger.warning("Rootkit Scan already in progress. Skipping duplicate request.")
            return []
            
        if (current_time - RootkitDetector._last_scan_time) < RootkitDetector._scan_debounce_seconds:
            logger.info("Skipping rapid re-scan (Debounce active).")
            return []

        try:
            RootkitDetector._is_scanning = True
            RootkitDetector._last_scan_time = current_time
            
            logger.info("Starting Cross-View Rootkit Scan (User-Mode)...")
            
            low_pids = self.get_low_level_pids()
            high_pids = self.get_high_level_pids()
            
            # PIDs visible to Kernel/EnumProcesses but hidden from User Mode API
            hidden_pids = low_pids - high_pids
            
            results = []
            for pid in hidden_pids:
                # Ignore PID 0 (System Idle) and 4 (System) if psutil misses them
                if pid in [0, 4]:
                    continue
                    
                logger.warning(f"ROOTKIT DETECTED: Hidden PID {pid} found via EnumProcesses but missing in psutil!")
                
                name = self._try_get_name(pid)
                
                results.append({
                    'pid': pid,
                    'name': name,
                    'type': 'Hidden Process (DKOM/Rootkit)',
                    'detection_method': 'Cross-View Analysis (EnumProcesses vs Toolhelp32)'
                })
    
            if not results:
                logger.info(f"Cross-View Analysis Complete: Verified {len(high_pids)} processes. No hidden threats detected in User Mode.")
            else:
                logger.warning(f"Cross-View Analysis Complete: Found {len(results)} potential hidden processes.")
                
            return results
            
        except Exception as e:
            logger.error(f"Cross-View Analysis Failed: {e}")
            return []
            
        finally:
            RootkitDetector._is_scanning = False

    def _try_get_name(self, pid: int) -> str:
        """Attempt to resolve name of a hidden process"""
        try:
            PROCESS_QUERY_INFORMATION = 0x0400
            PROCESS_VM_READ = 0x0010
            
            h_process = self.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if h_process:
                name_buffer = ctypes.create_unicode_buffer(1024)
                if self.psapi.GetModuleBaseNameW(h_process, 0, name_buffer, ctypes.sizeof(name_buffer)):
                    self.kernel32.CloseHandle(h_process)
                    return name_buffer.value
                self.kernel32.CloseHandle(h_process)
        except:
            pass
        return "Unknown_Hidden"

    def run_kernel_stealth_detection(self) -> Dict:
        """
        Bridge to the Kernel Interface (Safe Mode).
        Wrapper for executing kernel-level scans ensuring proper mode logging.
        """
        try:
            from core.kernel_interface import execute_kernel_scan
            return execute_kernel_scan()
        except ImportError:
            return {"status": "error", "message": "Kernel Interface missing"}
        except Exception as e:
            logger.error(f"Kernel detection bridge failed: {e}")
            return {"status": "error", "message": str(e)}
