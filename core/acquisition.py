"""
Memory Acquisition Module
Performs surgical memory capture using Windows API (ReadProcessMemory)
Targets specific memory regions of active processes
"""

import os
import ctypes
from ctypes import wintypes
import psutil
from pathlib import Path
from typing import List, Dict, Optional
import logging

# Windows API Constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Windows MEMORY_BASIC_INFORMATION structure"""
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class MemoryAcquisition:
    """
    Handles live process memory acquisition on Windows
    Uses ReadProcessMemory for forensically-sound capture
    """
    
    # Class-level flag to ensure we only try to elevate ONCE per application run
    _privileges_elevated = False

    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        
        # Set up Windows API functions
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        
        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, 
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
        
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        
        # Try to elevate privileges (ONCE)
        if not MemoryAcquisition._privileges_elevated:
            self.set_debug_privilege()

    def set_debug_privilege(self):
        """Enable SeDebugPrivilege for the current process to access system apps"""
        try:
            advapi32 = ctypes.windll.advapi32
            
            # Define Types for 64-bit Safety
            advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
            advapi32.OpenProcessToken.restype = wintypes.BOOL
            
            advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(wintypes.LARGE_INTEGER)]
            advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
            
            class LUID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Luid", wintypes.LARGE_INTEGER), ("Attributes", wintypes.DWORD)]

            class TOKEN_PRIVILEGES(ctypes.Structure):
                _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

            advapi32.AdjustTokenPrivileges.argtypes = [
                wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES), 
                wintypes.DWORD, ctypes.POINTER(TOKEN_PRIVILEGES), ctypes.POINTER(wintypes.DWORD)
            ]
            advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL

            # Constants
            SE_DEBUG_NAME = "SeDebugPrivilege"
            TOKEN_ADJUST_PRIVILEGES = 0x0020
            TOKEN_QUERY = 0x0008
            SE_PRIVILEGE_ENABLED = 0x00000002
            
            # 1. Open current process token
            h_token = wintypes.HANDLE()
            # GetCurrentProcess returns a pseudo-handle (-1). 
            # ctypes treats it as int, but OpenProcessToken expects HANDLE. Explicit cast is safer.
            current_proc = self.kernel32.GetCurrentProcess()
            
            if not advapi32.OpenProcessToken(current_proc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ctypes.byref(h_token)):
                err = self.kernel32.GetLastError()
                logger.warning(f"Failed to open process token (Err: {err})")
                return

            # 2. Lookup LUID
            luid = wintypes.LARGE_INTEGER()
            if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
                self.kernel32.CloseHandle(h_token)
                logger.warning(f"Failed to lookup {SE_DEBUG_NAME}")
                return

            # 3. Adjust Token
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

            if not advapi32.AdjustTokenPrivileges(h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None):
                logger.warning(f"Failed to enable {SE_DEBUG_NAME}")
            else:
                if self.kernel32.GetLastError() == 1300: # ERROR_NOT_ALL_ASSIGNED
                    # This is expected on many modern Windows systems even as Admin.
                    # It means some massive privileges (like TCB) weren't granted, but Debug usually is.
                    # We check if we actually got SeDebug by trying to open a system process later.
                    logger.info(f"Privilege {SE_DEBUG_NAME} requested. System returned partial success (Standard UAC behavior).")
                else:
                    logger.info(f"[{SE_DEBUG_NAME}] Enabled successfully (Full Token).")
            
            # Mark as attempted regardless of outcome to prevent log spam
            MemoryAcquisition._privileges_elevated = True 

            self.kernel32.CloseHandle(h_token)
            
        except Exception as e:
            logger.error(f"Error setting debug privilege: {e}")
        
    def get_process_list(self, exclude_system: bool = True, include_all: bool = False) -> List[Dict]:
        """
        Enumerate all running processes efficiently
        """
        processes = []
        from config import EXCLUDE_SYSTEM_PROCESSES, MIN_PROCESS_MEMORY_MB
        
        # [OPTIMIZATION] Fetch all attributes at once to minimize syscall overhead
        attrs = ['pid', 'name', 'ppid', 'username', 'cmdline', 'exe', 'memory_info']
        
        for proc in psutil.process_iter(attrs):
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or "Unknown"
                
                # SAFETY: Always Skip Self
                if pid == os.getpid():
                    continue

                # Fetch memory info safely
                mem_info = info.get('memory_info')
                mem_mb = (mem_info.rss / (1024 * 1024)) if mem_info else 0
                
                # Apply filters unless include_all is requested
                if not include_all:
                    if exclude_system and name in EXCLUDE_SYSTEM_PROCESSES:
                        continue
                    if mem_mb < MIN_PROCESS_MEMORY_MB:
                        continue
                
                # Fetch Extended Attributes from pre-fetched info
                ppid = info.get('ppid', 0)
                username = info.get('username', 'N/A')
                cmdline_list = info.get('cmdline')
                cmdline = " ".join(cmdline_list) if cmdline_list else ""
                exe_path = info.get('exe', "")
                
                # CLEANUP: Remove kernel path prefix \??\
                if cmdline.startswith("\\??\\"):
                    cmdline = cmdline.replace("\\??\\", "")
                
                # Fallback for protected processes where attributes might be None despite iter
                if username is None:
                    # Identify known system processes
                    SYSTEM_PROCS = ["System", "Registry", "MemCompression", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe"]
                    if name in SYSTEM_PROCS or "system" in name.lower():
                        username = "SYSTEM"
                        cmdline = "[System Process]"
                        exe_path = "System"
                    else:
                        username = "Access Denied"

                processes.append({
                    'pid': pid,
                    'name': name,
                    'exe_path': exe_path or "",
                    'memory_mb': round(mem_mb, 2),
                    'ppid': ppid or 0,
                    'username': username or "N/A",
                    'cmdline': cmdline or ""
                })
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.debug(f"Error processing PID: {e}")
                continue
        
        return sorted(processes, key=lambda x: x['memory_mb'], reverse=True)
    
    def acquire_process_memory(self, pid: int, output_path: Path) -> Dict:
        """
        Capture memory regions of a target process
        
        Args:
            pid: Process ID to capture
            output_path: Path to save raw memory dump
            
        Returns:
            Dictionary containing capture metadata
        """
        logger.info(f"Starting memory acquisition for PID {pid}")
        
        # Open process handle
        h_process = self.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid
        )
        
        if not h_process:
            error_code = ctypes.get_last_error()
            return {
                'pid': pid,
                'status': 'access_denied',
                'error': f'Access Denied (WinError {error_code})',
                'total_bytes': 0
            }
        
        try:
            regions_captured = 0
            total_bytes = 0
            
            import time
            from config import CAPTURE_MEM_TYPES

            # Per-process timeout (30 seconds max to prevent hanging)
            PROCESS_TIMEOUT = 30
            acq_start = time.time()

            # Map config string types to integer values
            ALLOWED_TYPES = []
            if "MEM_IMAGE" in CAPTURE_MEM_TYPES: ALLOWED_TYPES.append(MEM_IMAGE)
            if "MEM_MAPPED" in CAPTURE_MEM_TYPES: ALLOWED_TYPES.append(MEM_MAPPED)
            if "MEM_PRIVATE" in CAPTURE_MEM_TYPES: ALLOWED_TYPES.append(MEM_PRIVATE)
            
            with open(output_path, 'wb') as dump_file:
                address = 0
                max_address = 0x7FFFFFFF0000  # Max user-mode address on x64
                
                
                while address < max_address:
                    # Timeout guard: skip process if taking too long
                    if time.time() - acq_start > PROCESS_TIMEOUT:
                        logger.warning(f"PID {pid}: acquisition timed out after {PROCESS_TIMEOUT}s, captured {regions_captured} regions so far")
                        break

                    mbi = MEMORY_BASIC_INFORMATION()
                    result = self.kernel32.VirtualQueryEx(
                        h_process,
                        ctypes.c_void_p(address),
                        ctypes.byref(mbi),
                        ctypes.sizeof(mbi)
                    )
                    
                    if result == 0:
                        break
                    
                    if (mbi.State == MEM_COMMIT and 
                        mbi.Protect not in [PAGE_NOACCESS, PAGE_GUARD] and
                        mbi.Type in ALLOWED_TYPES and  # CRITICAL FIX: Only capture safe types
                        mbi.RegionSize > 0):
                        
                        # Chunked reading for large regions to prevent OOM
                        # Increased chunk size to 4MB for better throughput
                        CHUNK_SIZE = 4 * 1024 * 1024 
                        bytes_left = mbi.RegionSize
                        current_offset = 0
                        
                        # [OPTIMIZATION] Reuse buffer if region is larger than CHUNK_SIZE
                        # Pre-allocating the maximum possible buffer to avoid churn
                        shared_buffer = ctypes.create_string_buffer(CHUNK_SIZE)
                        
                        while bytes_left > 0:
                            read_size = min(bytes_left, CHUNK_SIZE)
                            # Only create new buffer if current one is too small (shouldn't happen with min logic but safe)
                            # Actually, we can just use the shared_buffer and slice it
                            
                            bytes_read = ctypes.c_size_t()
                            
                            read_success = self.kernel32.ReadProcessMemory(
                                h_process,
                                ctypes.c_void_p(mbi.BaseAddress + current_offset),
                                shared_buffer,
                                read_size,
                                ctypes.byref(bytes_read)
                            )
                            
                            if read_success and bytes_read.value > 0:
                                dump_file.write(shared_buffer.raw[:bytes_read.value])
                                total_bytes += bytes_read.value
                            
                            # Move to next chunk
                            bytes_left -= read_size
                            current_offset += read_size
                            
                            # [PERFORMANCE] Yield to OS to allow other processes to breathe
                            # Prevents full system freeze during massive I/O
                            time.sleep(0.001)
                                
                        regions_captured += 1
                    
                    if mbi.RegionSize == 0:
                        address += 4096 # Safety jump
                    else:
                        address += mbi.RegionSize
            
            metadata = {
                'pid': pid,
                'regions_captured': regions_captured,
                'total_bytes': total_bytes,
                'total_mb': round(total_bytes / (1024 * 1024), 2),
                'output_path': str(output_path),
                'status': 'success'
            }
            
            logger.info(f"Captured {regions_captured} regions ({metadata['total_mb']} MB) from PID {pid}")
            return metadata
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            logger.error(f"Error during memory acquisition for PID {pid}: {str(e)}\n{error_details}")
            return {
                'pid': pid,
                'status': 'error',
                'error': f"{type(e).__name__}: {str(e)}"
            }
        finally:
            self.kernel32.CloseHandle(h_process)
    
    def acquire_memory_region(self, pid: int, base_address: int, size: int) -> Optional[bytes]:
        """
        Acquire a specific memory region (used for targeted analysis)
        
        Args:
            pid: Process ID
            base_address: Starting address of region
            size: Number of bytes to read
            
        Returns:
            Raw bytes from memory region, or None if failed
        """
        h_process = self.kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            False,
            pid
        )
        
        if not h_process:
            return None
        
        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            if self.kernel32.ReadProcessMemory(
                h_process,
                ctypes.c_void_p(base_address),
                buffer,
                size,
                ctypes.byref(bytes_read)
            ):
                return buffer.raw[:bytes_read.value]
            
            return None
            
        finally:
            self.kernel32.CloseHandle(h_process)
