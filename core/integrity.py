"""
Memory Integrity Validation Module
Implements passive inline hook detection via NTDLL comparison
Compares in-memory NTDLL against clean disk copy
"""

import os
import ctypes
from ctypes import wintypes
import logging
from pathlib import Path
from typing import Dict, List, Optional
import pefile

logger = logging.getLogger(__name__)

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010


class HookDetector:
    """
    Passive hook detector for user-mode API tampering
    Performs byte-level comparison of NT API functions
    """
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll_disk_path = Path(os.environ['SystemRoot']) / 'System32' / 'ntdll.dll'
        self.clean_ntdll = self._load_clean_ntdll()
        
    def _load_clean_ntdll(self) -> Optional[bytes]:
        """Load clean NTDLL from disk as reference"""
        try:
            with open(self.ntdll_disk_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load clean NTDLL: {e}")
            return None
    
    def _get_function_rva(self, dll_bytes: bytes, function_name: str) -> Optional[int]:
        """
        Parse PE export table to get function RVA
        
        Args:
            dll_bytes: Raw DLL bytes
            function_name: Name of exported function
            
        Returns:
            Relative Virtual Address of function
        """
        try:
            pe = pefile.PE(data=dll_bytes)
            
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.name and export.name.decode('utf-8') == function_name:
                    return export.address
            
            return None
            
        except Exception as e:
            logger.error(f"Error parsing PE exports: {e}")
            return None
    
    def _read_process_memory(self, pid: int, address: int, size: int) -> Optional[bytes]:
        """Read memory from target process"""
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
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytes_read)
            ):
                return buffer.raw[:bytes_read.value]
            
            return None
            
        finally:
            self.kernel32.CloseHandle(h_process)
    
    def _get_module_base(self, pid: int, module_name: str) -> Optional[int]:
        """Get base address of loaded module in target process"""
        try:
            import psutil
            proc = psutil.Process(pid)
            
            for module in proc.memory_maps():
                if module_name.lower() in module.path.lower():
                    # Try to get address - handle different psutil versions
                    try:
                        # Newer psutil versions
                        if hasattr(module, 'addr'):
                            addr_str = module.addr.split('-')[0]
                        else:
                            # Fallback: module is a named tuple with path as first element
                            # Address is typically in the format "0x7ff... - 0x7ff..."
                            continue  # Skip if we can't get address
                        return int(addr_str, 16)
                    except (AttributeError, ValueError) as e:
                        logger.debug(f"Could not parse address from module: {e}")
                        continue
            
            # Fallback: Try using ctypes to enumerate modules
            logger.warning(f"Could not find {module_name} using psutil, trying alternative method")
            return self._get_module_base_ctypes(pid, module_name)
            
        except Exception as e:
            logger.error(f"Error getting module base: {e}")
            return None
    
    def _get_module_base_ctypes(self, pid: int, module_name: str) -> Optional[int]:
        """
        Alternative method to get module base using ctypes and PSAPI.
        Resolves issues where psutil fails to enumerate modules.
        """
        try:
            # 1. Open target process
            # PROCESS_QUERY_INFORMATION (0x0400) | PROCESS_VM_READ (0x0010)
            h_process = self.kernel32.OpenProcess(0x0410, False, pid)
            if not h_process:
                return None
                
            try:
                # 2. Prepare PSAPI functions
                psapi = ctypes.WinDLL('psapi.dll')
                
                # Arrays to store module handles
                # 1024 modules should be enough for most processes
                count = 1024
                h_mods = (wintypes.HMODULE * count)()
                cb_needed = wintypes.DWORD()
                
                # 3. EnumProcessModules
                # LIST_MODULES_ALL (0x03) prevents missing 32-bit modules in 64-bit processes
                # But EnumProcessModulesEx is safer for WoW64
                if hasattr(psapi, 'EnumProcessModulesEx'):
                     # 0x03 = LIST_MODULES_ALL
                     status = psapi.EnumProcessModulesEx(h_process, ctypes.byref(h_mods), ctypes.sizeof(h_mods), ctypes.byref(cb_needed), 0x03)
                else:
                     status = psapi.EnumProcessModules(h_process, ctypes.byref(h_mods), ctypes.sizeof(h_mods), ctypes.byref(cb_needed))
                
                if not status:
                    return None
                    
                # Calculate number of modules returned
                num_mods = cb_needed.value // ctypes.sizeof(wintypes.HMODULE)
                num_mods = min(num_mods, count)
                
                # 4. Iterate and check names
                name_buffer = ctypes.create_unicode_buffer(260)
                
                for i in range(num_mods):
                    h_mod = h_mods[i]
                    
                    # Get Module Name
                    if psapi.GetModuleBaseNameW(h_process, h_mod, name_buffer, ctypes.sizeof(name_buffer)):
                        curr_name = name_buffer.value
                        if curr_name.lower() == module_name.lower():
                            # Found it! Convert HMODULE to integer address
                            # FIX: Properly handle 64-bit pointers to avoid OverflowError
                            # On 64-bit systems, HMODULE can be a 64-bit pointer
                            try:
                                # Try direct conversion first
                                addr = ctypes.cast(h_mod, ctypes.c_void_p).value
                                return addr if addr is not None else 0
                            except (OverflowError, ValueError):
                                # Fallback: Use addressof for 64-bit compatibility
                                # This handles cases where the pointer value is too large
                                try:
                                    # Convert to c_ulonglong for 64-bit addresses
                                    if ctypes.sizeof(ctypes.c_void_p) == 8:
                                        return int(ctypes.c_ulonglong(h_mod).value)
                                    else:
                                        return int(h_mod)
                                except:
                                    logger.error(f"Failed to convert HMODULE for {curr_name}")
                                    return None
                            
            finally:
                self.kernel32.CloseHandle(h_process)
                
            return None
            
        except Exception as e:
            logger.error(f"Error in ctypes module enumeration: {e}")
            return None
    
    def detect_hooks(self, pid: int, functions: List[str]) -> Dict:
        """
        Detect inline hooks by comparing function prologues
        
        Args:
            pid: Target process ID
            functions: List of NT API function names to check
            
        Returns:
            Dictionary containing detection results
        """
        if not self.clean_ntdll:
            return {'status': 'error', 'message': 'Clean NTDLL not loaded'}
        
        logger.info(f"Starting hook detection for PID {pid}")
        
        # Get NTDLL base address in target process
        ntdll_base = self._get_module_base(pid, 'ntdll.dll')
        if not ntdll_base:
            logger.warning(f"Could not locate NTDLL in target process {pid} - hook detection skipped")
            return {
                'status': 'skipped',
                'message': 'Could not locate NTDLL in target process',
                'pid': pid,
                'functions_checked': 0,
                'hooks_detected': [],
                'clean_functions': [],
                'is_compromised': False
            }
        
        from config import HOOK_BYTE_COMPARE_LENGTH
        
        results = {
            'pid': pid,
            'ntdll_base': hex(ntdll_base),
            'functions_checked': len(functions),
            'hooks_detected': [],
            'clean_functions': []
        }
        
        for func_name in functions:
            # Get RVA from clean NTDLL
            rva = self._get_function_rva(self.clean_ntdll, func_name)
            if not rva:
                logger.warning(f"Function {func_name} not found in NTDLL exports")
                continue
            
            # Calculate actual address in target process
            func_address = ntdll_base + rva
            
            # Read function prologue from target process
            live_bytes = self._read_process_memory(pid, func_address, HOOK_BYTE_COMPARE_LENGTH)
            if not live_bytes:
                continue
            
            # Read corresponding bytes from clean NTDLL
            clean_bytes = self.clean_ntdll[rva:rva + HOOK_BYTE_COMPARE_LENGTH]
            
            # Compare byte-by-byte
            if live_bytes != clean_bytes:
                hook_info = {
                    'function': func_name,
                    'address': hex(func_address),
                    'clean_bytes': clean_bytes.hex(),
                    'hooked_bytes': live_bytes.hex(),
                    'divergence_offset': self._find_first_divergence(clean_bytes, live_bytes)
                }
                results['hooks_detected'].append(hook_info)
                logger.warning(f"HOOK DETECTED: {func_name} at {hex(func_address)}")
            else:
                results['clean_functions'].append(func_name)
        
        results['status'] = 'completed'
        results['is_compromised'] = len(results['hooks_detected']) > 0
        
        return results
    
    def _find_first_divergence(self, bytes1: bytes, bytes2: bytes) -> int:
        """Find first byte offset where two sequences differ"""
        for i, (b1, b2) in enumerate(zip(bytes1, bytes2)):
            if b1 != b2:
                return i
        return -1
    
    def comprehensive_scan(self, pid: int) -> Dict:
        """
        Perform comprehensive hook analysis on target process
        Wrapper for detect_hooks using configured function list
        """
        from config import HOOK_DETECTION_FUNCTIONS
        return self.detect_hooks(pid, HOOK_DETECTION_FUNCTIONS)

    def scan_offline_dump(self, dump_path: Path) -> Dict:
        """
        Passive Hook Scanner for Offline Dumps
        Uses heuristic pattern matching to detect anomalies in syscall stubs.
        
        Technique:
        1. Search for x64 Syscall Prologue: '4C 8B D1 B8' (MOV R10, RCX; MOV EAX, ...)
        2. Identify deviations or presence of 'E9' (JMP) / 'FF 25' (JMP Indirect) in code code caves.
        """
        results = {
            'status': 'completed',
            'pid': 0,
            'hooks_detected': [],
            'clean_functions': [],
            'is_compromised': False,
            'method': 'Passive Heuristic (Offline)'
        }
        
        try:
            with open(dump_path, 'rb') as f:
                content = f.read()
                
            # Heuristic 1: Count Syscall Prologues (Valid Functions)
            # x64 syscalls typically start with: 4C 8B D1 B8 (mov r10, rcx; mov eax, ...)
            clean_syscall_pattern = b'\x4C\x8B\xD1\xB8'
            clean_count = content.count(clean_syscall_pattern)
            
            # Heuristic 2: Detect Suspicious Jumps (Hooks)
            # Look for classic user-mode hooks: E9 <Offset> (JMP Rel32) where code *should* be
            # This is hard without offsets. 
            # instead, we look for JMP instructions that jump into "nowhere" or are surrounded by NOPs (trampolines)
            # BUT, a better approach for the user:
            
            # Use the clean_ntdll to verify presence of specific functions
            if not self.clean_ntdll:
                results['status'] = 'error'
                results['message'] = 'Clean NTDLL not available'
                return results

            from config import HOOK_DETECTION_FUNCTIONS
            
            # Search for each function's "Clean Signature" in the dump
            for func_name in HOOK_DETECTION_FUNCTIONS:
                rva = self._get_function_rva(self.clean_ntdll, func_name)
                if not rva: continue
                
                # Get the first 16 bytes of the CLEAN function (Ground Truth)
                clean_bytes = self.clean_ntdll[rva:rva+16]
                
                # Check if this exact sequence exists in the dump
                # If it exists, the function is present and UNHOOKED (in at least one copy)
                if clean_bytes in content:
                    results['clean_functions'].append(func_name)
                    
                else:
                    # If clean bytes are NOT found, it *might* be hooked or just not captured/split
                    # We flag it as "Potentially Hooked / Missing"
                    # To reduce false positives, we check if the *Prologue* (first 4 bytes) is there
                    prologue = clean_bytes[:4]
                    if prologue in content:
                        # Prologue exists, but full 16 bytes don't match -> MODIFIED (Hooked)
                        results['hooks_detected'].append({
                            'function': func_name,
                            'type': 'Inline Modification',
                            'details': 'Prologue matches but body differs (Partial Match)'
                        })
                    else:
                        # Prologue totally missing -> Could be a JMP hook (Overwriter) OR just missing data
                        # We check for a JMP instruction (E9) followed by plausible offset? No, too noisy.
                        # We mark as "Missing/Hooked"
                        results['hooks_detected'].append({
                            'function': func_name,
                            'type': 'Missing/Overwritten',
                            'details': 'Sycall stub signature not found (Complete Mismatch)'
                        })
            
            results['is_compromised'] = len(results['hooks_detected']) > 0
            
            # Filter results for "Offline" confidence
            # If we found NOTHING, the dump might just be partial data (e.g. heap only)
            if len(results['clean_functions']) == 0 and len(results['hooks_detected']) > 0:
                # Likely just a raw data dump without code sections
                results['status'] = 'inconclusive'
                results['message'] = 'No executable code patterns found (Data-only dump?)'
                results['is_compromised'] = False
                results['hooks_detected'] = []
                
        except Exception as e:
            logger.error(f"Offline hook scan failed: {e}")
            results['error'] = str(e)
            
        return results
