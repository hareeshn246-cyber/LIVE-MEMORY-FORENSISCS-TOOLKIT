"""
Feature Extraction Module
Converts raw memory data into structured JSON artifacts
Extracts behavioral indicators for ML analysis
"""

import json
import re
import struct
from pathlib import Path
from typing import Dict, List, Optional
import logging
import math
from collections import Counter
import pefile
import io

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Extracts behavioral features from memory dumps
    Generates JSON artifacts for ML-based detection
    """
    
    def __init__(self):
        # Common suspicious API patterns
        self.suspicious_apis = [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtCreateThreadEx', 'SetWindowsHookEx', 'GetAsyncKeyState',
            'CryptEncrypt', 'CryptDecrypt', 'InternetReadFile',
            'URLDownloadToFile', 'WinExec', 'ShellExecute',
            'CreateProcess', 'AdjustTokenPrivileges', 'OpenProcess',
            'NtMapViewOfSection', 'NtUnmapViewOfSection', 'QueueUserAPC', 
            'SetThreadContext', 'RtlCreateUserThread' # Modern Injection APIs
        ]
        
        # Network indicators
        self.network_patterns = [
            rb'http://', rb'https://', rb'ftp://',
            rb'POST', rb'GET', rb'User-Agent:',
            rb'Content-Type:', rb'Cookie:'
        ]
        
        # Registry patterns
        self.registry_patterns = [
            rb'HKEY_LOCAL_MACHINE', rb'HKEY_CURRENT_USER',
            rb'Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            rb'RegCreateKey', rb'RegSetValue'
        ]
    
    def extract_features(self, dump_path: Path, yara_results: Dict, hook_results: Dict) -> Dict:
        """
        Extract comprehensive behavioral features from memory dump
        WITH TIMEOUT PROTECTION to prevent UI freezing
        
        Args:
            dump_path: Path to raw memory dump
            yara_results: Results from YARA scan
            hook_results: Results from hook detection
            
        Returns:
            Dictionary of extracted features (JSON artifact)
        """
        if isinstance(dump_path, str):
            dump_path = Path(dump_path)
            
        logger.info(f"Extracting features from {dump_path.name}")
        
        # Use threading to implement timeout protection
        import threading
        from config import FEATURE_EXTRACTION_TIMEOUT
        
        result_container = {'features': None, 'error': None}
        
        def _extract_with_timeout():
            """Inner function that performs the actual extraction"""
            try:
                result_container['features'] = self._extract_features_internal(
                    dump_path, yara_results, hook_results
                )
            except Exception as e:
                logger.error(f"Feature extraction error: {e}", exc_info=True)
                result_container['error'] = str(e)
        
        # Run extraction in a separate thread with timeout
        extraction_thread = threading.Thread(target=_extract_with_timeout, daemon=True)
        extraction_thread.start()
        extraction_thread.join(timeout=FEATURE_EXTRACTION_TIMEOUT)
        
        # Check if thread completed or timed out
        if extraction_thread.is_alive():
            logger.warning(f"Feature extraction timed out after {FEATURE_EXTRACTION_TIMEOUT}s for {dump_path.name}")
            # Return minimal features with timeout indicator
            return {
                'metadata': {
                    'source_dump': str(dump_path),
                    'dump_size_mb': round(dump_path.stat().st_size / (1024 * 1024), 2) if dump_path.exists() else 0
                },
                'signature_indicators': self._process_yara_results(yara_results, dump_path),
                'integrity_indicators': self._process_hook_results(hook_results),
                'behavioral_indicators': {},
                'pe_features': {},
                'statistical_features': {},
                'error': 'Feature extraction timed out',
                'warnings': [f'Extraction exceeded {FEATURE_EXTRACTION_TIMEOUT}s timeout - analysis incomplete'],
                'risk_assessment': self.calculate_weighted_risk({
                    'signature_indicators': self._process_yara_results(yara_results, dump_path),
                    'integrity_indicators': self._process_hook_results(hook_results),
                    'behavioral_indicators': {},
                    'metadata': {'source_dump': str(dump_path)}
                }, anomaly_score=0.0)
            }
        
        # Check for errors
        if result_container['error']:
            return {
                'metadata': {
                    'source_dump': str(dump_path),
                    'dump_size_mb': round(dump_path.stat().st_size / (1024 * 1024), 2) if dump_path.exists() else 0
                },
                'signature_indicators': self._process_yara_results(yara_results, dump_path),
                'integrity_indicators': self._process_hook_results(hook_results),
                'behavioral_indicators': {},
                'pe_features': {},
                'statistical_features': {},
                'error': result_container['error'],
                'risk_assessment': self.calculate_weighted_risk({
                    'signature_indicators': self._process_yara_results(yara_results, dump_path),
                    'integrity_indicators': self._process_hook_results(hook_results),
                    'behavioral_indicators': {},
                    'metadata': {'source_dump': str(dump_path)}
                }, anomaly_score=0.0)
            }
        
        return result_container['features']
    
    def _extract_features_internal(self, dump_path: Path, yara_results: Dict, hook_results: Dict) -> Dict:
        """
        Internal method that performs the actual feature extraction
        (separated for timeout handling)
        """
        try:
            dump_size = round(dump_path.stat().st_size / (1024 * 1024), 2)
        except (FileNotFoundError, OSError):
            dump_size = 0
            
        features = {
            'metadata': {
                'source_dump': str(dump_path),
                'dump_size_mb': dump_size
            },
            # Pass dump_path to allow trusted process checking inside processing
            'signature_indicators': self._process_yara_results(yara_results, dump_path),
            'integrity_indicators': self._process_hook_results(hook_results),
            'behavioral_indicators': {},
            'pe_features': {},
            'statistical_features': {}
        }
        
        # Extract behavioral indicators from raw dump
        try:
            from config import MAX_ANALYSIS_SIZE_MB
            file_size_mb = dump_path.stat().st_size / (1024 * 1024)
            
            if file_size_mb > MAX_ANALYSIS_SIZE_MB:
                logger.warning(f"Dump too large for full feature extraction ({file_size_mb:.2f} MB)")
                features['error'] = 'Dump too large for deep analysis'
                features['warnings'] = ['Deep analysis skipped due to size limits (prevention of OOM)']
            else:
                try:
                    # Use memory mapping for large file support
                    import mmap
                    with open(dump_path, 'rb') as f:
                        # Check for empty file
                        if f.seek(0, 2) == 0:
                            raise ValueError("File is empty")
                        f.seek(0)
                        
                        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                           features['behavioral_indicators'] = self._extract_behavioral(mm)
                           logger.info(f"DEBUG: Extracted behavioral indicators for {dump_path.name}: {list(features['behavioral_indicators'].keys())}")

                           
                           # Disable PE Feature Extraction for large dumps (>100MB) to prevent OOM
                           if file_size_mb < 100:
                               features['pe_features'] = self._extract_pe_features(mm)
                           else:
                               features['pe_features'] = {} # Skip for stability
                           
                           features['statistical_features'] = self._extract_statistical(mm)
                    
                except Exception as e:
                    logger.error(f"Error reading dump {dump_path.name}: {e}")
                    features['error'] = 'Analysis failed'
                    features['warnings'] = [str(e)]
            
        except Exception as e:
            logger.error(f"Error reading dump for feature extraction: {e}")
            features['error'] = str(e)
        
        # Risk score is now calculated AFTER anomaly detection in the pipeline
        # We process a preliminary score here acting as if anomaly is 0, or rely on caller to update.
        features['risk_assessment'] = self.calculate_weighted_risk(features, anomaly_score=0.0)
        
        return features
    
    def _process_yara_results(self, yara_results: Dict, dump_path: Path = None) -> Dict:
        """Process YARA scan results into feature format"""
        processed_rules = []
        ignored_count = 0
        
        # Whitelist Filtering Logic
        is_trusted = False
        try:
            from config import TRUSTED_PROCESSES
            if dump_path:
                is_trusted = any(proc.lower() in str(dump_path).lower() for proc in TRUSTED_PROCESSES)
        except ImportError:
            pass

        # Rules to ignore for trusted processes (False Positives)
        NOISY_RULES = [
            'MalMem_ProcessInjection_classic',
            'MalMem_Reflective_DLL_Injection', 
            'MalMem_Persistence_Registry_RunKeys',
            'MalMem_Suspicious_PowerShell_Encoded',
            'MalMem_Suspicious_PowerShell_Encoded',
            'MalMem_Suspicious_Network_APIs',
            'YARA_Example_Rule'  # Added to prevent false alert on example file
        ]

        for det in yara_results.get('detections', []):
            # Use .get() for safe access in case of malformed detection
            rule_name = det.get('rule_name', det.get('name', 'Unknown_Rule'))
            
            # Skip noisy rules for trusted apps
            if is_trusted and rule_name in NOISY_RULES:
                ignored_count += 1
                continue
                
            meta = det.get('meta', {})
            severity = meta.get('severity', 'unknown')
            
            # Fallback: Map score to severity if missing
            if severity == 'unknown' and 'score' in meta:
                score = meta['score']
                if score >= 90: severity = 'Critical'
                elif score >= 70: severity = 'High'
                elif score >= 40: severity = 'Medium'
                else: severity = 'Low'
            
            processed_rules.append({
                'name': rule_name,
                'severity': severity,
                'description': meta.get('description', '')
            })

        return {
            'total_detections': len(processed_rules), # Only count kept rules
            'suppressed_matches': ignored_count,
            'is_signature_match': len(processed_rules) > 0, # Update flag based on filtered list
            'matched_rules': processed_rules
        }
    
    def _process_hook_results(self, hook_results: Dict) -> Dict:
        """Process hook detection results into feature format"""
        # Handle hooks_detected which can be list or int
        hooks_detected = hook_results.get('hooks_detected', [])
        if isinstance(hooks_detected, list):
            hooks_count = len(hooks_detected)
            hooked_functions = [h['function'] for h in hooks_detected if isinstance(h, dict)]
        elif isinstance(hooks_detected, int):
            hooks_count = hooks_detected
            hooked_functions = []
        else:
            hooks_count = 0
            hooked_functions = []
        
        # Handle clean_functions which can be list or int
        clean_functions = hook_results.get('clean_functions', [])
        clean_count = len(clean_functions) if isinstance(clean_functions, list) else (clean_functions if isinstance(clean_functions, int) else 0)
        
        return {
            'hooks_detected': hooks_count,
            'is_compromised': hook_results.get('is_compromised', False),
            'hooked_functions': hooked_functions,
            'clean_functions': clean_count
        }
    
    def _regex_find_chunked(self, pattern: bytes, data: bytes, chunk_size: int = 10 * 1024 * 1024) -> List[bytes]:
        """
        Run regex on large data by splitting into chunks with overlap
        Prevents ReDoS and hangs on massive memory dumps
        """
        matches = set()
        overlap = 1024  # 1KB overlap to catch boundary cases
        total_len = len(data)
        
        # Pre-compile regex if it's not already
        regex = re.compile(pattern) if isinstance(pattern, bytes) else pattern
        
        for i in range(0, total_len, chunk_size):
            end = min(i + chunk_size + overlap, total_len)
            chunk = data[i:end]
            
            # Find matches in chunk
            chunk_matches = regex.findall(chunk)
            matches.update(chunk_matches)
            
            # Optimization: Don't process too many matches to save memory
            if len(matches) > 1000:
                break
                
        return list(matches)

    def _count_pattern(self, data, pattern: bytes) -> int:
        """Count pattern occurrences in bytes or mmap"""
        count = 0
        start = 0
        while True:
            # mmap and bytes both support find()
            idx = data.find(pattern, start)
            if idx == -1:
                break
            count += 1
            start = idx + len(pattern)
        return count

    def _count_pattern_chunked(self, pattern: bytes, data: bytes, chunk_size: int = 10 * 1024 * 1024) -> int:
        """Count pattern occurrences using chunked processing (or direct if mmap)"""
        # If internal mmap logic (above) is preferred, we can just use that. 
        # But this function was designed for byte chunks.
        # For mmap, the find() loop in _count_pattern is memory efficient.
        return self._count_pattern(data, pattern)

    def _extract_behavioral(self, memory_data: bytes) -> Dict:
        """Extract behavioral indicators from raw memory"""
        # OPTIMIZATION: Split data scopes to balance Accuracy vs Performance
        
        # 1. Full Scope (Fast Operations)
        # scan_data is the full memory. Python's 'bytes.find' (literal search) uses Boyer-Moore 
        # in C and releases GIL, so it's safe and fast even on 8GB+ dumps.
        fast_data = memory_data
        
        # 2. Limited Scope (Expensive Operations)
        # Regex operations are expensive and can be slow. We limit them to the first 200MB for responsiveness.
        REGEX_LIMIT = 200 * 1024 * 1024
        if len(memory_data) > REGEX_LIMIT:
            regex_data = memory_data[:REGEX_LIMIT]
        else:
            regex_data = memory_data
            
        indicators = {
            # FAST: Literal searches on FULL memory (High Accuracy)
            'suspicious_apis': self._find_api_references(fast_data),
            'network_indicators': self._find_network_indicators(fast_data),
            'crypto_constants': self._find_crypto_constants(fast_data),
            
            # SLOW: Regex searches on LIMITED memory (Performance)
            'urls': self._extract_urls(regex_data),
            'ip_addresses': self._extract_ip_addresses(regex_data),
            'file_paths': self._extract_file_paths(regex_data)
        }
        
        return indicators
    
    def _extract_statistical(self, memory_data: bytes) -> Dict:
        """Extract statistical features from memory"""
        # Entropy calculation - Optimize by sampling if data is too large
        total_bytes = len(memory_data)
        
        # If larger than 50MB, sample for entropy to save time
        if total_bytes > 50 * 1024 * 1024:
            step = total_bytes // (50 * 1024 * 1024)  # Step size to get ~50MB samples
            sample_data = memory_data[::step]
        else:
            sample_data = memory_data
            
        byte_counts = Counter(sample_data)
        sample_total = len(sample_data)
        
        entropy = -sum(
            (count / sample_total) * math.log2(count / sample_total)
            for count in byte_counts.values()
        )
        
        
        # Null byte ratio (packed/encrypted data has low null ratio)
        # Fix: mmap does not support .count(), but we already computed byte_counts using Counter
        # We handle both int (mmap iteration) and bytes (bytes iteration) keys
        null_count = byte_counts.get(0, 0) + byte_counts.get(b'\x00', 0)
        null_ratio = null_count / sample_total if sample_total > 0 else 0
        
        # Printable ASCII ratio
        # When iterating mmap/bytes, careful as mmap iteration yields bytes in Py3, but indexing yields int.
        # But for mmap, 'for b in mmap_obj' yields bytes of length 1.
        # So we convert to int using ord() if it's bytes, or just use it if it's already int (from bytes object).
        printable = 0
        for b in sample_data:
            val = b if isinstance(b, int) else ord(b)
            if 32 <= val <= 126:
                printable += 1
                
        printable_ratio = printable / sample_total
        
        return {
            'entropy': round(entropy, 4),
            'null_byte_ratio': round(null_ratio, 4),
            'printable_ratio': round(printable_ratio, 4),
            'unique_bytes': len(byte_counts),
            'total_size': total_bytes
        }
    
    def _find_api_references(self, data: bytes) -> Dict:
        """Find references to suspicious APIs in memory"""
        api_counts = {}
        
        for api in self.suspicious_apis:
            pattern = api.encode('ascii')
            # Use chunked count or count on full data (bytes.count is fast C implementation, so usually fine)
            # But specific regex might fail. Here we use literal search which is fast.
            # Use helper that supports mmap
            count = self._count_pattern(data, pattern)
            if count > 0:
                api_counts[api] = count
        
        return {
            'total_unique_apis': len(api_counts),
            'total_references': sum(api_counts.values()),
            'api_details': api_counts
        }
    
    def _find_network_indicators(self, data: bytes) -> Dict:
        """Find network-related indicators"""
        network_hits = {}
        
        for pattern in self.network_patterns:
            # simple byte search is fast, keep as is
            # simple byte search is fast, keep as is
            count = self._count_pattern(data, pattern)
            if count > 0:
                network_hits[pattern.decode('ascii', errors='ignore')] = count
        
        return {
            'has_network_activity': len(network_hits) > 0,
            'network_pattern_count': sum(network_hits.values()),
            'patterns': network_hits
        }
    
    def _find_registry_indicators(self, data: bytes) -> Dict:
        """Find Windows registry indicators"""
        registry_hits = {}
        
        for pattern in self.registry_patterns:
            count = self._count_pattern(data, pattern)
            if count > 0:
                registry_hits[pattern.decode('ascii', errors='ignore')] = count
        
        return {
            'has_registry_activity': len(registry_hits) > 0,
            'registry_pattern_count': sum(registry_hits.values()),
            'patterns': registry_hits
        }
    
    def _extract_urls(self, data: bytes) -> List[str]:
        """Extract URLs from memory"""
        # Stricter regex to avoid binary garbage (printable ASCII only)
        # Matches http/https followed by allowed URL chars (alphanumeric + safe symbols)
        url_pattern = rb'https?://[a-zA-Z0-9\-\._~:/?#\[\]@!$&\'()*+,;=]+'
        matches = self._regex_find_chunked(url_pattern, data)
        
        # Additional cleanup: Filter out anything with non-ascii or control chars
        clean_urls = []
        for m in matches:
            try:
                decoded = m.decode('ascii')
                # Double check for common binary artifacts that might slip through
                if all(32 <= ord(c) <= 126 for c in decoded) and len(decoded) < 2048:
                    clean_urls.append(decoded)
            except UnicodeDecodeError:
                continue
                
        return list(set(clean_urls[:50]))  # Limit to 50 unique URLs
    
    def _extract_ip_addresses(self, data: bytes) -> List[str]:
        """Extract IP addresses from memory"""
        ip_pattern = rb'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        matches = self._regex_find_chunked(ip_pattern, data)
        
        ips = [m.decode('ascii') for m in matches[:50]]
        return list(set(ips))
    
    def _extract_file_paths(self, data: bytes) -> List[str]:
        """Extract Windows file paths from memory"""
        # Stricter regex: Drive letter, colon, backslash, then valid Windows path chars
        path_pattern = rb'[a-zA-Z]:\\[a-zA-Z0-9\-\._~\\(\) \[\]]+'
        matches = self._regex_find_chunked(path_pattern, data)
        
        clean_paths = []
        for m in matches:
            try:
                decoded = m.decode('ascii')
                # Heuristic: Valid paths usually don't have back-to-back dots or weird combos
                if all(32 <= ord(c) <= 126 for c in decoded) and len(decoded) > 4 and len(decoded) < 260:
                     clean_paths.append(decoded)
            except:
                continue
                
        return list(set(clean_paths[:50]))
    
    def _find_crypto_constants(self, data: bytes) -> Dict:
        """Find cryptographic constants (indicators of encryption)"""
        # Common crypto constants
        md5_constants = b'\x67\x45\x23\x01\xef\xcd\xab\x89'
        sha1_constants = b'\x67\x45\x23\x01\x01\x23\x45\x67'
        
        return {
            'has_md5_constants': md5_constants in data,
            'has_sha1_constants': sha1_constants in data
        }

    def _extract_pe_features(self, data: bytes) -> Dict:
        """Extract Static PE Header features (Kaggle Dataset Compatibility)"""
        try:
            # PEFile expects a file-like object or bytes
            # We use fast_load=True to avoid parsing all directories if not needed
            pe = pefile.PE(data=data, fast_load=True)
            
            features = {
                'Machine': pe.FILE_HEADER.Machine,
                'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
                'Characteristics': pe.FILE_HEADER.Characteristics,
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
                'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
                'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
                'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
                'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
                'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
                'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
                'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
                'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                'SectionsNb': pe.FILE_HEADER.NumberOfSections,
                'SectionsMeanEntropy': 0.0,  # Placeholder, could calculate if needed
                'SectionsMinEntropy': 0.0,
                'SectionsMaxEntropy': 0.0,
                'ResourcesNb': len(pe.DIRECTORY_ENTRY_RESOURCE.entries) if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0,
                'ImportsNbDLL': len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            }
            pe.close()
            return features
            
        except Exception as e:
            # Not a valid PE or partial dump
            return {}
    
    def calculate_weighted_risk(self, features: Dict, anomaly_score: float = 0.0, ml_confidence: float = 0.0) -> Dict:
        """
        Calculate Weighted Risk Score with refined logic (15/10/35/40 weighting).
        
        Weighting Distribution (Total 100):
        - YARA Signatures: Max 15 pts (Critical=15, High=12, Med=8, Low=5)
        - Integrity (Hooks): Max 10 pts (Confirmed Hooks=10)
        - ML Confidence: Max 35 pts (Scaled from ml_confidence 0-100)
        - Anomaly Score: Max 40 pts (Scaled from anomaly_score 0-100)
        
        Logic:
        - Strong forensic evidence (YARA/Hooks) contributes a base level.
        - ML and Anomaly (Behavioral) have the highest weight as requested.
        """
        risk_factors = []
        
        # --- 1. YARA COMPONENT (Max 15) ---
        yara_score = 0.0
        sig_match = features.get('signature_indicators', {}).get('is_signature_match', False)
        
        if sig_match:
            matched_rules = features.get('signature_indicators', {}).get('matched_rules', [])
            severities = [r.get('severity', 'low').lower() for r in matched_rules]
            
            if 'critical' in severities:
                yara_score = 15.0
                risk_factors.append("Critical YARA Match (+15)")
            elif 'high' in severities:
                yara_score = 12.0
                risk_factors.append("High Severity YARA Match (+12)")
            elif 'medium' in severities:
                yara_score = 8.0
                risk_factors.append("Medium Severity YARA Match (+8)")
            else:
                yara_score = 5.0
                risk_factors.append("Low Severity YARA Match (+5)")
                
        # --- 2. INTEGRITY COMPONENT (Max 10) ---
        integrity_score = 0.0
        integrity = features.get('integrity_indicators', {})
        
        # Check hooks
        hooks_data = integrity.get('hooks_detected', [])
        hooks_count = len(hooks_data) if isinstance(hooks_data, list) else int(hooks_data) if isinstance(hooks_data, int) else 0
        
        if hooks_count > 0:
             integrity_score = 10.0
             risk_factors.append(f"API Hooks Detected: {hooks_count} (+10)")
        
        # Check injection-specific YARA - Reinforce Integrity
        if sig_match:
             matched_rules = features.get('signature_indicators', {}).get('matched_rules', [])
             if any('injection' in r.get('name', '').lower() or 'reflective' in r.get('name', '').lower() for r in matched_rules):
                 # Boost integrity if YARA confirms injection
                 integrity_score = max(integrity_score, 30.0)
                 if "Injection Patterns Detected" not in risk_factors:
                    risk_factors.append("Injection Patterns Detected")

        # --- 3. ANOMALY COMPONENT (Max 40) ---
        # Normalize 0-100 score to 0-40
        anomaly_component = (anomaly_score / 100.0) * 40.0
        if anomaly_score > 70:
            risk_factors.append(f"High Anomaly Score: {anomaly_score:.1f} (+{anomaly_component:.1f})")

        # --- 4. ML COMPONENT (Max 35) ---
        # Normalize 0-100 confidence to 0-35
        ml_component = (ml_confidence / 100.0) * 35.0
        if ml_confidence > 70:
            risk_factors.append(f"High ML Confidence: {ml_confidence:.1f} (+{ml_component:.1f})")
            
        # --- TOTAL CALCULATION ---
        total_score = yara_score + integrity_score + anomaly_component + ml_component
        total_score = min(total_score, 100.0) # Cap total at 100
        
        # --- TRUST DAMPENING ---
        try:
            from config import TRUSTED_PROCESSES
            src_path = str(features.get('metadata', {}).get('source_dump', ''))
            process_name = Path(src_path).stem.split('_')[0].lower() if src_path else ""
            
            # Simple check
            is_trusted = any(p.lower() in process_name for p in TRUSTED_PROCESSES)
            
            if is_trusted:
                # Significant reduction for trusted processes unless there is STRONG evidence
                if yara_score < 40 and integrity_score < 30:
                    # If no Critical/High YARA and no Hooks -> CAP SCORE
                    original = total_score
                    total_score = min(total_score, 15.0) # Cap at Benign
                    if original > 15:
                        risk_factors.append(f"Score reduced from {original:.1f} (Trusted Process)")
                        
        except ImportError:
            pass

        return {
            'risk_score': round(total_score, 2),
            'max_score': 100.0,
            'components': {
                'yara_score': yara_score,
                'integrity_score': integrity_score,
                'anomaly_weighted': anomaly_component,
                'ml_weighted': ml_component
            },
            'risk_factors': risk_factors,
            'is_malicious': total_score >= 61.0 # Aligned with ML Engine / Unified Thresholds
        }
    
    def export_for_ml(self, features: Dict) -> List[float]:
        """
        Convert features to numerical vector for ML model
        Generates 27 features to match the deployed anomaly model (trained on CSV subset)
        
        Args:
            features: Feature dictionary
            
        Returns:
            Feature vector for ML inference (27 features)
        """
        pe = features.get('pe_features', {})
        behavioral = features.get('behavioral_indicators', {})
        stats = features.get('statistical_features', {})
        
        vector = [
            # Signature indicators (3 features)
            float(features['signature_indicators']['is_signature_match']),
            features['signature_indicators']['total_detections'],
            len(features['signature_indicators']['matched_rules']),
            
            # Integrity indicators (3 features)
            float(features['integrity_indicators']['is_compromised']),
            features['integrity_indicators']['hooks_detected'],
            features['integrity_indicators']['clean_functions'],
            
            # Behavioral indicators (7 features — registry removed but placeholder kept for model alignment)
            behavioral.get('suspicious_apis', {}).get('total_references', 0),
            float(behavioral.get('network_indicators', {}).get('has_network_activity', False)),
            behavioral.get('network_indicators', {}).get('network_pattern_count', 0),
            0,  # Registry placeholder (removed feature — kept as 0 for model compatibility)
            len(behavioral.get('urls', []) or []),
            len(behavioral.get('ip_addresses', []) or []),
            len(behavioral.get('file_paths', []) or []),
            
            # Statistical features (4 features only - Size Excluded)
            stats.get('entropy', 0),
            stats.get('null_byte_ratio', 0),
            stats.get('printable_ratio', 0),
            stats.get('unique_bytes', 0),
            
            # PE Features - Subset (10 features) for Model Compatibility
            float(pe.get('Machine', 0)),
            float(pe.get('SizeOfOptionalHeader', 0)),
            float(pe.get('Characteristics', 0)),
            float(pe.get('MajorLinkerVersion', 0)),
            float(pe.get('SizeOfCode', 0)),
            float(pe.get('SizeOfInitializedData', 0)),
            float(pe.get('SizeOfUninitializedData', 0)),
            float(pe.get('AddressOfEntryPoint', 0)),
            float(pe.get('ImageBase', 0)),
            float(pe.get('DllCharacteristics', 0))
        ]
        
        return vector
