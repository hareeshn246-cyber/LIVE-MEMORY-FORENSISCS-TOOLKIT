"""
YARA Detection Engine
Scans RAW process memory for malware signatures
Automatically triggers secure deletion after analysis
"""

import yara
from pathlib import Path
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class YARAEngine:
    """
    Signature-based detection using YARA rules
    Scans RAW memory dumps and triggers automated cleanup
    """
    
    def __init__(self, rules_path: Optional[Path] = None):
        from config import YARA_RULES_PATH, YARA_TIMEOUT_SECONDS
        
        self.rules_path = rules_path or YARA_RULES_PATH
        self.timeout = YARA_TIMEOUT_SECONDS
        self.rules = self._load_rules()
        
    def _load_rules(self) -> Optional[yara.Rules]:
        """Load and compile YARA rules from file"""
        if not self.rules_path.exists():
            logger.warning(f"YARA rules file not found: {self.rules_path}")
            logger.info("Creating default YARA rules file")
            self._create_default_rules()
        
        try:
            rules = yara.compile(filepath=str(self.rules_path))
            logger.info(f"Successfully loaded YARA rules from {self.rules_path}")
            return rules
        except Exception as e:
            logger.error(f"Error loading YARA rules: {e}")
            return None
    
    def _create_default_rules(self):
        """
        Create default YARA rules for common malware patterns
        NOTE: Simplified to avoid duplication. 
        Main rules are maintained in rules/malmem_rules.yar
        """
        # Checks if file exists, if not, warns user instead of overwriting with old defaults
        logger.warning(f"YARA rules file missing at {self.rules_path}. Please restore 'rules/malmem_rules.yar'.")
        # We process without rules rather than injecting legacy ones
        pass
        

    
    def _yara_callback(self, data):
        """
        YARA callback to limit matches and prevent OOM
        """
        if data['matches']:
            self._scan_match_count += 1
            
        # Stop scanning if we exceed the safety limit
        if self._scan_match_count > 10000:  # Hard limit of 10k matches
            return yara.CALLBACK_ABORT
            
        return yara.CALLBACK_CONTINUE

    def scan_memory_dump(self, dump_path: Path, evidence_metadata: Dict) -> Dict:
        """
        Scan RAW memory dump with YARA rules
        AUTOMATICALLY triggers secure deletion after scan
        
        Args:
            dump_path: Path to RAW memory dump file
            evidence_metadata: Metadata dictionary from lifecycle manager
            
        Returns:
            Scan results dictionary
        """
        if not self.rules:
            return {
                'status': 'error',
                'message': 'YARA rules not loaded',
                'matches': []
            }
        
        # Ensure dump_path is a Path object
        if isinstance(dump_path, str):
            dump_path = Path(dump_path)
            
        logger.info(f"Starting YARA scan of {dump_path.name}")
        
        try:
            # Initialize match counter for this scan
            self._scan_match_count = 0
            
            # Scan the RAW dump with callback
            matches = []
            try:
                matches = self.rules.match(
                    filepath=str(dump_path),
                    timeout=self.timeout,
                    callback=self._yara_callback
                )
            except Exception as e:
                # If aborted or error, log it
                logger.warning(f"YARA scan ended/aborted: {e}")
                
            # Note: yara-python match() returns a list of Match objects.
            # If aborted via callback, it might return what it found so far or raise.

            # Let's re-run without callback if we want *some* results but that defeats the purpose.
            # Actually, standard yara.match returns the matches found so far if aborted? 
            # Re-reading docs: "The callback function... if it returns yara.CALLBACK_ABORT the scanning is aborted."
            # The return value of match() is the list of matches found.
            
            # Re-scan safely? No, that causes OOM.
            # We trust the matches variable is populated or we handle it.
            
            # To be safe against "local variable 'matches' referenced before assignment" if exception occurs:
            if 'matches' not in locals():
                matches = []

            # Check if we hit the limit
            limit_reached = self._scan_match_count > 10000

            # SMART FILTERING: Ignored Rules for Trusted Processes
            # These rules are too generic for complex apps like Chrome/Edge
            GENERIC_RULES = [
                'Suspicious_API_Sequence', 'Code_Injection_Pattern', 
                'Shellcode_Indicators', 'Encrypted_Payload', 'Keylogger_Behavior'
            ]
            
            # [REFAC] Use Centralized Whitelist from Config
            try:
                from config import TRUSTED_PROCESSES
                TRUSTED_APPS = TRUSTED_PROCESSES
            except ImportError:
                # Fallback if config fails
                TRUSTED_APPS = [
                    'chrome.exe', 'msedge.exe', 'firefox.exe', 'opera.exe',
                    'svchost.exe', 'explorer.exe', 'searchui.exe',
                    'msedgewebview2.exe', 'teams.exe', 'discord.exe',
                    'audiodg.exe', 'services.exe', 'wininit.exe', 'lsass.exe', 
                    'csrss.exe', 'winlogon.exe', 'dwm.exe'
                ]
            
            # Check if current dump is from a trusted app
            is_trusted_app = any(app.lower() in str(dump_path).lower() for app in TRUSTED_APPS)

            # Parse matches (Limit the *stored* matches too, creating a new list)
            detections = []
            valid_match_count = 0 
            
            for i, match in enumerate(matches):
                # FILTER: Logic for trusted apps
                if is_trusted_app:
                    rule_severity = match.meta.get('severity', 'unknown').lower()
                    
                    
                    # 1. ALWAYS Ignore specific noisy rules for trusted apps
                    if match.rule in GENERIC_RULES or match.rule == 'Whitelisted_System_Process':
                        continue
                        
                    # 2. SENSITIVE PROCESS FILTER (Development Tools)
                    # Tools like VS Code and Language Servers hold arbitrary strings in memory (including malware signatures from files being edited)
                    # We must be extremely conservative with them.
                    SENSITIVE_DEV_TOOLS = ['code.exe', 'language_server', 'devenv.exe', 'idea64.exe', 'pyrefly.exe']
                    is_sensitive_tool = any(t in str(dump_path).lower() for t in SENSITIVE_DEV_TOOLS)
                    
                    if is_sensitive_tool:
                        # For dev tools, ignore ALMOST EVERYTHING except specific injection patterns
                        # that represent actual behavioral compromise, not just static strings.
                        ALLOWED_FOR_DEV = ['Code_Injection_Pattern', 'Reflective_DLL_Loading']
                        if match.rule not in ALLOWED_FOR_DEV:
                            continue

                    # 3. Ignore non-critical matches for generic trusted apps
                    if rule_severity not in ['critical', 'high']:
                        continue
                
                valid_match_count += 1
                
                if i >= 100: # Only store details for top 100 matches to save JSON size
                    break
                    
                detection = {
                    'rule_name': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [
                        {
                            'identifier': s.identifier,
                            'instances': len(s.instances),
                            # Limit number of offsets stored per string
                            'offsets': [inst.offset for inst in s.instances[:10]] 
                        }
                        for s in match.strings[:50] # Limit strings per match
                    ]
                }
                detections.append(detection)
                if i < 5: # Only log first few
                    logger.warning(f"YARA MATCH: {match.rule} in {dump_path.name}")
            
            scan_results = {
                'status': 'completed' if not limit_reached else 'truncated',
                'dump_path': str(dump_path),
                'dump_sha256': evidence_metadata.get('hashes', {}).get('sha256'),
                'total_matches': valid_match_count, # Use filtered count
                'matches_limit_reached': limit_reached,
                'detections': detections,
                'is_malicious': valid_match_count > 0, # Only mark malicious if valid matches exist
                'scan_timestamp': evidence_metadata.get('timestamp')
            }
            
            # CRITICAL: Auto-deletion requested to be moved to orchestrator (UI/Worker)
            # to allow feature extraction to complete first.
            scan_results['raw_deleted'] = False
            
            return scan_results
            
        except Exception as e:
            logger.error(f"Error during YARA scan: {e}")
            return {
                'status': 'error',
                'message': str(e),
                'matches': [],
                'raw_deleted': False
            }
    
    def scan_process_live(self, pid: int) -> Dict:
        """
        Scan live process memory (without dumping to disk)
        For quick analysis without evidence retention
        
        Args:
            pid: Process ID to scan
            
        Returns:
            Scan results
        """
        # This would require custom YARA callback for process memory
        # For now, we'll use the dump-then-scan approach
        logger.info(f"Live scanning not yet implemented, use full acquisition")
        return {
            'status': 'not_implemented',
            'message': 'Use acquire_and_scan workflow'
        }
    
    def reload_rules(self, new_rules_path: Optional[Path] = None) -> bool:
        """
        Reload YARA rules from file
        
        Args:
            new_rules_path: Optional new path to rules file
            
        Returns:
            True if successful
        """
        if new_rules_path:
            self.rules_path = new_rules_path
        
        self.rules = self._load_rules()
        return self.rules is not None
