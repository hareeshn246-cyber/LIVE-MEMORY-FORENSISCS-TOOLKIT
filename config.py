"""
Global Configuration Module
Maps project paths, thresholds, and system parameters
"""

import os
from pathlib import Path

# ============================================================================
# PROJECT ROOT AND PATHS
# ============================================================================

BASE_DIR = Path(__file__).resolve().parent

# Core Directories
CORE_DIR = BASE_DIR / "core"
DETECTION_DIR = BASE_DIR / "detection"
UI_DIR = BASE_DIR / "ui"

# Data Directories
DATA_DIR = BASE_DIR / "data"
DATA_RAW_DIR = DATA_DIR / "raw"
DATA_PROCESSED_DIR = DATA_DIR / "processed"

# Models Directory
MODELS_DIR = BASE_DIR / "models"
MODEL_CLASSIFIER_PATH = MODELS_DIR / "mem_classifier.pkl"
MODEL_SCALER_PATH = MODELS_DIR / "scaler.pkl"
ANOMALY_MODEL_PATH = MODELS_DIR / "anomaly_model.pkl"

# Storage Directories
STORAGE_DIR = BASE_DIR / "storage"
STORAGE_RAW_TEMP_DIR = STORAGE_DIR / "raw_temp"  # AUTO-WIPED
STORAGE_ARTIFACTS_DIR = STORAGE_DIR / "artifacts"  # PERMANENT

# Reports Directory
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_OUTPUT_DIR = REPORTS_DIR / "Final_Reports"

# Rules Directory
RULES_DIR = BASE_DIR / "rules"
YARA_RULES_PATH = RULES_DIR / "malmem_rules.yar"

# ============================================================================
# ADVANCED FORENSICS CONFIGURATION (SAFE EXTENSION)
# ============================================================================
ADVANCED_MODE = False        # Master Switch (Default: False)

# ============================================================================
# DETECTION THRESHOLDS
# ============================================================================

# YARA Scanning
YARA_TIMEOUT_SECONDS = 300  # 5 minutes per process

# Feature Extraction Timeouts (Prevent UI Freezing)
FEATURE_EXTRACTION_TIMEOUT = 60  # 60 seconds total timeout for feature extraction
PE_PARSING_TIMEOUT = 10  # 10 seconds for PE header parsing
REGEX_TIMEOUT = 30  # 30 seconds for regex operations

# Machine Learning
ML_MALWARE_THRESHOLD = 0.70  # Higher confidence required (Reduced noise)
ML_HIGH_RISK_THRESHOLD = 0.90

# Hook Detection
HOOK_DETECTION_FUNCTIONS = [
    "NtCreateThread",
    "NtCreateThreadEx",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtOpenProcess",
    "NtCreateProcess",
    "NtCreateProcessEx",
    "NtSetContextThread",
    "NtQueueApcThread"
]

HOOK_BYTE_COMPARE_LENGTH = 32  # First 32 bytes of function prologue

# ============================================================================
# MEMORY ACQUISITION SETTINGS
# ============================================================================

# Process filtering
EXCLUDE_SYSTEM_PROCESSES = ["System", "Registry", "smss.exe", "csrss.exe"]
# Comprehensive list of standard Windows system processes to prevent false positives
TRUSTED_PROCESSES = [
    # Core System
    "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "svchost.exe", "fontdrvhost.exe", "winlogon.exe", "dwm.exe",
    
    # Windows Shell & UI
    "explorer.exe", "taskmgr.exe", "sihost.exe", "ShellExperienceHost.exe",
    "StartMenuExperienceHost.exe", "SearchApp.exe", "SearchUI.exe",
    "ApplicationFrameHost.exe", "SystemSettings.exe", "TextInputHost.exe",
    "ctfmon.exe", "ChsIME.exe", "smartscreen.exe",
    
    # Runtime & Services
    "RuntimeBroker.exe", "backgroundTaskHost.exe", "conhost.exe",
    "WmiPrvSE.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe",
    "audiodg.exe", "dasHost.exe",
    
    # Microsoft Apps/Services
    "AggregatorHost.exe", "GameBar.exe", "GameBarFTServer.exe",
    "YourPhone.exe", "Calculator.exe", "Notepad.exe", "mspaint.exe",
    
    # Browsers (Common)
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
    
    # Hardware Drivers (AMD/NVIDIA)
    "amdow.exe", "amdfendrsr.exe", "atiesrxx.exe", "AMDRSServ.exe", "amdrssrecext.exe",
    "nvcontainer.exe", "nvdisplay.container.exe",
    
    # Gaming & Anti-Cheat (Avoid False Positives)
    "steam.exe", "steamwebhelper.exe", "epicgameslauncher.exe", 
    "riotclientservices.exe", "valorant.exe", "leagueoflegends.exe",
    "easyanticheat.exe", "vgtray.exe",
    
    # Development Tools (Whitelisted)
    "Antigravity.exe", "python.exe", "language_server_windows_x64.exe", "code.exe"
]
MIN_PROCESS_MEMORY_MB = 0  # 0 to capture EVERYTHING (even 0.1MB malware stubs)
MAX_ANALYSIS_SIZE_MB = 16384 # Maximum memory size to analyze (16GB for full RAM)

# Memory region types to capture
CAPTURE_MEM_TYPES = [
    "MEM_PRIVATE",  # Private memory
    "MEM_IMAGE"     # Executable images
]

# ============================================================================
# LIFECYCLE MANAGEMENT
# ============================================================================

# RAW memory deletion policy
AUTO_DELETE_RAW_AFTER_YARA = True  # AUTOMATED WIPE
SECURE_DELETE_PASSES = 1  # Reduced from 3 to 1 for performance (DoD standard causes lag)
ACQUISITION_THROTTLE_MS = 0  # No artificial delay — timeout guard in acquisition.py prevents hangs

# JSON artifact retention
ARTIFACT_RETENTION_DAYS = 365  # 1 year

# ============================================================================
# REPORTING SETTINGS
# ============================================================================

REPORT_LOGO_PATH = UI_DIR / "icons" / "forensic_logo.png"
REPORT_TEMPLATE = "forensic_standard"
REPORT_FORMAT = "PDF"

# ============================================================================
# UI CONFIGURATION
# ============================================================================

UI_THEME = "dark"
UI_REFRESH_RATE_MS = 500  # Dashboard refresh rate
UI_PROCESS_LIST_LIMIT = 500

# ============================================================================
# LOGGING
# ============================================================================

LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = BASE_DIR / "forensic_tool.log"

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def ensure_directories():
    """Create all required directories if they don't exist"""
    directories = [
        DATA_RAW_DIR,
        DATA_PROCESSED_DIR,
        MODELS_DIR,
        STORAGE_RAW_TEMP_DIR,
        STORAGE_ARTIFACTS_DIR,
        REPORTS_OUTPUT_DIR,
        RULES_DIR,
        UI_DIR / "icons"
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)

def get_temp_raw_path(process_name: str, pid: int) -> Path:
    """Generate temporary raw memory dump path with sanitation"""
    import re
    # Remove invalid filename characters: \ / : * ? " < > |
    clean_name = re.sub(r'[\\/:*?"<>|]', '_', process_name)
    return STORAGE_RAW_TEMP_DIR / f"{clean_name}_{pid}_{os.getpid()}.raw"

def get_artifact_path(process_name: str, pid: int, timestamp: str) -> Path:
    """Generate JSON artifact path"""
    return STORAGE_ARTIFACTS_DIR / f"{process_name}_{pid}_{timestamp}.json"

# Initialize directories on import
ensure_directories()
