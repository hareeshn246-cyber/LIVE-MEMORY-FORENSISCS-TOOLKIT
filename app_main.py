"""
Windows Memory Forensics & Malware Detection Tool
MAIN ENTRY POINT

Description:
A Windows memory forensics tool that performs YARA-based signature scanning
on raw process memory dumps, detects passive inline hooks via NTDLL 
integrity comparison, conducts ML-driven behavioral analysis using retained 
JSON artifacts, securely deletes raw dumps after analysis, and generates 
forensic reports manually.

Architecture:
- RAW memory dumps: Retained for inspection (NOT auto-deleted)
- JSON artifacts: Permanent retention for ML and correlation
- Detection engines: YARA, Hook Detection, ML Classification
- Reports: Manual generation with full forensic chain

Author: Research Project
Date: 2026
"""

import sys
import os
import logging
from pathlib import Path

# Force Path to Script Directory (Fix for Desktop Shortcuts)
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

os.chdir(application_path)
sys.path.insert(0, application_path)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('forensic_tool.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


def check_admin_privileges():
    """
    Check if running with administrator privileges
    If not, attempt to elevate using ShellExecute 'runas'
    Returns True if already admin, False if elevation was triggered (and we should exit)
    """
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        
        if is_admin:
            logger.info("Running with Administrator privileges")
            return True
            
        # Not admin - attempt to elevate
        logger.info("Attempting to elevate privileges via UAC...")
        print("\n[*] Requesting Administrator privileges...")
        
        # Re-run the script with 'runas' (Admin)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, 
            "runas", 
            sys.executable, 
            " ".join(f'"{arg}"' for arg in sys.argv), 
            None, 
            1
        )
        
        # If ShellExecuteW returns > 32, it succeeded
        if result > 32:
            logger.info("UAC elevation triggered, exiting non-admin instance")
            sys.exit(0)
        else:
            # User clicked No or error occurred
            logger.warning(f"UAC elevation failed or declined (code: {result})")
            print("\n[!] WARNING: Administrator privileges required for full functionality")
            print("Some processes may not be accessible.\n")
            return True  # Continue anyway with limited access
        
    except Exception as e:
        logger.warning(f"Failed to check/elevate privileges: {e}")
        print(f"\n[!] WARNING: Could not verify admin status: {e}")
        return True  # Continue anyway


def check_dependencies():
    """Verify all required dependencies are installed (Fast Check)"""
    import importlib.util
    
    required = {
        'yara': 'yara-python',
        'psutil': 'psutil',
        'win32api': 'pywin32',
        'PyQt5': 'PyQt5',
        'sklearn': 'scikit-learn',
        'reportlab': 'reportlab',
        'pefile': 'pefile'
    }
    
    missing = []
    
    for module_name, pkg_name in required.items():
        if not importlib.util.find_spec(module_name):
            missing.append(pkg_name)
    
    if missing:
        logger.error(f"Missing dependencies: {', '.join(missing)}")
        print("\n[!] MISSING DEPENDENCIES")
        print("Please install the following packages:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\nRun: pip install -r requirements.txt")
        return False
    
    return True


def display_banner():
    """Display application banner"""
    banner = """
==========================================================================
                                                                          
            FORENSICS PROJECT - ADVANCED MALWARE DETECTION               
                        AND HIDDEN PROCESSES                              
                                                                          
  [*] Signature-based Detection (YARA)                                   
  [*] Memory Integrity Validation (Hook Detection)                       
  [*] Machine Learning Classification                                    
  [*] Behavioral Analysis & Feature Extraction                           
  [*] RAW Dump Retention (No Auto-Delete)                                
  [*] Forensic Report Generation                                         
                                                                           
  Evidence Lifecycle:                                                    
    -> RAW Memory: RETAINED (Available for re-analysis)                  
    -> JSON Artifacts: PERMANENT (Retained for analysis)                 
                                                                          
==========================================================================
    """
    print(banner)


def initialize_directories():
    """Initialize all required directories"""
    from config import ensure_directories
    
    try:
        ensure_directories()
        logger.info("Directory structure initialized")
        return True
    except Exception as e:
        logger.error(f"Failed to initialize directories: {e}")
        return False


def run_cli_mode():
    """Run in command-line interface mode"""
    print("\n[*] CLI Mode - Basic Operations\n")
    
    from core.acquisition import MemoryAcquisition
    
    acquisition = MemoryAcquisition()
    
    print("Loading running processes...")
    processes = acquisition.get_process_list()
    
    print(f"\nTop 10 Processes by Memory Usage:\n")
    print(f"{'PID':<8} {'Process Name':<30} {'Memory (MB)':<12}")
    print("-" * 50)
    
    for proc in processes[:10]:
        print(f"{proc['pid']:<8} {proc['name']:<30} {proc['memory_mb']:<12}")
    
    print("\n[*] For full functionality, run with GUI mode (default)")


def run_gui_startup():
    """
    Launch GUI with immediate Splash Screen
    Perform dependency checks and imports *while* splash is visible
    """
    try:
        from PyQt5.QtWidgets import QApplication, QMessageBox, QLabel
        from PyQt5.QtCore import Qt, QThread, pyqtSignal
    except ImportError:
        logger.error("PyQt5 not installed. Cannot launch GUI.")
        print("[!] Fatal: PyQt5 is missing. Run: pip install PyQt5")
        return

    # 1. Create App & Show Splash IMMEDIATELY
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    
    # Get Screen Geometry for Centering
    screen_geometry = app.desktop().screenGeometry()
    screen_center = screen_geometry.center()

    splash = QLabel("🔮 Initializing Memory Forensics Tool...\n\nRunning system checks...")
    splash.setStyleSheet("""
        QLabel {
            background-color: #1e1e1e;
            color: #00ffcc;
            font-family: 'Segoe UI', sans-serif;
            font-size: 16px;
            font-weight: bold;
            padding: 40px;
            border: 2px solid #00ffcc;
            border-radius: 12px;
            min-width: 400px;
            qproperty-alignment: AlignCenter;
        }
    """)
    splash.setAlignment(Qt.AlignCenter)
    splash.setWindowFlags(Qt.SplashScreen | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint)
    
    # Center Splash
    splash.adjustSize()
    splash.move(screen_center - splash.rect().center())
    
    splash.show()
    app.processEvents()
    
    # 2. Perform Heavy Imports/Checks with visual updates
    try:
        # Check Deps
        splash.setText("🔮 Loading Core Engines...\n\nChecking Dependencies...")
        app.processEvents()
        
        if not check_dependencies():
            splash.close()
            # Check dependencies logs error, just exit
            sys.exit(1)
            
        # Init Dirs
        splash.setText("🔮 preparing Workspace...\n\nInitializing Directories...")
        app.processEvents()
        
        if not initialize_directories():
            splash.close()
            sys.exit(1)
            
        # Import UI (Heavy)
        splash.setText("🔮 Starting User Interface...\n\nLoading Layouts...")
        app.processEvents()
        
        from ui.layouts import ForensicToolUI
        
        # Exception Hook
        def exception_hook(exctype, value, tb):
            import traceback
            traceback_str = ''.join(traceback.format_tb(tb))
            # Log full traceback to file
            logger.critical(f"Unhandled Exception: {value}\nTraceback:\n{traceback_str}")
            # Ensure it hits stdout/stderr for CLI capture
            traceback.print_exc()
            
            try:
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Critical)
                msg.setWindowTitle("FORENSICS PROJECT - Critical Error")
                msg.setText(f"A critical error occurred:\n\n{str(value)}")
                msg.setDetailedText(traceback_str)
                msg.exec_()
            except:
                # If GUI fails, we at least have the logs
                pass
            sys.exit(1)
        sys.excepthook = exception_hook

        # Launch Main Window
        window = ForensicToolUI()
        
        splash.close()
        window.show()
        
        sys.exit(app.exec_())
        
    except Exception as e:
        splash.close()
        logger.critical(f"Startup failed: {e}")
        QMessageBox.critical(None, "Startup Error", f"Failed to start application:\n\n{e}")
        sys.exit(1)


def main():
    """Main application entry point"""
    display_banner()
    logger.info(f"Starting Windows Memory Forensics Tool (Exec: {sys.executable})")
    logger.debug(f"Python Path: {sys.path}")
    
    # 1. Elevate Privileges (Restart script if needed)
    if not check_admin_privileges():
        # Elevation failed or user declined, but we continue with warning
        pass

    # 3. Launch Interface
    if len(sys.argv) > 1 and sys.argv[1] == '--cli':
        # CLI Mode: Check deps sequentially
        if not check_dependencies(): sys.exit(1)
        if not initialize_directories(): sys.exit(1)
        run_cli_mode()
    else:
        # GUI Mode: Delegate everything to startup wrapper for Splash Screen
        print("\n[*] Launching GUI...")
        try:
            run_gui_startup()
        except Exception as e:
            logger.critical(f"GUI failed to start: {e}", exc_info=True)
            print(f"\n[!] GUI ERROR: {e}")
            sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Operation cancelled by user")
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Fatal error: {e}", exc_info=True)
        print(f"\n[!] FATAL ERROR: {e}")
        sys.exit(1)
