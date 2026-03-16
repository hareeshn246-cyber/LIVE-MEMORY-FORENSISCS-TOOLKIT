# FORENSICS PROJECT
### Advanced Malware Detection & Analysis Framework

**Yes, absolutely.** This tool identifies as a **Live Memory Forensics** solution because it performs real-time acquisition and analysis of volatile memory (RAM) from running processes, without requiring a system reboot or external hardware.

## ❓ Why "Process-Centric" Memory Forensics?
Traditional antivirus tools scan files on the **Hard Disk**. This tool scans **Volatile RAM**.
*   **Malware Unpacking**: Malware often decrypts itself only in memory. We catch it there.
*   **Fileless Threats**: Some attacks never touch the disk. We find them in RAM.
*   **Hook Detection**: We detect if malware has tampered with the live operating system functions.

### ⚡ vs. Traditional Memory Dumpers (like Volatility)
While tools like **Volatility** are powerful, they typically require capturing the **ENTIRE** system RAM (16GB+), which is slow, hard to transfer, and requires complex command-line analysis.
*   **Surgical Precision**: This tool captures **only** the suspicious process (e.g., 50MB), making it 100x faster.
*   **Live Analysis**: You don't need to crash the system or take a full image to find a threat.
*   **Automated Intelligence**: Instead of manual plugins, our ML Engine gives you an instant "Malicious/Benign" verdict.

---

## 🔄 The Forensic Workflow

This tool is designed to follow a strict forensic chain of custody while providing automated threat intelligence.

### 1. Initialization & Privilege Escalation
*   **Action**: When you launch `app_main.py` or the executable.
*   **System Check**: The tool immediately requests **SeDebugPrivilege**. This is a critical Windows API right that allows the tool to "debug" (read the memory of) other high-privileged processes like `lsass.exe` or `svchost.exe`.
*   **Safety**: It verifies dependencies (YARA, PEFile) and initializes the Machine Learning models.

### 2. Live Target Selection (Batch Analysis Tab)
*   **Action**: Navigate to the **Batch Analysis** tab.
*   **Process Enumeration**: The tool scans the entire process list in real-time.
*   **Targeting**: You can select specific processes or run a **Full System Scan**.
*   **Smart Filtering**:
    *   **Trusted Apps**: Processes running from `C:\Windows` or `C:\Program Files` are automatically identified.
    *   **Optimization**: Requires minimal memory footprint to avoid crashing the system during analysis.

### 3. Deep Analysis Algorithms (The "Algo Analysis")
Once analysis starts, the tool relies on four core engines working in parallel:

#### A. Memory Acquisition Engine
*   **Technique**: Uses the `ReadProcessMemory` Windows API.
*   **Function**: Takes a "snapshot" of the process's RAM (Private, Mapped, and Image memory) and dumps it to a sophisticated buffer.
*   **Privacy**: These dumps are analyzed and then **Securely Deleted** immediately after the result is obtained.

#### B. Integrity & Hook Detection
*   **Purpose**: Detects **Rootkits** and **User-Land Hooks** (which malware uses to hide).
*   **Algorithm**:
    1.  Reads the `NTDLL.DLL` from the **Disk** (Clean copy).
    2.  Reads the `NTDLL.DLL` from the **Live Memory** (Potentially infected).
    3.  **Orchestrated Comparison**: It compares the assembly code of every system function. If there is a mismatch (e.g., a Jump instruction to an unknown address), it flags a **Critical Hook**.

#### C. YARA Signature Engine
*   **Purpose**: Identifies known malware families.
*   **Operation**: Scans the memory dump against a database of extended rules (Ransomware, trojans, RATs). It can detect "fileless" malware that exists only in RAM, never touching the hard drive.

#### D. Behavioral & ML Anomaly Detection
*   **Purpose**: Detects **Zero-Day** (Unknown) threats.
*   **Feature Extraction**:
    *   **API Calls**: Counts suspicious imports (e.g., `VirtualAlloc`, `CreateRemoteThread`).
    *   **Network**: Scrapes RAM for IP addresses and URL patterns.
    *   **Entropy**: Measures randomness to detect packed/encrypted code.
*   **Machine Learning**: A Random Forest classifier (trained on 50,000+ samples) analyzes these features to output a verdict: **BENIGN**, **SUSPICIOUS**, or **MALICIOUS**.
    *   *Note*: Trusted system apps are automatically dampened to reduce false alarms.

### 4. Review & Export (Batch Analysis Results)
*   **The Results Table**:
    *   **Green**: Low Threat (Safe/Trusted).
    *   **Orange**: Medium Threat (Suspicious Anomaly or API usage).
    *   **Red**: Critical Threat (Confirmed Malware Signature or Rootkit Hook).
*   **Exports**: You can generate a **PDF Report** or **Excel Sheet** of the entire session for legal/compliance review.

### 5. Report Integrity Verification (Report & Integrity Tab)
*   **Purpose**: Chain of Custody.
*   **Workflow**:
    1.  Go to the **Report & Integrity** tab.
    2.  Select a previously generated PDF report.
    3.  Select its accompanying `.sig` (Signature) file.
    4.  **Verification**: The tool re-calculates the cryptographic hash (HMAC-SHA256) of the PDF.
    5.  **Verdict**: It confirms if the report is **AUTHENTIC** or **TAMPERED**, ensuring evidence hasn't been altered.
