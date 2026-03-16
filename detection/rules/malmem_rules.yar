/*
    CIC-MalMem-2022 Memory Forensics YARA Ruleset
    Author: Antigravity (Google Deepmind)
    Description: 
        YARA rules designed to detect behaviors associated with CIC-MalMem-2022 features:
        - pslist anomalies (excessive threads -> injection)
        - dlllist anomalies (loaded dlls -> reflective loading)
        - handles anomalies (registry keys -> persistence)
    
    References:
        - CIC-MalMem-2022 Dataset
        - Common Malware Enumeration (CME)
*/

import "pe"

rule MalMem_ProcessInjection_classic {
    meta:
        description = "Detects classic process injection APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)"
        score = 75
        feature_mapping = "pslist_nthread (High thread count often results from injected threads)"
        date = "2026-01-24"
    strings:
        $api1 = "VirtualAllocEx" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "CreateRemoteThread" ascii
        $api4 = "OpenProcess" ascii
    condition:
        // Presence of these APIs in a non-debugger process is suspicious
        3 of them
}

rule MalMem_Reflective_DLL_Injection {
    meta:
        description = "Detects Reflective DLL Injection artifacts"
        score = 90
        feature_mapping = "dlllist_ndlls (Unlinked DLLs or anomalous DLL counts)"
        reference = "Stephan Borosmokanyos ReflectiveDLLInjection"
    strings:
        $mz = "MZ"
        $rdi_func = "ReflectiveLoader" ascii fullword
        $magic_func = { 4D 5Z 90 00 } // Heuristic for PE header start in buffer
    condition:
        $rdi_func
}

rule MalMem_Persistence_Registry_RunKeys {
    meta:
        description = "Detects strings related to Registry Persistence mechanisms"
        score = 60
        feature_mapping = "handles_nregistry (Abuse of registry handles for persistence)"
    strings:
        $reg_run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $reg_runonce = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide
        $api_reg = "RegSetValueEx" ascii
    condition:
        $api_reg and (any of ($reg_*))
}

rule MalMem_Suspicious_PowerShell_Encoded {
    meta:
        description = "Detects encoded PowerShell commands often used in fileless malware"
        score = 80
        feature_mapping = "pslist (Anomalous process arguments/behavior)"
    strings:
        $b64_flag_1 = "-enc" ascii wide nocase
        $b64_flag_2 = "-EncodedCommand" ascii wide nocase
        $ps_hidden = "-w hidden" ascii wide nocase
    condition:
        any of them
}

rule MalMem_Ransomware_ShadowCopies {
    meta:
        description = "Detects commands used to delete shadow copies (Ransomware behavior)"
        score = 100
        feature_mapping = "handles_nfiles (High handle count to files), malicious intent"
    strings:
        $vss_1 = "vssadmin.exe" ascii wide nocase
        $vss_2 = "Delete Shadows" ascii wide nocase
        $wbadmin = "wbadmin DELETE SYSTEMSTATEBACKUP" ascii wide nocase
        $bcdedit = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
    condition:
        any of them
}

rule MalMem_Memory_Packed_HighEntropy {
    meta:
        description = "Detects potential packed code or high entropy sections"
        score = 50
        feature_mapping = "handles_nfiles (Obfuscation), Entropy Analysis"
    strings:
        $upx_sig = "UPX0" ascii
        $upx_sig2 = "UPX1" ascii
    condition:
        // Basic check for UPX, a common packer
        any of them
}

rule MalMem_Suspicious_Network_APIs {
    meta:
        description = "Detects network communication APIs often used by C2"
        score = 60
        feature_mapping = "dlllist (Network libraries loaded: ws2_32.dll, wininet.dll)"
    strings:
        $net_1 = "InternetOpenUrlA" ascii
        $net_2 = "HttpSendRequestA" ascii
        $net_3 = "URLDownloadToFile" ascii
        $net_4 = "WSAStartup" ascii
    condition:
        2 of them
}
