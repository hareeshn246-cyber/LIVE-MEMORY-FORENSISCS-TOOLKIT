import "pe"

rule Whitelisted_System_Process {
    meta:
        description = "Matches known benign system process characteristics"
        severity = "info"
        author = "Internal"
    strings:
        $ms = "Microsoft Corporation" ascii wide
        $win = "Windows" ascii wide
        $amd = "Advanced Micro Devices" ascii wide
        $audio = "Windows Audio" ascii wide
        $sys1 = "ntdll.dll" ascii wide
        $sys2 = "kernel32.dll" ascii wide
        $self1 = "Antigravity.exe" ascii wide
        $self2 = "python.exe" ascii wide
    condition:
        ($ms and $win) or $amd or $audio or ($sys1 and $sys2) or $self1 or $self2
}

rule Suspicious_API_Sequence {
    meta:
        description = "Detects suspicious API call patterns with sequence validation"
        severity = "medium"
        author = "Memory Forensics Tool"
        modified = "Optimized for false positive reduction"
    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "OpenProcess" ascii wide
        $api5 = "GetProcAddress" ascii wide
    condition:
        all of ($api1, $api2, $api3) and 
        (1 of ($api4, $api5)) and 
        not Whitelisted_System_Process and 
        not pe.is_dll() and 
        pe.imphash() != "00000000000000000000000000000000"
}

rule Code_Injection_Pattern {
    meta:
        description = "Common code injection indicators"
        severity = "high"
        author = "Memory Forensics Tool"
    strings:
        $inject1 = { 48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20 }
        $inject2 = { E8 [4] 48 8B D8 48 85 C0 74 }
        $ntapi = "NtCreateThreadEx" ascii
    condition:
        any of ($inject*) and $ntapi and not Whitelisted_System_Process and uint16(0) == 0x5A4D
}

rule Reflective_DLL_Loading {
    meta:
        description = "Reflective DLL injection pattern"
        severity = "critical"
        author = "Memory Forensics Tool"
    strings:
        $rdi2 = { 4C 8B DC 49 89 5B 08 49 89 6B 10 49 89 73 18 57 41 56 }
        $export = { 50 45 00 00 4C 01 }
    condition:
        (pe.exports("ReflectiveLoader") or $rdi2) and $export and not Whitelisted_System_Process
}

rule Shellcode_Indicators {
    meta:
        description = "Common shellcode patterns"
        severity = "high"
        author = "Memory Forensics Tool"
    strings:
        $shell1 = { 64 8B 05 30 00 00 00 }
        $shell2 = { 65 48 8B 04 25 60 00 00 00 }
        $shell3 = { FC 48 83 E4 F0 E8 }
    condition:
        any of them and not Whitelisted_System_Process
}

rule Encrypted_Payload {
    meta:
        description = "Encrypted or obfuscated payload"
        severity = "medium"
        author = "Memory Forensics Tool"
    strings:
        $xor_loop = { 30 ?? [1-3] 48 FF C? 48 3B }
        $crypto = "CryptDecrypt" ascii
    condition:
        any of them and not Whitelisted_System_Process
}

rule Keylogger_Behavior {
    meta:
        description = "Keylogger characteristic patterns with co-occurrence validation"
        severity = "high"
        author = "Memory Forensics Tool"
        modified = "Optimized for false positive reduction"
    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "GetForegroundWindow" ascii
        $api3 = "GetWindowText" ascii
        $api4 = "SetWindowsHookEx" ascii
        $api5 = "CallNextHookEx" ascii
    condition:
        (2 of ($api1, $api2, $api3)) and 
        (1 of ($api4, $api5)) and 
        not Whitelisted_System_Process and 
        not pe.is_dll()
}

rule Privilege_Escalation {
    meta:
        description = "Privilege escalation attempts"
        severity = "critical"
        author = "Memory Forensics Tool"
    strings:
        $token1 = "SeDebugPrivilege" ascii wide
        $token2 = "SeTcbPrivilege" ascii wide
        $api = "AdjustTokenPrivileges" ascii
    condition:
        $api and any of ($token*)
}

rule Network_Exfiltration {
    meta:
        description = "Data exfiltration indicators with contextual validation"
        severity = "high"
        author = "Memory Forensics Tool"
        modified = "Optimized for false positive reduction"
    strings:
        $wininet = "InternetReadFile" ascii
        $winsock = "WSASend" ascii
        $http_post = "POST" ascii
        $http_get = "GET" ascii
        $content_type = "Content-Type:" ascii
        $user_agent = "User-Agent:" ascii
        $encoding = "Content-Encoding:" ascii
    condition:
        (($wininet or $winsock) and 
         ($http_post or $http_get) and 
         (1 of ($content_type, $user_agent, $encoding))) and 
        not Whitelisted_System_Process and 
        not pe.is_dll()
}

rule Persistence_Mechanism {
    meta:
        description = "Registry-based persistence"
        severity = "medium"
        author = "Memory Forensics Tool"
    strings:
        $run = "\\CurrentVersion\\Run" ascii wide
        $runonce = "\\CurrentVersion\\RunOnce" ascii wide
        $service = "SYSTEM\\CurrentControlSet\\Services" ascii wide
    condition:
        any of them and not Whitelisted_System_Process
}

rule Anti_Analysis_Techniques {
    meta:
        description = "Anti-debugging and anti-VM techniques with category separation"
        severity = "medium"
        author = "Memory Forensics Tool"
        modified = "Optimized for false positive reduction"
    strings:
        $isdbg = "IsDebuggerPresent" ascii
        $checkremote = "CheckRemoteDebuggerPresent" ascii
        $ntquery = "NtQueryInformationProcess" ascii
        $vmware_string = "VMware" ascii wide nocase
        $vbox_string = "VirtualBox" ascii wide nocase
        $hyper_v = "Hyper-V" ascii wide nocase
        $evasion1 = "SetUnhandledExceptionFilter" ascii
        $evasion2 = "DebugBreak" ascii
    condition:
        ((2 of ($isdbg, $checkremote, $ntquery)) or 
         (1 of ($vmware_string, $vbox_string, $hyper_v))) and 
        (1 of ($evasion1, $evasion2)) and 
        not Whitelisted_System_Process and 
        not pe.is_dll()
}

rule WannaCry_Ransomware {
    meta:
        description = "Detects WannaCry Ransomware strings"
        severity = "critical"
        author = "Florian Roth (Signature-Base)"
    strings:
        $s1 = "tasksche.exe" ascii wide
        $s2 = "WanaCrypt0r" ascii wide
        $s3 = "msg/m_bulgarian.wnry" ascii
        $x1 = "icacls . /grant Everyone:F /T /C /Q" ascii
    condition:
        1 of ($s*) or $x1
}

rule Emotet_Banking_Trojan {
    meta:
        description = "Detects Emotet Banking Trojan with temporal validation"
        severity = "critical"
        author = "Research"
        modified = "Optimized for false positive reduction"
    strings:
        $s1 = "Cookie: %s=%s" ascii
        $s2 = "Content-Type: application/x-www-form-urlencoded" ascii
        $s3_old = "User-Agent: Mozilla/4.0 (compatible; MSIE 7.0" ascii
        $s3_alt = "User-Agent: Mozilla/" ascii
        $network = "WinINet" ascii wide
        $crypto = "CryptEncrypt" ascii
        $ip = /[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{2,5}/
    condition:
        ($s1 and $s2) and 
        (($s3_old) or ($s3_alt and $network and $crypto)) and 
        $ip and 
        not Whitelisted_System_Process and 
        not pe.is_dll() and 
        filesize > 100KB
}

rule Mimikatz_Credential_Dumper {
    meta:
        description = "Detects Mimikatz credential dumping tool"
        severity = "critical"
        author = "Benjamin Delpy (gentilkiwi)"
    strings:
        $s1 = "sekurlsa::logonpasswords" ascii wide nocase
        $s2 = "lsadump::lsa" ascii wide nocase
        $s3 = "privilege::debug" ascii wide nocase
        $s4 = "crypto::certificates" ascii wide nocase
    condition:
        1 of them
}

rule UPX_Packer {
    meta:
        description = "Detects UPX packed executables (often used by malware)"
        severity = "medium"
        author = "YARA-Rules"
    strings:
        $s1 = "UPX0" ascii
        $s2 = "UPX1" ascii
        $s3 = "UPX!" ascii
    condition:
        all of them
}

rule AsyncRAT_Client {
    meta:
        description = "Detects AsyncRAT Client"
        severity = "high"
        author = "Community"
    strings:
        $s1 = "AsyncClient" ascii wide
        $s2 = "Pastebin" ascii wide
        $s3 = "Pong" ascii wide
        $s4 = "Stub.exe" ascii wide
    condition:
        3 of them
}

rule LockBit_Ransomware {
    meta:
        description = "Detects LockBit Ransomware artifacts"
        severity = "critical"
        author = "Research"
    strings:
        $s1 = "LockBit 3.0" ascii wide
        $s2 = "restore-my-files.txt" ascii wide
        $s3 = ".lockbit" ascii wide
        $cmd1 = "vssadmin remove shadows" ascii wide
        $cmd2 = "bcdedit /set {default} recoveryenabled No" ascii wide
    condition:
        any of ($s*) or all of ($cmd*)
}

rule Conti_Ransomware {
    meta:
        description = "Detects Conti Ransomware artifacts"
        severity = "critical"
        author = "Research"
    strings:
        $s1 = "CONTI_LOG.txt" ascii wide
        $s2 = "expand 32-byte k" ascii
        $s3 = "Win32_ShadowCopy" ascii wide
        $ext = ".chk" ascii wide
        $note = "readme.txt" ascii wide
    condition:
        3 of them
}

rule Ryuk_Ransomware {
    meta:
        description = "Detects Ryuk Ransomware artifacts"
        severity = "critical"
        author = "Research"
    strings:
        $s1 = "RyukReadMe.txt" ascii wide
        $s2 = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide
        $s3 = "balance_shadow_copy" ascii wide
        $s4 = "HERMES" ascii wide
    condition:
        2 of them
}

rule Sodinokibi_REvil {
    meta:
        description = "Detects Sodinokibi/REvil Ransomware"
        severity = "critical"
        author = "Research"
    strings:
        $s1 = "Sodinokibi" ascii wide
        $s2 = "test.txt;nope.txt;check.txt" ascii wide
        $config = "\"pid\":\"" ascii
        $note = "-readme.txt" ascii wide
    condition:
        any of ($s*) or ($config and $note)
}