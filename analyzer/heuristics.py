"""Static Heuristic Rules Engine for FileGuard.
Evaluates file properties, structure, and static strings against known threat patterns.
All inspections are purely static byte scans without executing file code.
"""

import os
import re
import zipfile
import io

# Dangerous executable and script extensions
DANGEROUS_EXTENSIONS = {
    '.exe': 'Windows Executable Binary',
    '.dll': 'Windows Dynamic Link Library',
    '.scr': 'Windows Screensaver Executable (Often Malicious)',
    '.bat': 'Windows Batch Script',
    '.cmd': 'Windows Command Script',
    '.ps1': 'PowerShell Script',
    '.vbs': 'VBScript Script',
    '.vbe': 'Encoded VBScript',
    '.js': 'JavaScript Executable File',
    '.jse': 'Encoded JavaScript File',
    '.wsf': 'Windows Script File',
    '.hta': 'HTML Application Executable',
    '.msi': 'Windows Installer Package',
    '.msp': 'Windows Installer Patch',
    '.pif': 'Program Information File',
    '.com': 'DOS Application',
    '.cpl': 'Control Panel Item',
    '.jar': 'Java Executable Archive',
    '.sh': 'Unix/Linux Shell Script'
}

# Suspicious string patterns with weights, categories, and explanations
SUSPICIOUS_PATTERNS = [
    {
        'pattern': re.compile(rb'powershell(\.exe)?\s+(-[a-zA-Z0-9_-]+\s+)*(-enc|-encodedcommand)', re.IGNORECASE),
        'title': 'Base64 Encoded PowerShell Execution',
        'severity': 'HIGH',
        'weight': 35,
        'category': 'Living-off-the-Land (LotL)',
        'explanation': 'Encoded PowerShell execution is a common obfuscation technique used by droppers to conceal malicious scripts from command-line monitoring.'
    },
    {
        'pattern': re.compile(rb'powershell(\.exe)?\s+(-[a-zA-Z0-9_-]+\s+)*(-w(indowstyle)?\s+hidden|-nop|-noni|-ep\s+bypass)', re.IGNORECASE),
        'title': 'Stealth PowerShell Execution Flags',
        'severity': 'HIGH',
        'weight': 30,
        'category': 'Evasion',
        'explanation': 'Flags like -windowstyle hidden, -nop (NoProfile), or -ep bypass are used to silently launch processes without user visibility.'
    },
    {
        'pattern': re.compile(rb'vssadmin(\.exe)?\s+delete\s+shadows', re.IGNORECASE),
        'title': 'Volume Shadow Copy Deletion Command',
        'severity': 'CRITICAL',
        'weight': 50,
        'category': 'Ransomware Indicator',
        'explanation': 'Deleting volume shadow copies is a hallmark indicator of ransomware preventing recovery of encrypted files.'
    },
    {
        'pattern': re.compile(rb'certutil(\.exe)?\s+.*-(urlcache|decode|encode)', re.IGNORECASE),
        'title': 'Certutil Downloader / Decoder Pattern',
        'severity': 'HIGH',
        'weight': 30,
        'category': 'Living-off-the-Land (LotL)',
        'explanation': 'Certutil is a native Windows utility frequently abused by threat actors to download and decode malicious payloads.'
    },
    {
        'pattern': re.compile(rb'bitsadmin(\.exe)?\s+/transfer', re.IGNORECASE),
        'title': 'Bitsadmin Background File Download',
        'severity': 'HIGH',
        'weight': 25,
        'category': 'Living-off-the-Land (LotL)',
        'explanation': 'BITSadmin is abused to stealthily stage and download second-stage payloads in the background.'
    },
    {
        'pattern': re.compile(rb'wscript\.shell', re.IGNORECASE),
        'title': 'WScript.Shell Object Invocation',
        'severity': 'MEDIUM',
        'weight': 20,
        'category': 'Script Execution',
        'explanation': 'Commonly used in VBScript and JScript to execute external operating system commands or alter the Windows registry.'
    },
    {
        'pattern': re.compile(rb'cmd(\.exe)?\s+/[ck]', re.IGNORECASE),
        'title': 'Command Prompt Spawn Execution (/c or /k)',
        'severity': 'MEDIUM',
        'weight': 15,
        'category': 'Command Shell',
        'explanation': 'Spawns an interactive or hidden Command Prompt to execute chained system instructions.'
    },
    {
        'pattern': re.compile(rb'(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|QueueUserAPC)', re.IGNORECASE),
        'title': 'Process Injection Win32 API Indicators',
        'severity': 'HIGH',
        'weight': 35,
        'category': 'Process Injection',
        'explanation': 'References to memory allocation and remote thread creation APIs are typical in DLL injection, shellcode droppers, and process hollowing.'
    },
    {
        'pattern': re.compile(rb'FromBase64String\s*\(', re.IGNORECASE),
        'title': '.NET Base64 Decoding Routine',
        'severity': 'MEDIUM',
        'weight': 15,
        'category': 'Obfuscation',
        'explanation': 'Dynamically decodes base64-encoded binary data or commands in memory.'
    },
    {
        'pattern': re.compile(rb'eval\s*\(\s*(base64_decode|unescape|String\.fromCharCode)', re.IGNORECASE),
        'title': 'Obfuscated Dynamic Code Evaluation (eval)',
        'severity': 'HIGH',
        'weight': 30,
        'category': 'Code Obfuscation',
        'explanation': 'Evaluating decoded strings at runtime is a primary method for evading static string detection in scripts.'
    },
    {
        'pattern': re.compile(rb'https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{2,5})?', re.IGNORECASE),
        'title': 'Direct IP Address URL Reference',
        'severity': 'MEDIUM',
        'weight': 20,
        'category': 'Network Indicator',
        'explanation': 'Raw IP addresses (bypassing DNS domain resolution) are frequently associated with Command and Control (C2) servers or temporary drop points.'
    },
    {
        'pattern': re.compile(rb'[a-z0-9]{16,56}\.onion', re.IGNORECASE),
        'title': 'Tor Hidden Service (.onion) Reference',
        'severity': 'HIGH',
        'weight': 30,
        'category': 'Dark Web / Ransomware',
        'explanation': 'Onion links are predominantly found in ransomware extortion notes and dark web C2 communications.'
    },
    {
        'pattern': re.compile(rb'UPX[012]!?', re.IGNORECASE),
        'title': 'UPX Executable Packer Signatures',
        'severity': 'MEDIUM',
        'weight': 15,
        'category': 'Binary Packing',
        'explanation': 'UPX is a legitimate compression packer that compresses binaries, but is heavily abused by malware authors to hinder static reverse-engineering.'
    }
]

def check_filename_anomalies(filename: str) -> list:
    """Detect suspicious filename tricks such as RTLO or double extensions."""
    findings = []
    
    # Check 1: Right-to-Left Override (RTLO) Unicode character (U+202E)
    if '\u202e' in filename:
        findings.append({
            'rule_id': 'RULE-RTLO-01',
            'title': 'Right-to-Left Override (RTLO) Spoofing Detected',
            'severity': 'CRITICAL',
            'weight': 50,
            'category': 'Filename Deception',
            'explanation': 'The filename contains the Unicode RTLO character (\u202e), which forces text to render in reverse. This is an advanced trick used to disguise executable files (e.g., invoice[RTLO]exe.pdf).'
        })

    # Check 2: Null byte in filename
    if '\x00' in filename:
        findings.append({
            'rule_id': 'RULE-NULL-01',
            'title': 'Null Byte Injection in Filename',
            'severity': 'CRITICAL',
            'weight': 40,
            'category': 'Path Traversal / Bypass',
            'explanation': 'Filename contains embedded null bytes, a technique historically used to truncate filename extensions in vulnerable parsers.'
        })

    # Check 3: Double extension deception (e.g. document.pdf.exe)
    parts = filename.lower().split('.')
    if len(parts) >= 3:
        penultimate = '.' + parts[-2]
        final_ext = '.' + parts[-1]
        
        # If final extension is executable and penultimate is document or image
        decoy_extensions = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.png', '.txt', '.mp3', '.mp4'}
        if final_ext in DANGEROUS_EXTENSIONS and penultimate in decoy_extensions:
            findings.append({
                'rule_id': 'RULE-DOUBLE-EXT-01',
                'title': f'Camouflaged Double Extension ({penultimate}{final_ext})',
                'severity': 'HIGH',
                'weight': 45,
                'category': 'Filename Deception',
                'explanation': f'The file appears to masquerade as a {penultimate} document while actually having an executable {final_ext} extension. Exploits Windows default setting that hides file extensions.'
            })

    return findings

def check_extension_mismatch(filename: str, detected_type: dict) -> list:
    """Check if the filename extension mismatches the true magic byte signature."""
    findings = []
    _, ext = os.path.splitext(filename.lower())
    
    expected_exts = detected_type.get('expected_extensions', [])
    type_name = detected_type.get('type_name', '')
    is_exec = detected_type.get('is_executable', False)
    
    # If the file claims to be an image or document, but the byte header is a PE/ELF binary
    doc_or_media_exts = {'.pdf', '.jpg', '.jpeg', '.png', '.gif', '.txt', '.doc', '.docx', '.xls', '.xlsx', '.mp3', '.mp4'}
    if ext in doc_or_media_exts and is_exec:
        findings.append({
            'rule_id': 'RULE-SPOOF-01',
            'title': f'Critical Extension Mismatch: {ext} masquerading as {type_name}',
            'severity': 'CRITICAL',
            'weight': 50,
            'category': 'File Spoofing',
            'explanation': f'The file has a non-executable extension ({ext}) but its raw byte header confirms it is a compiled {type_name}. This is a critical indicator of disguised malware.'
        })
    elif expected_exts and ext and (ext not in expected_exts):
        # Mismatch between expected extensions and actual extension
        # Exclude benign zip derivatives like docx / jar if type is ZIP
        if not (type_name.startswith('ZIP') and ext in ['.docx', '.xlsx', '.pptx', '.jar', '.apk']):
            findings.append({
                'rule_id': 'RULE-MISMATCH-02',
                'title': f'File Extension Anomaly ({ext} vs {type_name})',
                'severity': 'LOW',
                'weight': 10,
                'category': 'Format Anomaly',
                'explanation': f'The file extension ({ext}) does not match the detected header signature ({type_name}). Could be a renamed file or corrupted format.'
            })

    # Direct dangerous extension check
    if ext in DANGEROUS_EXTENSIONS:
        findings.append({
            'rule_id': 'RULE-EXEC-EXT-01',
            'title': f'Executable / Script Format Detected ({ext})',
            'severity': 'MEDIUM',
            'weight': 20,
            'category': 'File Risk',
            'explanation': f'Files with the extension {ext} ({DANGEROUS_EXTENSIONS[ext]}) are directly interpretable or executable by the operating system and can run arbitrary code.'
        })

    return findings

def scan_suspicious_patterns(data: bytes) -> list:
    """Scan raw byte stream for suspicious strings, shell invocations, and IOC patterns."""
    findings = []
    
    # Limit deep regex scan to the first 4 MB for efficiency
    scan_slice = data[:4 * 1024 * 1024]
    
    for item in SUSPICIOUS_PATTERNS:
        matches = item['pattern'].findall(scan_slice)
        if matches:
            # Clean snippet for evidence
            evidence = []
            for m in matches[:3]: # limit to top 3 matches
                if isinstance(m, tuple):
                    match_str = m[0] if m[0] else (m[1] if len(m) > 1 else b'')
                else:
                    match_str = m
                try:
                    decoded = match_str.decode('ascii', errors='ignore')
                    if len(decoded) > 80:
                        decoded = decoded[:77] + '...'
                    if decoded.strip():
                        evidence.append(decoded.strip())
                except Exception:
                    pass
            
            findings.append({
                'rule_id': f"RULE-STR-{item['category'][:4].upper()}",
                'title': item['title'],
                'severity': item['severity'],
                'weight': item['weight'],
                'category': item['category'],
                'explanation': item['explanation'],
                'evidence': evidence if evidence else ['Pattern matched in file binary stream']
            })
            
    return findings

def inspect_archive_contents(data: bytes, detected_type: dict) -> list:
    """Safely inspect inside ZIP containers/Office documents for embedded executables or macros without extracting to disk."""
    findings = []
    
    if not (detected_type.get('is_archive') or 'ZIP' in detected_type.get('type_name', '') or 'Office' in detected_type.get('type_name', '')):
        return findings

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            namelist = zf.namelist()
            
            embedded_execs = []
            has_macro = False
            
            for name in namelist:
                lower = name.lower()
                _, sub_ext = os.path.splitext(lower)
                if sub_ext in DANGEROUS_EXTENSIONS:
                    embedded_execs.append(name)
                if 'vba' in lower or 'macros' in lower or lower.endswith('.bin') and 'vbaproject' in lower:
                    has_macro = True
                    
            if embedded_execs:
                findings.append({
                    'rule_id': 'RULE-ARCH-EXEC-01',
                    'title': 'Executable Files Embedded Inside Archive Container',
                    'severity': 'HIGH',
                    'weight': 35,
                    'category': 'Archive Payload',
                    'explanation': f'The archive contains embedded executable files ({", ".join(embedded_execs[:3])}). Frequently used in phishing campaigns to bypass perimeter email filters.',
                    'evidence': embedded_execs[:5]
                })
                
            if has_macro:
                findings.append({
                    'rule_id': 'RULE-MACRO-01',
                    'title': 'VBA Macro Code Detected in Document Archive',
                    'severity': 'HIGH',
                    'weight': 30,
                    'category': 'Macro Threat',
                    'explanation': 'Document contains internal VBA macro storage (vbaProject.bin). Malicious macros are commonly used to execute droppers or downloaders upon document launch.',
                    'evidence': ['Internal VBA Project / Macro stream identified']
                })
                
    except (zipfile.BadZipFile, Exception):
        # Ignore corrupt or non-standard ZIP structures safely
        pass
        
    return findings
