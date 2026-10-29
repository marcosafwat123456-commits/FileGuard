"""FileGuard Core Analyzer.
Coordinates cryptographic hashing, byte magic inspection, Shannon entropy analysis,
and static heuristic rules.
Guaranteed safe: Analyzes raw bytes only and NEVER executes files.
"""

import os
import hashlib
import uuid
from datetime import datetime, timezone

from .magic_types import detect_file_type
from .entropy import calculate_shannon_entropy, analyze_entropy_chunks, interpret_entropy
from .heuristics import (
    check_filename_anomalies,
    check_extension_mismatch,
    scan_suspicious_patterns,
    inspect_archive_contents
)

class FileAnalyzer:
    """Static inspection and heuristic analysis coordinator."""
    
    @staticmethod
    def format_bytes(size: int) -> str:
        """Format raw byte size into human readable string."""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.2f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.2f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"

    @staticmethod
    def generate_hex_dump(data: bytes, length: int = 128) -> list:
        """Generate a clean hex and ASCII inspection view of the first N bytes."""
        slice_bytes = data[:length]
        rows = []
        
        for offset in range(0, len(slice_bytes), 16):
            chunk = slice_bytes[offset:offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            # Pad if less than 16 bytes
            if len(chunk) < 16:
                hex_part = hex_part.ljust(16 * 3 - 1)
                
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            rows.append({
                'offset': f"{offset:04X}",
                'hex': hex_part,
                'ascii': ascii_part
            })
            
        return rows

    @classmethod
    def analyze_bytes(cls, data: bytes, filename: str) -> dict:
        """Perform comprehensive static heuristic analysis on a byte stream.
        
        Args:
            data: Raw file byte stream.
            filename: Original file name.
            
        Returns:
            Complete analysis report dictionary.
        """
        scan_id = str(uuid.uuid4())
        created_at = datetime.now(timezone.utc).isoformat()
        filesize = len(data)
        _, ext = os.path.splitext(filename.lower())
        
        # 1. Cryptographic Hashes
        sha256_hash = hashlib.sha256(data).hexdigest()
        sha1_hash = hashlib.sha1(data).hexdigest()
        md5_hash = hashlib.md5(data).hexdigest()
        
        # 2. File Magic & Type Identification
        detected_type = detect_file_type(data[:4096], filename)
        
        # 3. Shannon Entropy Analysis
        entropy_val = calculate_shannon_entropy(data)
        entropy_info = interpret_entropy(entropy_val)
        entropy_chunks = analyze_entropy_chunks(data, num_chunks=16)
        
        # 4. Heuristic Rule Evaluations
        findings = []
        
        # Rule Check A: Filename anomalies (RTLO, double extension, null bytes)
        findings.extend(check_filename_anomalies(filename))
        
        # Rule Check B: Extension vs Magic mismatch
        findings.extend(check_extension_mismatch(filename, detected_type))
        
        # Rule Check C: Entropy check as a heuristic finding
        if entropy_info['score_impact'] > 0:
            findings.append({
                'rule_id': 'RULE-ENTROPY-01',
                'title': f"Elevated Shannon Entropy ({entropy_val:.2f} / 8.00)",
                'severity': 'HIGH' if entropy_val >= 7.4 else 'MEDIUM',
                'weight': entropy_info['score_impact'],
                'category': 'Byte Randomness',
                'explanation': f"{entropy_info['description']} High byte randomness suggests binary packing, compression, or cryptographic obfuscation used to conceal malicious payload logic."
            })
            
        # Rule Check D: Suspicious strings, shell patterns, LotL commands
        findings.extend(scan_suspicious_patterns(data))
        
        # Rule Check E: Archive container inspection
        findings.extend(inspect_archive_contents(data, detected_type))
        
        # 5. Risk Scoring & Threat Calculation
        total_weight = sum(f.get('weight', 10) for f in findings)
        
        # Check if critical rule was triggered
        has_critical = any(f.get('severity') == 'CRITICAL' for f in findings)
        has_high = any(f.get('severity') == 'HIGH' for f in findings)
        
        if has_critical:
            risk_score = max(75, min(100, total_weight))
        elif has_high:
            risk_score = max(50, min(100, total_weight))
        else:
            risk_score = min(100, total_weight)
            
        # Determine Verdict
        if risk_score == 0:
            verdict = "Clean"
            verdict_badge = "success"
            summary_message = "No suspicious characteristics or anomalous patterns detected in static triage."
        elif risk_score <= 25:
            verdict = "Low Risk"
            verdict_badge = "info"
            summary_message = "Standard file characteristics observed. Minor informational flags present."
        elif risk_score <= 55:
            verdict = "Suspicious"
            verdict_badge = "warning"
            summary_message = "Suspicious attributes or script commands identified. Exercise caution and verify source."
        else:
            verdict = "High Risk"
            verdict_badge = "danger"
            summary_message = "Multiple severe threat indicators detected (e.g., spoofed extension, high entropy, or malicious command patterns)."

        # 6. Hex dump preview
        hex_dump = cls.generate_hex_dump(data, length=128)
        
        return {
            'scan_id': scan_id,
            'created_at': created_at,
            'file_metadata': {
                'filename': filename,
                'filesize': filesize,
                'filesize_formatted': cls.format_bytes(filesize),
                'extension': ext if ext else '(none)',
                'detected_type': detected_type['type_name'],
                'mime_type': detected_type['mime_type'],
                'is_executable': detected_type['is_executable'],
                'is_archive': detected_type['is_archive'],
                'confidence': detected_type['confidence']
            },
            'hashes': {
                'sha256': sha256_hash,
                'sha1': sha1_hash,
                'md5': md5_hash
            },
            'entropy': {
                'score': entropy_val,
                'level': entropy_info['level'],
                'description': entropy_info['description'],
                'risk': entropy_info['risk'],
                'chunks': entropy_chunks
            },
            'analysis': {
                'risk_score': risk_score,
                'verdict': verdict,
                'verdict_badge': verdict_badge,
                'summary': summary_message,
                'findings_count': len(findings),
                'findings': findings
            },
            'hex_dump': hex_dump,
            'disclaimer': {
                'notice': 'FileGuard performs static byte-level heuristic triage without code execution.',
                'limitation': 'This analysis is educational and rule-based. It does not replace full endpoint antivirus or dynamic sandbox detonation, and cannot guarantee detection of all malware.'
            }
        }
