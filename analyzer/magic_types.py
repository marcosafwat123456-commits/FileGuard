"""Pure Python file magic header inspection.
Identifies true file types based on initial byte signatures without external dependencies.
"""

# Mapping of file magic signatures
# Tuple: (byte_prefix, offset, file_type_name, mime_type, expected_extensions)
SIGNATURES = [
    # Executables & Binaries
    (b'MZ', 0, 'Windows PE Executable / DLL', 'application/x-dosexec', ['.exe', '.dll', '.sys', '.scr', '.cpl', '.ocx']),
    (b'\x7fELF', 0, 'Linux ELF Binary', 'application/x-executable', ['.elf', '.so', '.bin', '']),
    (b'\xfe\xed\xfa\xce', 0, 'Mach-O Binary (32-bit)', 'application/x-mach-binary', ['.dylib', '']),
    (b'\xfe\xed\xfa\xcf', 0, 'Mach-O Binary (64-bit)', 'application/x-mach-binary', ['.dylib', '']),
    (b'\xce\xfa\xed\xfe', 0, 'Mach-O Binary (Reverse 32-bit)', 'application/x-mach-binary', ['.dylib', '']),
    (b'\xcf\xfa\xed\xfe', 0, 'Mach-O Binary (Reverse 64-bit)', 'application/x-mach-binary', ['.dylib', '']),
    (b'\xca\xfe\xba\xbe', 0, 'Java Class File / Mach-O Fat', 'application/java-vm', ['.class']),
    
    # Archives & Compressed Containers
    (b'PK\x03\x04', 0, 'ZIP Archive / Office OpenXML', 'application/zip', ['.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk']),
    (b'PK\x05\x06', 0, 'Empty ZIP Archive', 'application/zip', ['.zip']),
    (b'PK\x07\x08', 0, 'Spanned ZIP Archive', 'application/zip', ['.zip']),
    (b'Rar!\x1a\x07\x00', 0, 'RAR Archive (v4)', 'application/x-rar-compressed', ['.rar']),
    (b'Rar!\x1a\x07\x01\x00', 0, 'RAR Archive (v5)', 'application/x-rar-compressed', ['.rar']),
    (b'7z\xbc\xaf\x27\x1c', 0, '7-Zip Archive', 'application/x-7z-compressed', ['.7z']),
    (b'\x1f\x8b', 0, 'GZIP Compressed Data', 'application/gzip', ['.gz', '.tgz']),
    (b'BZh', 0, 'BZIP2 Compressed Data', 'application/x-bzip2', ['.bz2']),
    (b'\xfd7zXZ\x00', 0, 'XZ Compressed Data', 'application/x-xz', ['.xz']),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, 'Legacy Microsoft OLE Compound Document', 'application/x-ole-storage', ['.doc', '.xls', '.ppt', '.msi']),
    
    # Documents
    (b'%PDF-', 0, 'PDF Document', 'application/pdf', ['.pdf']),
    (b'{\\rtf', 0, 'Rich Text Format (RTF)', 'application/rtf', ['.rtf']),
    
    # Images
    (b'\x89PNG\r\n\x1a\n', 0, 'PNG Image', 'image/png', ['.png']),
    (b'\xff\xd8\xff', 0, 'JPEG Image', 'image/jpeg', ['.jpg', '.jpeg']),
    (b'GIF87a', 0, 'GIF Image (87a)', 'image/gif', ['.gif']),
    (b'GIF89a', 0, 'GIF Image (89a)', 'image/gif', ['.gif']),
    (b'BM', 0, 'BMP Image', 'image/bmp', ['.bmp']),
    (b'RIFF', 0, 'RIFF Multimedia Container', 'application/octet-stream', ['.webp', '.wav', '.avi']),
    
    # System & Other
    (b'\x4c\x00\x00\x00\x01\x14\x02\x00', 0, 'Windows Shell Link Shortcut', 'application/x-ms-shortcut', ['.lnk']),
]

def detect_file_type(raw_bytes: bytes, filename: str = "") -> dict:
    """Analyze file byte header to identify the true file type and potential spoofing.
    
    Args:
        raw_bytes: Initial bytes of the file (at least 512 bytes recommended)
        filename: Original filename to check extension compatibility
        
    Returns:
        dict with detected_type, mime_type, is_executable, is_archive, and confidence
    """
    if not raw_bytes:
        return {
            'type_name': 'Empty File',
            'mime_type': 'inode/x-empty',
            'is_executable': False,
            'is_archive': False,
            'confidence': 'High',
            'expected_extensions': []
        }
    
    header = raw_bytes[:64]
    
    # Check binary signatures
    for sig, offset, type_name, mime_type, expected_exts in SIGNATURES:
        if len(header) >= offset + len(sig):
            if header[offset:offset + len(sig)] == sig:
                # Specific refinement for RIFF formats
                if sig == b'RIFF' and len(raw_bytes) >= 12:
                    sub_sig = raw_bytes[8:12]
                    if sub_sig == b'WEBP':
                        return {
                            'type_name': 'WebP Image',
                            'mime_type': 'image/webp',
                            'is_executable': False,
                            'is_archive': False,
                            'confidence': 'High',
                            'expected_extensions': ['.webp']
                        }
                    elif sub_sig == b'WAVE':
                        return {
                            'type_name': 'WAV Audio',
                            'mime_type': 'audio/wav',
                            'is_executable': False,
                            'is_archive': False,
                            'confidence': 'High',
                            'expected_extensions': ['.wav']
                        }
                
                # Office OpenXML check within ZIP
                if sig == b'PK\x03\x04':
                    # Look ahead in header/first chunk for Office keywords
                    first_4k = raw_bytes[:4096]
                    if b'word/' in first_4k or b'[Content_Types].xml' in first_4k:
                        if b'word/' in first_4k:
                            type_name = 'Microsoft Word OpenXML Document'
                            mime_type = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                            expected_exts = ['.docx', '.docm']
                        elif b'xl/' in first_4k:
                            type_name = 'Microsoft Excel OpenXML Spreadsheet'
                            mime_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                            expected_exts = ['.xlsx', '.xlsm']
                        elif b'ppt/' in first_4k:
                            type_name = 'Microsoft PowerPoint Presentation'
                            mime_type = 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
                            expected_exts = ['.pptx', '.pptm']

                is_exec = (
                    'Executable' in type_name or 
                    'Mach-O' in type_name or 
                    'ELF' in type_name or 
                    mime_type.startswith('application/x-dosexec')
                )
                
                is_arch = (
                    'Archive' in type_name or 
                    mime_type in ['application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed', 'application/gzip']
                )

                return {
                    'type_name': type_name,
                    'mime_type': mime_type,
                    'is_executable': is_exec,
                    'is_archive': is_arch,
                    'confidence': 'High',
                    'expected_extensions': expected_exts
                }

    # Text / Script detection heuristics
    first_chunk = raw_bytes[:1024]
    
    # Shell script with shebang
    if first_chunk.startswith(b'#!/'):
        return {
            'type_name': 'POSIX Shell Script',
            'mime_type': 'text/x-shellscript',
            'is_executable': True,
            'is_archive': False,
            'confidence': 'High',
            'expected_extensions': ['.sh', '.bash', '']
        }
    
    # HTML / XML text
    stripped_chunk = first_chunk.lstrip()
    if stripped_chunk.startswith(b'<!DOCTYPE html') or stripped_chunk.startswith(b'<html') or stripped_chunk.startswith(b'<HTML'):
        return {
            'type_name': 'HTML Hypertext Document',
            'mime_type': 'text/html',
            'is_executable': False,
            'is_archive': False,
            'confidence': 'Medium',
            'expected_extensions': ['.html', '.htm']
        }
    
    if stripped_chunk.startswith(b'<?xml'):
        return {
            'type_name': 'XML Document',
            'mime_type': 'text/xml',
            'is_executable': False,
            'is_archive': False,
            'confidence': 'Medium',
            'expected_extensions': ['.xml']
        }
        
    if stripped_chunk.startswith(b'@echo off') or stripped_chunk.startswith(b'@ECHO OFF'):
        return {
            'type_name': 'Windows Batch Script',
            'mime_type': 'text/x-batch',
            'is_executable': True,
            'is_archive': False,
            'confidence': 'High',
            'expected_extensions': ['.bat', '.cmd']
        }

    # Check if mostly readable ASCII/UTF-8 text
    printable_count = sum(1 for b in first_chunk if 32 <= b <= 126 or b in (9, 10, 13))
    total_len = len(first_chunk)
    
    if total_len > 0 and (printable_count / total_len) > 0.88:
        return {
            'type_name': 'Plain Text Document / Script',
            'mime_type': 'text/plain',
            'is_executable': False,
            'is_archive': False,
            'confidence': 'Medium',
            'expected_extensions': ['.txt', '.py', '.js', '.json', '.csv', '.log', '.md', '.ps1']
        }

    # Fallback to binary octet stream
    return {
        'type_name': 'Binary Data Stream / Unrecognized Format',
        'mime_type': 'application/octet-stream',
        'is_executable': False,
        'is_archive': False,
        'confidence': 'Low',
        'expected_extensions': []
    }
