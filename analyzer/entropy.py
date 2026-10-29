"""Shannon Entropy Analysis for FileGuard.
Measures the randomness/information density of file byte distributions.
High entropy (>7.2) is a strong static indicator of packing, encryption, or obfuscation.
"""

import math
from collections import Counter

def calculate_shannon_entropy(data: bytes) -> float:
    """Calculate the Shannon Entropy of a byte sequence.
    Range: 0.0 (uniform/identical bytes) to 8.0 (completely random/encrypted).
    
    Args:
        data: Raw byte array of file contents.
        
    Returns:
        float representing entropy between 0.0 and 8.0.
    """
    if not data:
        return 0.0
    
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    
    for count in counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
            
    return round(entropy, 4)

def analyze_entropy_chunks(data: bytes, num_chunks: int = 16) -> list:
    """Divide file data into discrete chunks and calculate entropy per chunk.
    This reveals entropy spikes (e.g., hidden encrypted payloads inside standard binaries).
    
    Args:
        data: Raw byte array.
        num_chunks: Number of segments to inspect (default 16).
        
    Returns:
        List of dicts with chunk index, start_pct, end_pct, and entropy score.
    """
    if not data or len(data) < num_chunks:
        overall = calculate_shannon_entropy(data)
        return [{'chunk': 1, 'start_pct': 0, 'end_pct': 100, 'entropy': overall}]
    
    chunk_size = len(data) // num_chunks
    chunks_results = []
    
    for i in range(num_chunks):
        start = i * chunk_size
        # Last chunk gets any remaining bytes
        end = len(data) if i == num_chunks - 1 else (i + 1) * chunk_size
        chunk_bytes = data[start:end]
        
        chunk_entropy = calculate_shannon_entropy(chunk_bytes)
        chunks_results.append({
            'chunk': i + 1,
            'start_pct': round((start / len(data)) * 100),
            'end_pct': round((end / len(data)) * 100),
            'entropy': chunk_entropy
        })
        
    return chunks_results

def interpret_entropy(entropy: float) -> dict:
    """Provide a human-readable security assessment of the calculated entropy.
    
    Args:
        entropy: Float value from 0.0 to 8.0.
        
    Returns:
        dict with rating, description, and risk assessment.
    """
    if entropy < 3.0:
        return {
            'level': 'Very Low',
            'badge': 'info',
            'description': 'Very repetitive, sparse, or plain ASCII data. Low variance.',
            'risk': 'None',
            'score_impact': 0
        }
    elif entropy < 5.5:
        return {
            'level': 'Moderate / Normal',
            'badge': 'safe',
            'description': 'Typical for structured plain text, source code, JSON, logs, or uncompressed documents.',
            'risk': 'Low',
            'score_impact': 0
        }
    elif entropy < 6.8:
        return {
            'level': 'Standard Binary',
            'badge': 'normal',
            'description': 'Typical for compiled executable code, media files, or formatted office documents.',
            'risk': 'Low',
            'score_impact': 5
        }
    elif entropy < 7.4:
        return {
            'level': 'High (Compressed / Packed)',
            'badge': 'warning',
            'description': 'High randomness. Common in compressed archives (ZIP, RAR) or software packers (e.g., UPX).',
            'risk': 'Medium',
            'score_impact': 15
        }
    else:
        return {
            'level': 'Extremely High (Likely Encrypted / Obfuscated)',
            'badge': 'critical',
            'description': 'Near maximum randomness (>7.4). Frequent in encrypted ransomware payloads, obfuscated droppers, or encrypted containers.',
            'risk': 'High',
            'score_impact': 25
        }
