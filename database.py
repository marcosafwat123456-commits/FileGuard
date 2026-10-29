"""Database persistence layer for FileGuard using SQLite.
Stores scan history, reports, and threat telemetry locally.
Zero external database dependencies.
"""

import os
import sqlite3
import json
from config import Config

def get_db_connection():
    """Create and configure a SQLite connection."""
    os.makedirs(Config.DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database tables and indexes."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        filename TEXT NOT NULL,
        filesize INTEGER NOT NULL,
        extension TEXT,
        detected_type TEXT,
        mime_type TEXT,
        sha256 TEXT NOT NULL,
        md5 TEXT NOT NULL,
        sha1 TEXT NOT NULL,
        entropy REAL NOT NULL,
        risk_score INTEGER NOT NULL,
        verdict TEXT NOT NULL,
        findings_count INTEGER DEFAULT 0,
        report_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    """)
    
    # Create indexes for fast lookup
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_sha256 ON scans(sha256);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_scan_id ON scans(scan_id);")
    
    conn.commit()
    conn.close()

def save_scan(report: dict) -> bool:
    """Save an analysis report to the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    meta = report['file_metadata']
    hashes = report['hashes']
    entropy = report['entropy']
    analysis = report['analysis']
    
    try:
        cursor.execute("""
        INSERT INTO scans (
            scan_id, filename, filesize, extension, detected_type, mime_type,
            sha256, md5, sha1, entropy, risk_score, verdict, findings_count,
            report_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report['scan_id'],
            meta['filename'],
            meta['filesize'],
            meta['extension'],
            meta['detected_type'],
            meta['mime_type'],
            hashes['sha256'],
            hashes['md5'],
            hashes['sha1'],
            entropy['score'],
            analysis['risk_score'],
            analysis['verdict'],
            analysis['findings_count'],
            json.dumps(report),
            report['created_at']
        ))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Database error saving scan: {e}")
        return False
    finally:
        conn.close()

def get_all_scans(limit: int = 100, search: str = None) -> list:
    """Fetch scan history records with optional search filter."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
    SELECT id, scan_id, filename, filesize, extension, detected_type,
           sha256, entropy, risk_score, verdict, findings_count, created_at
    FROM scans
    """
    params = []
    
    if search:
        query += " WHERE filename LIKE ? OR sha256 LIKE ? OR verdict LIKE ? OR detected_type LIKE ?"
        term = f"%{search}%"
        params.extend([term, term, term, term])
        
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    scans = []
    for r in rows:
        scans.append(dict(r))
    return scans

def get_scan_by_id(scan_id: str) -> dict:
    """Fetch full scan report by unique scan_id or SHA-256."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    SELECT report_json FROM scans WHERE scan_id = ? OR sha256 = ? LIMIT 1
    """, (scan_id, scan_id))
    row = cursor.fetchone()
    conn.close()
    
    if row and row['report_json']:
        try:
            return json.loads(row['report_json'])
        except json.JSONDecodeError:
            return None
    return None

def delete_scan(scan_id: str) -> bool:
    """Delete a scan record by scan_id."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    conn.commit()
    rows_affected = cursor.rowcount
    conn.close()
    return rows_affected > 0

def clear_all_scans() -> bool:
    """Clear all scan records from database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    conn.commit()
    conn.close()
    return True

def get_dashboard_stats() -> dict:
    """Aggregate threat telemetry for the dashboard overview."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Total scans
    cursor.execute("SELECT COUNT(*) AS total FROM scans")
    total_scans = cursor.fetchone()['total']
    
    if total_scans == 0:
        conn.close()
        return {
            'total_scans': 0,
            'clean_scans': 0,
            'suspicious_scans': 0,
            'high_risk_scans': 0,
            'avg_entropy': 0.0,
            'recent_scans': [],
            'verdict_distribution': {'Clean': 0, 'Low Risk': 0, 'Suspicious': 0, 'High Risk': 0},
            'type_distribution': []
        }
        
    # Verdict counts
    cursor.execute("""
    SELECT verdict, COUNT(*) as count 
    FROM scans 
    GROUP BY verdict
    """)
    verdict_rows = cursor.fetchall()
    verdict_dist = {'Clean': 0, 'Low Risk': 0, 'Suspicious': 0, 'High Risk': 0}
    for r in verdict_rows:
        verdict_dist[r['verdict']] = r['count']
        
    clean_count = verdict_dist.get('Clean', 0) + verdict_dist.get('Low Risk', 0)
    suspicious_count = verdict_dist.get('Suspicious', 0)
    high_risk_count = verdict_dist.get('High Risk', 0)
    
    # Average entropy
    cursor.execute("SELECT AVG(entropy) AS avg_ent FROM scans")
    avg_entropy = round(cursor.fetchone()['avg_ent'] or 0.0, 2)
    
    # Type distribution
    cursor.execute("""
    SELECT detected_type, COUNT(*) as count 
    FROM scans 
    GROUP BY detected_type 
    ORDER BY count DESC 
    LIMIT 5
    """)
    type_dist = [dict(r) for r in cursor.fetchall()]
    
    # Recent 5 scans
    cursor.execute("""
    SELECT scan_id, filename, filesize, extension, detected_type, sha256, risk_score, verdict, created_at
    FROM scans 
    ORDER BY id DESC 
    LIMIT 5
    """)
    recent = [dict(r) for r in cursor.fetchall()]
    
    conn.close()
    
    return {
        'total_scans': total_scans,
        'clean_scans': clean_count,
        'suspicious_scans': suspicious_count,
        'high_risk_scans': high_risk_count,
        'avg_entropy': avg_entropy,
        'recent_scans': recent,
        'verdict_distribution': verdict_dist,
        'type_distribution': type_dist
    }
