import os
import sys
import uuid
import json
import threading
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import (Flask, render_template, request,
                   jsonify, send_file)
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from config.settings import (FLASK_HOST, FLASK_PORT,
                              SECRET_KEY, REPORTS_DIR)
from modules.logger import (init_db, log, create_session,
                             get_all_sessions, get_findings,
                             get_logs, update_session_status)
from modules.osint       import OSINTModule
from modules.scanner     import ScannerModule
from modules.exploitation import ExploitationModule
from modules.wifi        import WiFiModule
from modules.ai          import AIModule

app     = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*",
                    async_mode='eventlet')

init_db()

# ── Helper: emit logs to frontend ────────────────────────────────
def emit_log(session_id, module, message, level="INFO"):
    log(session_id, module, message, level)
    socketio.emit('log', {
        "session_id": session_id,
        "module"    : module,
        "message"   : message,
        "level"     : level
    })

# ── Pages ─────────────────────────────────────────────────────────
@app.route('/')
def index():
    sessions = get_all_sessions()
    return render_template('index.html', sessions=sessions)

@app.route('/session/<session_id>')
def session_view(session_id):
    findings = get_findings(session_id)
    logs     = get_logs(session_id)
    return render_template('session.html',
                           session_id=session_id,
                           findings=findings,
                           logs=logs)

@app.route('/report/<session_id>')
def report_view(session_id):
    return render_template('report.html',
                           session_id=session_id)

# ── API: Create Session ───────────────────────────────────────────
@app.route('/api/session/create', methods=['POST'])
def api_create_session():
    data        = request.json
    session_id  = str(uuid.uuid4())[:8]
    create_session(
        session_id,
        data.get('name', 'Unnamed'),
        data.get('target'),
        data.get('target_type'),
        data.get('scope', 'full')
    )
    return jsonify({"session_id": session_id, "status": "created"})

# ── API: Run OSINT ────────────────────────────────────────────────
@app.route('/api/osint/<session_id>', methods=['POST'])
def api_osint(session_id):
    data   = request.json
    target = data.get('target')
    ttype  = data.get('target_type')

    def run():
        emit_log(session_id, "OSINT", f"Starting OSINT → {target}")
        osint   = OSINTModule(session_id)
        results = osint.run_full(target, ttype)
        socketio.emit('osint_complete', {
            "session_id": session_id,
            "results"   : results
        })
        emit_log(session_id, "OSINT", "OSINT complete")

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})

# ── API: Run Scanner ──────────────────────────────────────────────
@app.route('/api/scanner/<session_id>', methods=['POST'])
def api_scanner(session_id):
    data   = request.json
    target = data.get('target')
    ttype  = data.get('target_type')

    def run():
        emit_log(session_id, "SCANNER", f"Scanning → {target}")
        scanner = ScannerModule(session_id)
        results = scanner.run_full(target, ttype)
        socketio.emit('scan_complete', {
            "session_id": session_id,
            "results"   : results
        })
        emit_log(session_id, "SCANNER", "Scan complete")

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})

# ── API: Run Exploitation ─────────────────────────────────────────
@app.route('/api/exploit/<session_id>', methods=['POST'])
def api_exploit(session_id):
    data         = request.json
    target       = data.get('target')
    scan_results = data.get('scan_results', {})
    module_path  = data.get('module')
    options      = data.get('options', {})

    def run():
        emit_log(session_id, "EXPLOIT",
                 f"Exploitation → {target}", "WARNING")
        exp = ExploitationModule(session_id)
        if module_path:
            results = exp.run_exploit(target, module_path, options)
        else:
            results = exp.run_full(target, scan_results)
        socketio.emit('exploit_complete', {
            "session_id": session_id,
            "results"   : results
        })
        emit_log(session_id, "EXPLOIT", "Exploitation complete")

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})

# ── API: WiFi Scan ────────────────────────────────────────────────
@app.route('/api/wifi/<session_id>', methods=['POST'])
def api_wifi(session_id):
    data  = request.json
    iface = data.get('iface', 'wlan0')

    def run():
        emit_log(session_id, "WIFI", "WiFi scan started")
        wifi    = WiFiModule(session_id, iface)
        results = wifi.run_full(duration=20)
        socketio.emit('wifi_complete', {
            "session_id": session_id,
            "results"   : results
        })
        emit_log(session_id, "WIFI", "WiFi scan complete")

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})

# ── API: Generate AI Report ───────────────────────────────────────
@app.route('/api/report/<session_id>', methods=['POST'])
def api_report(session_id):
    def run():
        emit_log(session_id, "AI", "Generating report...")
        ai      = AIModule(session_id)
        path    = ai.generate_report()
        socketio.emit('report_complete', {
            "session_id": session_id,
            "file"      : path
        })
        emit_log(session_id, "AI", f"Report saved → {path}")

    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started"})

# ── API: Download Report ──────────────────────────────────────────
@app.route('/api/report/download/<session_id>')
def download_report(session_id):
    path = os.path.join(REPORTS_DIR, f"{session_id}.pdf")
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return jsonify({"error": "Report not found"}), 404

# ── API: Get Findings ─────────────────────────────────────────────
@app.route('/api/findings/<session_id>')
def api_findings(session_id):
    findings = get_findings(session_id)
    result   = []
    for f in findings:
        result.append({
            "id"          : f[0],
            "session_id"  : f[1],
            "timestamp"   : f[2],
            "module"      : f[3],
            "finding_type": f[4],
            "severity"    : f[5],
            "title"       : f[6],
            "description" : f[7],
            "data"        : json.loads(f[8]) if f[8] else {}
        })
    return jsonify(result)

# ── API: Get Logs ─────────────────────────────────────────────────
@app.route('/api/logs/<session_id>')
def api_logs(session_id):
    logs   = get_logs(session_id)
    result = [{"id": l[0], "session_id": l[1],
               "timestamp": l[2], "module": l[3],
               "level": l[4], "message": l[5]}
              for l in logs]
    return jsonify(result)

# ── API: Get Sessions ─────────────────────────────────────────────
@app.route('/api/sessions')
def api_sessions():
    sessions = get_all_sessions()
    result   = [{"id": s[0], "name": s[1], "target": s[2],
                 "target_type": s[3], "scope": s[4],
                 "status": s[5], "created_at": s[6]}
                for s in sessions]
    return jsonify(result)

if __name__ == '__main__':
    socketio.run(app, host=FLASK_HOST,
                 port=FLASK_PORT, debug=False)
