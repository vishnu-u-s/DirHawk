"""
server.py — Flask + SocketIO server for DirHawk UI mode
"""

import os
import json
import threading
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_socketio import SocketIO

from scanner.core import DirectoryScanner
from scanner.ai_analyzer import AIAnalyzer
from scanner.proxy import ProxyConfig

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.join(BASE_DIR, "results")
UI_DIR      = os.path.join(BASE_DIR, "ui")

app = Flask(__name__, static_folder=UI_DIR)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Globals (one active scanner + AI analyzer at a time) ──────────────────────
_scanner:     DirectoryScanner = None
_ai_analyzer: AIAnalyzer       = None
_scan_thread: threading.Thread = None


def make_callback():
    def cb(event, data):
        socketio.emit(event, data)
    return cb


# ── Static ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(UI_DIR, "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(UI_DIR, filename)


# ── POST /api/scan ─────────────────────────────────────────────────────────────
@app.route("/api/scan", methods=["POST"])
def api_scan():
    global _scanner, _ai_analyzer, _scan_thread

    data         = request.json or {}
    targets_raw  = data.get("targets", "")
    proxy_str    = data.get("proxy", "")
    mode         = data.get("mode", "normal")        # "normal" | "ai"
    ai_url       = data.get("ai_url", "")
    ai_key       = data.get("ai_key", "")
    ai_model     = data.get("ai_model", "")
    ai_scope     = data.get("ai_scope", "all")       # "all" | "sensitive"
    max_workers  = int(data.get("max_workers", 10))
    timeout      = int(data.get("timeout", 10))

    targets = [t.strip() for t in targets_raw.replace(",", "\n").splitlines() if t.strip()]
    if not targets:
        return jsonify({"error": "No targets provided"}), 400

    proxy    = ProxyConfig(proxy_str if proxy_str else None)
    callback = make_callback()

    _scanner = DirectoryScanner(
        proxy_config=proxy, timeout=timeout, max_workers=max_workers,
        callback=callback, results_dir=RESULTS_DIR,
    )

    def run_scan():
        global _ai_analyzer
        results = _scanner.scan_bulk(targets)

        # ── AI mode: analyze dirs one at a time ───────────────────────────────
        if mode == "ai" and ai_url and ai_key and ai_model:
            all_dirs = []
            for r in results:
                dirs = r.sensitive_dirs if ai_scope == "sensitive" else r.open_dirs
                all_dirs.extend(dirs)

            _ai_analyzer = AIAnalyzer(
                base_url=ai_url, api_key=ai_key, model=ai_model,
                proxies=proxy.get_proxies(), callback=callback,
            )
            _ai_analyzer.analyze_sequential(all_dirs)

        socketio.emit("scan_complete", {
            "total_targets":  len(targets),
            "total_open_dirs": sum(len(r.open_dirs)      for r in results),
            "total_sensitive": sum(len(r.sensitive_dirs)  for r in results),
            "total_403":       sum(len(r.found_403)       for r in results),
        })

    _scan_thread = threading.Thread(target=run_scan, daemon=True)
    _scan_thread.start()

    return jsonify({"status": "started", "targets": len(targets)})


# ── POST /api/stop ─────────────────────────────────────────────────────────────
@app.route("/api/stop", methods=["POST"])
def api_stop():
    if _scanner:
        _scanner.stop()
    return jsonify({"status": "stopping"})


# ── POST /api/ai-stop ──────────────────────────────────────────────────────────
@app.route("/api/ai-stop", methods=["POST"])
def api_ai_stop():
    global _ai_analyzer
    if _ai_analyzer:
        _ai_analyzer.stop()
    return jsonify({"status": "ai_stopping"})


# ── GET /api/results ───────────────────────────────────────────────────────────
@app.route("/api/results", methods=["GET"])
def api_results():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    files = sorted([f for f in os.listdir(RESULTS_DIR) if f.endswith(".json")], reverse=True)
    out = []
    for fname in files[:50]:
        try:
            with open(os.path.join(RESULTS_DIR, fname)) as f:
                d = json.load(f)
            out.append({
                "filename":      fname,
                "domain":        d.get("domain", ""),
                "started_at":    d.get("started_at", ""),
                "open_dirs":     len(d.get("open_dirs", [])),
                "sensitive_dirs":len(d.get("sensitive_dirs", [])),
                "found_403":     len(d.get("found_403", [])),
            })
        except Exception:
            pass
    return jsonify(out)


# ── GET /api/results/<filename> ────────────────────────────────────────────────
@app.route("/api/results/<filename>", methods=["GET"])
def api_result_detail(filename):
    path = os.path.join(RESULTS_DIR, filename)
    if not os.path.exists(path):
        return jsonify({"error": "Not found"}), 404
    with open(path) as f:
        return jsonify(json.load(f))


# ── DELETE /api/results/<filename> ─────────────────────────────────────────────
@app.route("/api/results/<filename>", methods=["DELETE"])
def api_result_delete(filename):
    path = os.path.join(RESULTS_DIR, filename)
    if not os.path.exists(path):
        return jsonify({"error": "Not found"}), 404
    os.remove(path)
    return jsonify({"status": "deleted", "filename": filename})


# ── POST /api/models ───────────────────────────────────────────────────────────
@app.route("/api/models", methods=["POST"])
def api_models():
    data    = request.json or {}
    ai_url  = data.get("ai_url", "")
    ai_key  = data.get("ai_key", "")
    proxy   = ProxyConfig(data.get("proxy", "") or None)
    if not ai_url or not ai_key:
        return jsonify({"error": "ai_url and ai_key required"}), 400
    analyzer = AIAnalyzer(base_url=ai_url, api_key=ai_key, proxies=proxy.get_proxies())
    return jsonify({"models": analyzer.list_models()})


# ── POST /api/test-proxy ────────────────────────────────────────────────────────
@app.route("/api/test-proxy", methods=["POST"])
def api_test_proxy():
    data      = request.json or {}
    proxy_str = data.get("proxy", "")
    if not proxy_str:
        return jsonify({"error": "proxy required"}), 400
    ok, msg = ProxyConfig.test_proxy(proxy_str)
    return jsonify({"success": ok, "message": msg})


if __name__ == "__main__":
    print("\n  🦅 DirHawk UI → http://localhost:5000\n")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
