"""Flask Routes for Smart Cybersecurity Assistant Dashboard"""

import json
from datetime import datetime
from flask import Blueprint, render_template, jsonify, request
from loguru import logger

from core.threat_detector import ThreatDetector
from core.log_analyzer import LogAnalyzer
from core.ai_explainer import AIExplainer
from core.linux_assistant import LinuxAssistant
from core.dashboard import SecurityDashboard

main_bp = Blueprint('main', __name__)

# Shared instances (in production, use dependency injection)
threat_detector = ThreatDetector()
log_analyzer = LogAnalyzer()
ai_explainer = AIExplainer()
linux_assistant = LinuxAssistant()
dashboard = SecurityDashboard()


@main_bp.route('/')
def index():
    """Home page - redirect to dashboard"""
    return render_template('dashboard.html',
                           page_title="Cybersecurity Dashboard",
                           current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


@main_bp.route('/dashboard')
def show_dashboard():
    """Main security dashboard"""
    return render_template('dashboard.html',
                           page_title="Security Dashboard")


@main_bp.route('/assistant')
def show_assistant():
    """Voice assistant page"""
    return render_template('assistant.html',
                           page_title="CyberGuard AI Assistant")


@main_bp.route('/logs')
def show_logs():
    """Log analysis page"""
    return render_template('logs.html',
                           page_title="Log Analyzer")


@main_bp.route('/threats')
def show_threats():
    """Threat management page"""
    return render_template('threats.html',
                           page_title="Threat Dashboard")


# ─── API Endpoints ─────────────────────────────────────────────────────────────

@main_bp.route('/api/scan', methods=['POST'])
def api_scan():
    """Run full system threat scan"""
    try:
        target = request.json.get('target', '127.0.0.1')
        port_range = request.json.get('port_range', '1-1024')
        
        results = threat_detector.scan_open_ports(target, port_range)
        return jsonify({
            "success": True,
            "ports": results,
            "count": len(results),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Scan API error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@main_bp.route('/api/threats', methods=['GET'])
def api_get_threats():
    """Get detected threats"""
    threats = [t.to_dict() for t in threat_detector.threats_detected[-50:]]
    return jsonify({
        "threats": threats,
        "count": len(threats),
        "timestamp": datetime.now().isoformat()
    })


@main_bp.route('/api/analyze-logs', methods=['POST'])
def api_analyze_logs():
    """Analyze system logs"""
    try:
        report = log_analyzer.generate_security_report()
        return jsonify({"success": True, "report": report})
    except Exception as e:
        logger.error(f"Log analysis API error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


@main_bp.route('/api/ai-explain', methods=['POST'])
def api_ai_explain():
    """Get AI explanation"""
    try:
        question = request.json.get('question', '')
        language = request.json.get('language', 'en')
        context = request.json.get('context', '')

        if not question:
            return jsonify({"error": "Question required"}), 400

        answer = ai_explainer.explain(question, language, context or None)
        return jsonify({
            "success": True,
            "answer": answer,
            "language": language,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@main_bp.route('/api/execute-command', methods=['POST'])
def api_execute_command():
    """Execute a Linux command (with safety checks)"""
    try:
        command = request.json.get('command', '')
        if not command:
            return jsonify({"error": "Command required"}), 400

        result = linux_assistant.execute_command(command, confirm=False)
        return jsonify({"success": True, "result": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@main_bp.route('/api/suggest-commands', methods=['POST'])
def api_suggest_commands():
    """Get command suggestions for a security task"""
    task = request.json.get('task', '')
    suggestions = linux_assistant.suggest_commands(task)
    return jsonify({"suggestions": suggestions})


@main_bp.route('/api/charts/threats', methods=['GET'])
def api_chart_threats():
    """Get threat timeline chart data"""
    threats = [t.to_dict() for t in threat_detector.threats_detected]
    chart_json = dashboard.create_threat_timeline(threats)
    return jsonify({"chart": chart_json})


@main_bp.route('/api/charts/severity', methods=['GET'])
def api_chart_severity():
    """Get severity distribution chart"""
    threats = threat_detector.threats_detected
    severity_counts = {}
    for t in threats:
        s = t.severity
        severity_counts[s] = severity_counts.get(s, 0) + 1

    chart_json = dashboard.create_threat_severity_pie(severity_counts)
    return jsonify({"chart": chart_json})


@main_bp.route('/api/system-status', methods=['GET'])
def api_system_status():
    """Get current system status"""
    import psutil
    return jsonify({
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent,
        "network_connections": len(psutil.net_connections()),
        "running_processes": len(psutil.pids()),
        "threat_count": len(threat_detector.threats_detected),
        "timestamp": datetime.now().isoformat(),
    })