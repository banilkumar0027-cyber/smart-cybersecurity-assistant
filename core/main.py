"""
Smart Cybersecurity Assistant - Main Orchestrator
Entry point for the entire system

Usage:
    python main.py                  # Start web dashboard (default)
    python main.py --voice          # Voice interaction mode
    python main.py --scan           # Run threat scan
    python main.py --analyze-logs   # Analyze system logs
    python main.py --ai             # AI chat mode
    python main.py --language te    # Telugu mode
"""

import sys
import signal
import argparse
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from loguru import logger
import socketio

import web

# Configure logging
logger.remove()
logger.add(
    "logs/app.log",
    rotation="10 MB",
    retention="7 days",
    level="INFO",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {module}:{line} | {message}",
)
logger.add(sys.stdout, level="WARNING", colorize=True)

console = Console()


def print_banner():
    """Display startup banner"""
    banner = Text()
    banner.append("╔══════════════════════════════════════════════════════╗\n", style="bold cyan")
    banner.append("║  🛡️  SMART CYBERSECURITY ASSISTANT  🛡️               ║\n", style="bold cyan")
    banner.append("║  AI-Powered | Telugu+English | Voice | Threat Detect  ║\n", style="cyan")
    banner.append("╚══════════════════════════════════════════════════════╝\n", style="bold cyan")
    banner.append("  Version: 1.0.0  |  Author: Your Name  |  Ethical Use Only\n", style="dim")
    console.print(banner)


def run_web_dashboard(host: str = "0.0.0.0", port: int = 5000):
    """Start the Flask web dashboard"""
    import sys
    from pathlib import Path
    core_path = Path(__file__).resolve().parent
    project_path = core_path.parent
    import sys
    if str(project_path) not in sys.path:
        sys.path.append(str(project_path))
    
    import web.socket_handlers as socketio_handlers
    app = web.create_app()
    console.print(Panel(
        f"🌐 [bold green]Dashboard starting...[/bold green]\n"
        f"URL: [link]http://localhost:{port}[/link]\n"
        f"Admin: http://localhost:{port}/dashboard",
        title="Web Server",
        border_style="green"
    ))
    socketio_handlers.socketio.run(app, host=host, port=port, debug=True, use_reloader=False)


def run_voice_mode(language: str = "te"):
    """Start voice interaction mode"""
    from voice_engine import VoiceEngine
    from ai_explainer import AIExplainer
    from threat_detector import ThreatDetector
    from linux_assistant import LinuxAssistant

    voice = VoiceEngine(language=language)
    ai = AIExplainer()
    detector = ThreatDetector()
    assistant = LinuxAssistant()

    voice.greet()
    
    console.print(Panel(
        f"🎤 [bold cyan]Voice Mode Active[/bold cyan]\n"
        f"Language: {voice.config['name']} ({voice.config['native_name']})\n"
        f"Commands: Say 'scan', 'logs', 'explain [topic]', 'switch language', 'help'\n"
        f"Press Ctrl+C to exit",
        border_style="cyan"
    ))

    while True:
        try:
            # Listen for command
            raw_text = voice.listen()
            if not raw_text:
                continue

            # Process bilingual input
            english_text, detected_lang = voice.process_bilingual_command(raw_text)

            # Route command
            response = process_voice_command(
                english_text, detected_lang, voice, ai, detector, assistant
            )

            # Respond in user's language
            if response:
                voice.speak(response, language=detected_lang)

        except KeyboardInterrupt:
            console.print("\n👋 [cyan]Voice mode ended. Stay secure![/cyan]")
            break


def process_voice_command(command: str, language: str,
                          voice, ai, detector, assistant) -> str:
    """Route voice command to appropriate handler"""
    cmd_lower = command.lower()

    if "scan" in cmd_lower or "threat" in cmd_lower:
        console.print("🔍 Running threat scan...")
        report = detector.full_system_scan()
        count = report["total_threats"]
        if language == "te":
            return f"స్కాన్ పూర్తయింది. {count} ముప్పులు కనుగొనబడ్డాయి. రిస్క్ స్థాయి: {report['risk_level']}"
        return f"Scan complete. Found {count} threats. Risk level: {report['risk_level']}"

    elif "log" in cmd_lower:
        from core.log_analyzer import LogAnalyzer
        analyzer = LogAnalyzer()
        result = analyzer.analyze_failed_logins()
        if language == "te":
            return f"లాగ్ విశ్లేషణ పూర్తయింది. {result.get('total_failures', 0)} విఫలమైన లాగిన్ ప్రయత్నాలు."
        return f"Log analysis done. {result.get('total_failures', 0)} failed login attempts detected."

    elif "explain" in cmd_lower or "what is" in cmd_lower:
        topic = command.replace("explain", "").replace("what is", "").strip()
        return ai.explain(f"Explain: {topic}", language=language)

    elif "switch" in cmd_lower and "language" in cmd_lower:
        new_lang = "en" if language == "te" else "te"
        voice.set_language(new_lang)
        if new_lang == "te":
            return "భాష తెలుగుకు మార్చబడింది"
        return "Language switched to English"

    elif "help" in cmd_lower:
        if language == "te":
            return ("అందుబాటులో ఉన్న ఆదేశాలు: స్కాన్, లాగ్ విశ్లేషణ, వివరించు, "
                   "భాష మార్చు. మీకు ఏమి కావాలి?")
        return ("Available commands: scan, analyze logs, explain [topic], "
               "switch language. What do you need?")

    else:
        # Default: ask AI
        return ai.explain(command, language=language)


def run_threat_scan():
    """Run a full system threat scan"""
    from core.threat_detector import ThreatDetector
    detector = ThreatDetector()
    report = detector.full_system_scan()
    
    import json
    output_path = f"logs/threat_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    Path(output_path).parent.mkdir(exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    console.print(f"✅ Report saved: [link]{output_path}[/link]")
    return report


def run_log_analysis():
    """Run log analysis"""
    from core.log_analyzer import LogAnalyzer
    analyzer = LogAnalyzer()
    report = analyzer.generate_security_report()
    
    console.print(Panel(
        f"📊 Security Report\n"
        f"Auth Events: {report['auth_events']}\n"
        f"Failed Logins: {report['failed_logins'].get('total_failures', 0)}\n"
        f"Web Attacks: {report['web_attacks']}\n"
        f"Risk Level: {report['overall_risk']}",
        border_style="cyan"
    ))
    return report


def setup_signal_handlers():
    """Setup graceful shutdown on Ctrl+C"""
    def signal_handler(sig, frame):
        console.print("\n\n👋 [bold cyan]Shutting down gracefully...[/bold cyan]")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Smart Cybersecurity Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                    Start web dashboard
  python main.py --voice            Voice mode (Telugu default)
  python main.py --voice --lang en  Voice mode (English)
  python main.py --scan             Run threat scan
  python main.py --logs             Analyze system logs
  python main.py --ai               AI chat mode
        """
    )

    parser.add_argument('--voice', action='store_true', help='Start voice mode')
    parser.add_argument('--scan', action='store_true', help='Run threat scan')
    parser.add_argument('--logs', action='store_true', help='Analyze logs')
    parser.add_argument('--ai', action='store_true', help='Start AI chat')
    parser.add_argument('--lang', choices=['te', 'en'], default='te',
                       help='Language (te=Telugu, en=English)')
    parser.add_argument('--host', default='0.0.0.0', help='Web server host')
    parser.add_argument('--port', type=int, default=5000, help='Web server port')

    args = parser.parse_args()

    print_banner()
    setup_signal_handlers()

    if args.voice:
        run_voice_mode(language=args.lang)
    elif args.scan:
        run_threat_scan()
    elif args.logs:
        run_log_analysis()
    elif args.ai:
        from core.ai_explainer import AIExplainer
        ai = AIExplainer()
        ai.interactive_qa(language=args.lang)
    else:
        # Default: start web dashboard
        run_web_dashboard(host=args.host, port=args.port)


if __name__ == "__main__":
    main()