"""
Smart Cybersecurity Assistant - Configuration Module
Author: Your Name | GitHub: your-username
Description: Central configuration manager for all modules
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# ─── Base Paths ────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOGS_DIR = BASE_DIR / "logs"
MODELS_DIR = DATA_DIR / "ml_models"
YARA_RULES_DIR = DATA_DIR / "yara_rules"

# ─── API Keys ──────────────────────────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

# ─── Flask Configuration ───────────────────────────────────
class FlaskConfig:
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-in-production")
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() == "true"
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/cybersec_assistant.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

# ─── Voice Configuration ───────────────────────────────────
class VoiceConfig:
    DEFAULT_LANGUAGE = os.getenv("DEFAULT_LANGUAGE", "te")  # te = Telugu
    LANGUAGES = {
        "te": {
            "name": "Telugu",
            "native_name": "తెలుగు",
            "google_stt_code": "te-IN",
            "gtts_code": "te",
            "greetings": [
                "నమస్కారం! నేను మీ సైబర్ సెక్యూరిటీ సహాయకుడిని.",
                "సహాయం చేయడానికి నేను సిద్ధంగా ఉన్నాను.",
            ]
        },
        "en": {
            "name": "English",
            "native_name": "English",
            "google_stt_code": "en-US",
            "gtts_code": "en",
            "greetings": [
                "Hello! I am your Smart Cybersecurity Assistant.",
                "Ready to help you with security analysis.",
            ]
        }
    }
    VOICE_TIMEOUT = 5        # seconds to wait for speech
    PHRASE_TIMEOUT = 10      # max phrase duration
    ENERGY_THRESHOLD = 4000  # mic sensitivity

# ─── Threat Detection Configuration ───────────────────────
class ThreatConfig:
    # Port scan thresholds
    SUSPICIOUS_PORT_SCAN_THRESHOLD = 20   # ports scanned per second
    SUSPICIOUS_FAILED_LOGINS = 5          # failed logins before alert
    SUSPICIOUS_OUTBOUND_BYTES = 10_000_000  # 10MB sudden outbound

    # Known malicious ports
    MALICIOUS_PORTS = {
        4444: "Metasploit default shell",
        1337: "Common backdoor port",
        31337: "Elite backdoor",
        12345: "NetBus trojan",
        27374: "SubSeven trojan",
        65535: "Common C2 port",
    }

    # Severity levels
    SEVERITY = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }

    # MITRE ATT&CK tactics mapping
    MITRE_TACTICS = {
        "port_scan":          "T1046 - Network Service Discovery",
        "brute_force":        "T1110 - Brute Force",
        "data_exfiltration":  "T1041 - Exfiltration Over C2 Channel",
        "privilege_escalation": "T1548 - Abuse Elevation Control",
        "persistence":        "T1053 - Scheduled Task/Job",
    }

# ─── Log Analysis Configuration ───────────────────────────
class LogConfig:
    LINUX_LOG_PATHS = [
        "/var/log/auth.log",        # Authentication logs
        "/var/log/syslog",          # System log
        "/var/log/kern.log",        # Kernel log
        "/var/log/apache2/access.log",  # Apache
        "/var/log/nginx/access.log",    # Nginx
        "/var/log/ufw.log",         # Firewall
        "/var/log/fail2ban.log",    # Fail2ban
    ]

    # Regex patterns for log parsing
    PATTERNS = {
        "ssh_failed":     r"Failed password for .+ from (\d+\.\d+\.\d+\.\d+)",
        "sudo_command":   r"sudo:\s+(\w+)\s+:.+COMMAND=(.*)",
        "kernel_error":   r"kernel:\s+\[.+\]\s+(.*)",
        "new_process":    r"New session (\d+) of user (\w+)",
        "ip_address":     r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b",
    }

# ─── Linux Commands Database ──────────────────────────────
SAFE_COMMANDS_PREFIX = [
    "ls", "pwd", "whoami", "id", "uname", "uptime",
    "df", "du", "free", "ps", "top", "htop", "netstat",
    "ss", "ip", "ifconfig", "ping", "traceroute",
    "cat", "less", "head", "tail", "grep", "find",
    "nmap", "whois", "dig", "nslookup", "curl",
    "systemctl status", "journalctl",
]

DANGEROUS_COMMANDS = [
    "rm -rf /", "dd if=", "mkfs", "> /dev/sda",
    "chmod 777 /", ":(){ :|:& };:", "fork bomb",
]

print("✅ Configuration loaded successfully")