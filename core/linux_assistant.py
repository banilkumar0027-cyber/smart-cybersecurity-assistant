"""
Smart Cybersecurity Assistant - Linux Command Assistant
Provides safe execution, explanation, and guidance for Linux security commands
"""

import re
import json
import subprocess
import shlex
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from loguru import logger
from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel

from config import SAFE_COMMANDS_PREFIX, DANGEROUS_COMMANDS, DATA_DIR

console = Console()


# ─── Linux Security Command Database ──────────────────────────────────────────
COMMAND_DATABASE = {
    # Network Commands
    "nmap": {
        "description": "Network port scanner and service detection",
        "telugu_description": "నెట్‌వర్క్ పోర్ట్ స్కానర్ మరియు సేవా గుర్తింపు",
        "usage": "nmap [options] <target>",
        "examples": [
            "nmap -sV 192.168.1.1         # Version detection",
            "nmap -sS -T4 192.168.1.0/24  # Stealth SYN scan",
            "nmap -A -p- localhost         # Aggressive full scan",
            "nmap --script vuln 10.0.0.1  # Vulnerability scripts",
        ],
        "category": "network",
        "risk_level": "medium",
        "use_cases": ["port_discovery", "service_enumeration", "vulnerability_assessment"],
    },
    "netstat": {
        "description": "Network statistics and connection listing",
        "telugu_description": "నెట్‌వర్క్ స్టాటిస్టిక్స్ మరియు కనెక్షన్ జాబితా",
        "usage": "netstat [options]",
        "examples": [
            "netstat -tuln     # TCP/UDP listening ports",
            "netstat -an       # All connections",
            "netstat -p        # Show process info",
        ],
        "category": "network",
        "risk_level": "low",
    },
    "ss": {
        "description": "Socket statistics (modern netstat replacement)",
        "telugu_description": "సాకెట్ స్టాటిస్టిక్స్",
        "usage": "ss [options]",
        "examples": [
            "ss -tuln          # TCP/UDP listening",
            "ss -tp            # TCP connections with process",
            "ss -s             # Summary",
        ],
        "category": "network",
        "risk_level": "low",
    },
    # Security Commands
    "iptables": {
        "description": "Linux firewall rule management",
        "telugu_description": "లినక్స్ ఫైర్‌వాల్ నియంత్రణ",
        "usage": "iptables [options] chain rule",
        "examples": [
            "iptables -L -n -v              # List all rules",
            "iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # Allow SSH",
            "iptables -A INPUT -s 1.2.3.4 -j DROP          # Block IP",
        ],
        "category": "security",
        "risk_level": "high",
    },
    "ufw": {
        "description": "Uncomplicated Firewall - Simple iptables frontend",
        "telugu_description": "సరళమైన ఫైర్‌వాల్",
        "usage": "ufw [command]",
        "examples": [
            "ufw status verbose    # Check status",
            "ufw allow 22/tcp      # Allow SSH",
            "ufw deny 23           # Block telnet",
            "ufw enable            # Enable firewall",
        ],
        "category": "security",
        "risk_level": "medium",
    },
    # Forensics Commands
    "find": {
        "description": "Find files matching criteria (SUID/SGID for privilege escalation)",
        "telugu_description": "ఫైళ్లను వెతకడం",
        "usage": "find [path] [options]",
        "examples": [
            "find / -perm -4000 2>/dev/null   # Find SUID binaries",
            "find / -perm -2000 2>/dev/null   # Find SGID binaries",
            "find / -name '*.sh' -mtime -1    # Recently modified scripts",
        ],
        "category": "forensics",
        "risk_level": "low",
    },
    "lsof": {
        "description": "List open files and network connections",
        "telugu_description": "తెరిచిన ఫైళ్లు మరియు కనెక్షన్లు చూడడం",
        "usage": "lsof [options]",
        "examples": [
            "lsof -i :22         # Processes using port 22",
            "lsof -u root        # Files opened by root",
            "lsof -p <pid>       # Files opened by process",
        ],
        "category": "forensics",
        "risk_level": "low",
    },
    "ps": {
        "description": "Process status monitor",
        "telugu_description": "ప్రక్రియల స్థితి",
        "usage": "ps [options]",
        "examples": [
            "ps aux              # All processes",
            "ps aux --forest     # Process tree",
            "ps -eo pid,ppid,cmd,pcpu,pmem --sort=-pcpu | head -20",
        ],
        "category": "monitoring",
        "risk_level": "low",
    },
    "grep": {
        "description": "Search text using patterns (essential for log analysis)",
        "telugu_description": "వచనాన్ని వెతకడం",
        "usage": "grep [options] pattern [file]",
        "examples": [
            "grep 'Failed password' /var/log/auth.log",
            "grep -r 'error' /var/log/ --include='*.log'",
            "grep -E '(ERROR|CRITICAL)' app.log",
        ],
        "category": "analysis",
        "risk_level": "low",
    },
}


class CommandRiskChecker:
    """Check if a command is safe to execute"""

    @staticmethod
    def assess_risk(command: str) -> Tuple[str, str]:
        """
        Assess command risk level
        
        Returns:
            Tuple of (risk_level, reason)
            risk_level: 'safe', 'caution', 'dangerous', 'blocked'
        """
        cmd_lower = command.lower().strip()

        # Block dangerous commands
        for danger in DANGEROUS_COMMANDS:
            if danger in cmd_lower:
                return ("blocked",
                        f"BLOCKED: Command contains dangerous pattern '{danger}'")

        # Check for privilege escalation risks
        if re.search(r'\bsudo\b.*\bsu\b', cmd_lower):
            return ("dangerous", "Potential privilege escalation")

        if re.search(r'chmod\s+[0-7]*7[0-7][0-7]\s+/', cmd_lower):
            return ("dangerous", "Setting world-writable permissions on root path")

        if "passwd" in cmd_lower and "grep" not in cmd_lower:
            return ("caution", "Modifying passwords - confirm this is intentional")

        # Check if command starts with safe prefix
        for safe_prefix in SAFE_COMMANDS_PREFIX:
            if cmd_lower.startswith(safe_prefix):
                return ("safe", "Command is in safe whitelist")

        # Default: caution for unknown commands
        return ("caution", "Unknown command - review before executing")


class LinuxAssistant:
    """
    Linux Command Assistant for Security Operations
    
    Features:
    - Safe command execution with risk assessment
    - Command explanation (Telugu + English)
    - Security command guidance
    - Command history tracking
    - Output formatting
    """

    def __init__(self):
        self.command_db = COMMAND_DATABASE
        self.risk_checker = CommandRiskChecker()
        self.history: List[Dict] = []
        logger.info("💻 Linux Command Assistant initialized")

    def execute_command(self, command: str, confirm: bool = True) -> Dict:
        """
        Safely execute a shell command
        
        Args:
            command: Shell command to execute
            confirm: Require confirmation for caution-level commands
        
        Returns:
            Dict with stdout, stderr, returncode, and metadata
        """
        risk_level, risk_reason = self.risk_checker.assess_risk(command)

        result = {
            "command": command,
            "risk_level": risk_level,
            "risk_reason": risk_reason,
            "stdout": "",
            "stderr": "",
            "returncode": -1,
            "timestamp": datetime.now().isoformat(),
            "executed": False,
        }

        # Handle blocked commands
        if risk_level == "blocked":
            console.print(f"🚫 [bold red]BLOCKED: {risk_reason}[/bold red]")
            result["stderr"] = risk_reason
            return result

        # Display risk info
        risk_colors = {
            "safe": "green",
            "caution": "yellow",
            "dangerous": "red",
        }
        color = risk_colors.get(risk_level, "white")
        console.print(f"\n⚡ [bold {color}]Risk: {risk_level.upper()}[/bold {color}]")
        console.print(f"   Reason: {risk_reason}")

        # Execute command
        try:
            proc = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout
            )

            result["stdout"] = proc.stdout
            result["stderr"] = proc.stderr
            result["returncode"] = proc.returncode
            result["executed"] = True

            # Display output
            if proc.stdout:
                syntax = Syntax(proc.stdout[:2000], "bash", theme="monokai",
                               line_numbers=False)
                console.print(syntax)
            if proc.stderr:
                console.print(f"[red]STDERR:[/red] {proc.stderr[:500]}")

        except subprocess.TimeoutExpired:
            result["stderr"] = "Command timed out after 30 seconds"
            console.print("⏱️ [red]Command timed out[/red]")
        except Exception as e:
            result["stderr"] = str(e)
            console.print(f"❌ [red]Execution error: {e}[/red]")

        # Add to history
        self.history.append(result)
        return result

    def explain_command(self, command: str, language: str = "en") -> str:
        """
        Get detailed explanation of a Linux command
        
        Args:
            command: Command to explain
            language: 'en' for English, 'te' for Telugu
        
        Returns:
            Explanation string
        """
        # Extract base command
        base_cmd = command.split()[0] if command.split() else command

        if base_cmd in self.command_db:
            cmd_info = self.command_db[base_cmd]
            
            if language == "te":
                explanation = (
                    f"**{base_cmd}** - {cmd_info.get('telugu_description', cmd_info['description'])}\n\n"
                    f"వాడకం: `{cmd_info['usage']}`\n\n"
                    f"ఉదాహరణలు:\n"
                )
                for ex in cmd_info.get("examples", []):
                    explanation += f"  • {ex}\n"
            else:
                explanation = (
                    f"**{base_cmd}** - {cmd_info['description']}\n\n"
                    f"Usage: `{cmd_info['usage']}`\n\n"
                    f"Examples:\n"
                )
                for ex in cmd_info.get("examples", []):
                    explanation += f"  • {ex}\n"
                
                explanation += f"\nRisk Level: {cmd_info.get('risk_level', 'unknown').upper()}"
        else:
            # Generic explanation for unknown commands
            explanation = (
                f"Command `{base_cmd}` not in local database.\n"
                f"Use `man {base_cmd}` for manual page.\n"
                f"Use `{base_cmd} --help` for help."
            )

        return explanation

    def suggest_commands(self, task: str) -> List[str]:
        """
        Suggest Linux commands for a security task
        
        Args:
            task: Security task description
        
        Returns:
            List of suggested commands
        """
        task_lower = task.lower()
        suggestions = []

        # Keyword-based suggestions
        if any(w in task_lower for w in ["port", "scan", "network", "open"]):
            suggestions.extend([
                "nmap -sV -T4 <target>",
                "ss -tuln",
                "netstat -an | grep LISTEN",
            ])

        if any(w in task_lower for w in ["log", "auth", "login", "fail"]):
            suggestions.extend([
                "tail -f /var/log/auth.log",
                "grep 'Failed password' /var/log/auth.log | tail -50",
                "journalctl -u ssh --since '1 hour ago'",
            ])

        if any(w in task_lower for w in ["process", "cpu", "memory", "running"]):
            suggestions.extend([
                "ps aux --sort=-pcpu | head -20",
                "htop",
                "top -bn1",
            ])

        if any(w in task_lower for w in ["firewall", "block", "allow", "rule"]):
            suggestions.extend([
                "ufw status verbose",
                "iptables -L -n -v",
                "ufw allow 22/tcp",
            ])

        if any(w in task_lower for w in ["file", "suid", "permission", "privilege"]):
            suggestions.extend([
                "find / -perm -4000 2>/dev/null",
                "find / -writable -type f 2>/dev/null | head -20",
                "ls -la /etc/passwd /etc/shadow",
            ])

        return suggestions[:5]  # Return top 5

    def get_security_checklist(self) -> List[Dict]:
        """Get a Linux server security hardening checklist"""
        return [
            {
                "category": "SSH Hardening",
                "command": "grep -E '(PasswordAuthentication|PermitRootLogin|Port)' /etc/ssh/sshd_config",
                "description": "Check SSH configuration security settings",
                "expected": "PasswordAuthentication no, PermitRootLogin no",
            },
            {
                "category": "Open Ports",
                "command": "ss -tuln",
                "description": "List all listening ports",
                "expected": "Only necessary ports should be open",
            },
            {
                "category": "SUID Binaries",
                "command": "find / -perm -4000 -type f 2>/dev/null",
                "description": "Find SUID binaries (potential privilege escalation)",
                "expected": "Minimal SUID binaries",
            },
            {
                "category": "User Accounts",
                "command": "awk -F: '($3 == 0) {print}' /etc/passwd",
                "description": "Find UID 0 (root-level) accounts",
                "expected": "Only 'root' should have UID 0",
            },
            {
                "category": "Failed Logins",
                "command": "grep 'Failed password' /var/log/auth.log | wc -l",
                "description": "Count recent failed login attempts",
                "expected": "0 or very low count",
            },
            {
                "category": "Firewall Status",
                "command": "ufw status",
                "description": "Check if firewall is active",
                "expected": "Status: active",
            },
        ]