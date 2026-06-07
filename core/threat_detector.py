"""
Smart Cybersecurity Assistant - Log Analysis Engine
Analyzes Linux system logs for security events
"""

import re
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
from collections import Counter, defaultdict

import pandas as pd
from loguru import logger
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from config import LogConfig

console = Console()


class LogEvent:
    """Represents a parsed log event"""

    def __init__(self, timestamp: datetime, level: str, source: str,
                 message: str, ip: str = None, user: str = None):
        self.timestamp = timestamp
        self.level = level
        self.source = source
        self.message = message
        self.ip = ip
        self.user = user

    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level,
            "source": self.source,
            "message": self.message,
            "ip": self.ip,
            "user": self.user,
        }


class LogAnalyzer:
    """
    Advanced Log Analysis Engine
    
    Capabilities:
    - Parse multiple Linux log formats
    - Detect suspicious patterns (brute force, privilege escalation)
    - Generate statistical reports
    - Create visualizable DataFrames
    - AI-ready data extraction
    """

    def __init__(self):
        self.events: List[LogEvent] = []
        self.df: Optional[pd.DataFrame] = None
        logger.info("📋 Log Analyzer initialized")

    # ─── Main Parsing Methods ──────────────────────────────────

    def parse_auth_log(self, log_path: str = "/var/log/auth.log",
                       max_lines: int = 50000) -> pd.DataFrame:
        """
        Parse /var/log/auth.log for authentication events
        
        Detects:
        - Failed SSH logins
        - Successful SSH logins
        - sudo commands
        - User additions/removals
        - PAM events
        """
        events = []

        try:
            with open(log_path, 'r', errors='ignore') as f:
                lines = f.readlines()[:max_lines]

            console.print(f"📂 Parsing {len(lines)} auth log lines...")

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                event = self._parse_auth_line(line)
                if event:
                    events.append(event.to_dict())

        except FileNotFoundError:
            console.print(f"⚠️  [yellow]Auth log not found. Generating demo data...[/yellow]")
            events = self._generate_demo_auth_events()

        self.df = pd.DataFrame(events)
        if not self.df.empty:
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
        
        logger.info(f"Parsed {len(events)} auth events")
        return self.df

    def _parse_auth_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single auth.log line"""
        # Standard syslog format: Month Day HH:MM:SS hostname service: message
        pattern = r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\S+?):\s+(.+)$'
        match = re.match(pattern, line)
        if not match:
            return None

        timestamp_str, service, message = match.groups()

        # Parse timestamp (current year, no year in syslog)
        try:
            current_year = datetime.now().year
            timestamp = datetime.strptime(
                f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            timestamp = datetime.now()

        # Extract IP address
        ip_match = re.search(LogConfig.PATTERNS["ip_address"], line)
        ip = ip_match.group(1) if ip_match else None

        # Classify event level
        level = "INFO"
        if "Failed" in message or "failure" in message:
            level = "WARNING"
        elif "BREAK-IN" in message or "Invalid user" in message:
            level = "CRITICAL"
        elif "Accepted" in message:
            level = "SUCCESS"

        return LogEvent(
            timestamp=timestamp,
            level=level,
            source=service,
            message=message,
            ip=ip,
        )

    def _generate_demo_auth_events(self) -> List[Dict]:
        """Generate realistic demo auth events for testing"""
        import random
        from datetime import datetime, timedelta

        demo_ips = ["192.168.1.100", "10.0.0.50", "172.16.0.1",
                    "45.33.32.156", "8.8.8.8"]
        demo_users = ["root", "admin", "ubuntu", "user1", "postgres"]

        events = []
        base_time = datetime.now() - timedelta(hours=24)

        for i in range(500):
            t = base_time + timedelta(seconds=random.randint(0, 86400))
            ip = random.choice(demo_ips)
            user = random.choice(demo_users)

            if random.random() < 0.3:
                msg = f"Failed password for {user} from {ip} port {random.randint(1024, 65535)} ssh2"
                level = "WARNING"
            elif random.random() < 0.1:
                msg = f"Invalid user {user} from {ip}"
                level = "CRITICAL"
            else:
                msg = f"Accepted publickey for {user} from {ip} port 22"
                level = "SUCCESS"

            events.append({
                "timestamp": t.isoformat(),
                "level": level,
                "source": "sshd",
                "message": msg,
                "ip": ip,
                "user": user,
            })

        return events

    def analyze_failed_logins(self) -> Dict:
        """
        Analyze failed login patterns
        Returns statistics and top attacker IPs
        """
        if self.df is None or self.df.empty:
            self.parse_auth_log()

        failed = self.df[self.df['level'] == 'WARNING']
        
        if failed.empty:
            return {"total_failures": 0, "top_attackers": [], "risk": "LOW"}

        # Count by IP
        ip_counts = failed['ip'].value_counts()
        
        # Time-based analysis
        failed_copy = failed.copy()
        failed_copy['timestamp'] = pd.to_datetime(failed_copy['timestamp'])
        failed_copy = failed_copy.set_index('timestamp')
        
        hourly = failed_copy.resample('h').size() if len(failed_copy) > 0 else pd.Series()

        result = {
            "total_failures": len(failed),
            "unique_ips": failed['ip'].nunique(),
            "top_attackers": ip_counts.head(10).to_dict(),
            "hourly_pattern": hourly.to_dict() if not hourly.empty else {},
            "risk": "CRITICAL" if len(failed) > 100 else "HIGH" if len(failed) > 20 else "MEDIUM",
        }

        # Display results
        self._display_failed_login_report(result, ip_counts)
        return result

    def _display_failed_login_report(self, result: Dict, ip_counts):
        """Display failed login analysis as rich table"""
        table = Table(title="🔐 Failed Login Analysis", show_lines=True)
        table.add_column("Rank", style="cyan", width=6)
        table.add_column("IP Address", style="white", width=18)
        table.add_column("Failed Attempts", style="red", width=16)
        table.add_column("Risk Level", style="yellow", width=12)

        for i, (ip, count) in enumerate(ip_counts.head(10).items(), 1):
            risk = "CRITICAL" if count > 50 else "HIGH" if count > 20 else "MEDIUM"
            risk_color = {"CRITICAL": "red", "HIGH": "orange3", "MEDIUM": "yellow"}[risk]
            table.add_row(
                str(i),
                str(ip) if ip else "Unknown",
                str(count),
                f"[{risk_color}]{risk}[/{risk_color}]",
            )

        console.print(table)
        console.print(f"\n📊 Total Failed Attempts: [bold red]{result['total_failures']}[/bold red]")
        console.print(f"🌐 Unique Attacker IPs: [bold]{result['unique_ips']}[/bold]")

    def parse_web_access_log(self, log_path: str = "/var/log/nginx/access.log") -> pd.DataFrame:
        """
        Parse Nginx/Apache access logs
        Detects: SQL injection, XSS, directory traversal, scanner fingerprints
        """
        events = []
        # Combined log format pattern
        pattern = (r'(\S+) \S+ \S+ \[(.+?)\] "(\S+) (\S+) \S+" '
                  r'(\d+) (\d+) "([^"]*)" "([^"]*)"')

        attack_patterns = {
            "SQL_INJECTION": [r"union\s+select", r"'--", r"1=1", r"or\s+1=1"],
            "XSS": [r"<script", r"javascript:", r"onerror="],
            "DIR_TRAVERSAL": [r"\.\./", r"etc/passwd", r"etc/shadow"],
            "SCANNER": [r"nikto", r"sqlmap", r"nessus", r"masscan"],
        }

        try:
            with open(log_path, 'r', errors='ignore') as f:
                for line in f:
                    m = re.match(pattern, line)
                    if not m:
                        continue

                    ip, ts, method, path, status, size, ref, ua = m.groups()

                    # Detect attack patterns
                    detected_attacks = []
                    full_req = f"{method} {path} {ua}"
                    for attack_type, patterns in attack_patterns.items():
                        for p in patterns:
                            if re.search(p, full_req, re.IGNORECASE):
                                detected_attacks.append(attack_type)
                                break

                    events.append({
                        "ip": ip,
                        "timestamp": ts,
                        "method": method,
                        "path": path[:100],
                        "status": int(status),
                        "size": int(size),
                        "user_agent": ua[:100],
                        "attacks": ",".join(detected_attacks),
                        "is_attack": len(detected_attacks) > 0,
                    })

        except FileNotFoundError:
            console.print(f"⚠️  [yellow]Web log not found. Using demo data.[/yellow]")
            events = self._generate_demo_web_events()

        return pd.DataFrame(events)

    def _generate_demo_web_events(self) -> List[Dict]:
        """Generate demo web access log events"""
        import random
        events = []
        paths = ["/", "/admin", "/login", "/api/users",
                "/?id=1' OR '1'='1", "/../../../etc/passwd",
                "/search?q=<script>alert(1)</script>"]
        
        for _ in range(200):
            events.append({
                "ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                "timestamp": datetime.now().isoformat(),
                "method": random.choice(["GET", "POST"]),
                "path": random.choice(paths),
                "status": random.choice([200, 404, 403, 500]),
                "size": random.randint(100, 5000),
                "user_agent": random.choice(["Mozilla/5.0", "sqlmap/1.0", "nikto"]),
                "attacks": "",
                "is_attack": False,
            })
        return events

    def generate_security_report(self) -> Dict:
        """Generate comprehensive security report from all logs"""
        console.print("📊 [cyan]Generating Security Report...[/cyan]")
        
        auth_df = self.parse_auth_log()
        web_df = self.parse_web_access_log()
        failed_logins = self.analyze_failed_logins()

        # Web attack summary
        if not web_df.empty and 'is_attack' in web_df.columns:
            web_attacks = web_df[web_df['is_attack'] == True]
            attack_summary = web_df['attacks'].value_counts().to_dict()
        else:
            web_attacks = pd.DataFrame()
            attack_summary = {}

        report = {
            "generated_at": datetime.now().isoformat(),
            "auth_events": len(auth_df) if not auth_df.empty else 0,
            "failed_logins": failed_logins,
            "web_requests": len(web_df) if not web_df.empty else 0,
            "web_attacks": len(web_attacks),
            "attack_types": attack_summary,
            "overall_risk": "HIGH" if failed_logins.get("total_failures", 0) > 50 else "MEDIUM",
        }

        console.print("✅ [green]Security report generated[/green]")
        return report