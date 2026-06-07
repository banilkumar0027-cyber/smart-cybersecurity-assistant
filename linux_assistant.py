# linux_assistant.py
import subprocess, re, shlex
from datetime import datetime

class LinuxAssistant:
    def __init__(self, ai_explainer=None):
        self.ai = ai_explainer
        self.command_history = []
        print("[LinuxAssistant] Initialized")

    # ── DANGEROUS COMMANDS ────────────────────────────
    DANGEROUS = [
        (r'rm\s+-rf\s+/', 'CRITICAL: Deletes entire filesystem!'),
        (r'rm\s+-rf\s+\*', 'CRITICAL: Deletes all files!'),
        (r':\(\)\{.*\}', 'CRITICAL: Fork bomb!'),
        (r'mkfs\.', 'CRITICAL: Formats disk!'),
        (r'dd\s+if=.*of=/dev/', 'HIGH: Overwrites disk!'),
        (r'chmod\s+-R\s+777', 'HIGH: Makes all files public!'),
        (r'wget.*\|.*sh', 'HIGH: Remote code execution!'),
        (r'curl.*\|.*bash', 'HIGH: Remote code execution!'),
        (r'nc\s+-e', 'HIGH: Reverse shell!'),
    ]

    # ── COMMAND DATABASE ──────────────────────────────
    CMD_DB = {
        'nmap': 'Network scanner. Usage: nmap -sV <target>. Finds open ports and services.',
        'netstat': 'Shows network connections. Usage: netstat -tulnp',
        'ss': 'Modern netstat. Usage: ss -tulnp (shows listening ports)',
        'iptables': 'Firewall manager. Usage: iptables -L -n -v (list rules)',
        'tcpdump': 'Packet sniffer. Usage: tcpdump -i eth0 port 80',
        'ps': 'Shows processes. Usage: ps aux (all processes with details)',
        'top': 'Real-time process monitor. Press q to quit.',
        'htop': 'Better process monitor. Install: apt install htop',
        'who': 'Shows logged-in users. Usage: who',
        'last': 'Shows login history. Usage: last -20',
        'find': 'Find files. Usage: find / -name "*.log" -type f',
        'grep': 'Search text. Usage: grep "error" /var/log/syslog',
        'chmod': 'Change permissions. Usage: chmod 755 file.py',
        'chown': 'Change ownership. Usage: chown user:group file',
        'tail': 'Watch log file live. Usage: tail -f /var/log/auth.log',
        'ufw': 'Simple firewall. Usage: ufw status / ufw enable',
        'fail2ban': 'Bans brute-force IPs. Usage: fail2ban-client status',
        'whoami': 'Shows current user. Usage: whoami',
        'ifconfig': 'Shows network interfaces and IP addresses.',
        'ip': 'Modern network tool. Usage: ip addr / ip route',
        'ping': 'Test connectivity. Usage: ping -c 4 google.com',
        'curl': 'HTTP client. Usage: curl -I https://example.com',
        'wget': 'Download files. Usage: wget https://example.com/file',
        'ssh': 'Secure remote login. Usage: ssh user@192.168.1.1',
        'scp': 'Secure file copy. Usage: scp file.txt user@host:/path/',
        'tar': 'Archive files. Usage: tar -xzf file.tar.gz',
        'df': 'Disk space. Usage: df -h',
        'du': 'Folder size. Usage: du -sh /var/log/',
        'lsof': 'List open files/ports. Usage: lsof -i :80',
        'history': 'Show command history. Usage: history | grep nmap',
    }

    def check_safety(self, command):
        """Returns (risk_level, warning_message)."""
        for pattern, warning in self.DANGEROUS:
            if re.search(pattern, command, re.IGNORECASE):
                level = warning.split(':')[0]
                return level, warning
        return 'SAFE', ''

    def explain(self, command, lang='en'):
        """Explain a Linux command."""
        cmd_name = command.strip().split()[0] if command.strip() else command

        # Check local database first
        if cmd_name in self.CMD_DB:
            explanation = self.CMD_DB[cmd_name]
            if lang == 'te':
                return f"[{cmd_name}] {explanation}\n(తెలుగు సపోర్ట్: AI key అవసరం)"
            return f"[{cmd_name}] {explanation}"

        # Use AI if available
        if self.ai:
            return self.ai.explain_command(command, lang)

        # Try man page
        try:
            result = subprocess.run(
                ['man', cmd_name],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'NAME' in line and i+1 < len(lines):
                        return f"[{cmd_name}] {lines[i+1].strip()}"
        except:
            pass

        return f"[{cmd_name}] No local info found. Try: man {cmd_name}"

    def suggest(self, task):
        """Suggest commands for a security task."""
        task = task.lower()
        suggestions = {
            'scan': ['nmap -sV <target>', 'nmap -p 1-65535 <target>'],
            'port': ['ss -tulnp', 'netstat -tulnp', 'lsof -i'],
            'log': ['tail -f /var/log/auth.log', 'grep Failed /var/log/auth.log'],
            'firewall': ['iptables -L -n -v', 'ufw status verbose'],
            'user': ['who', 'last -20', 'cat /etc/passwd'],
            'process': ['ps aux', 'htop', 'top'],
            'network': ['ifconfig', 'ip addr', 'ip route', 'netstat -rn'],
            'disk': ['df -h', 'du -sh /*'],
            'service': ['systemctl status', 'service --status-all'],
        }
        results = []
        for keyword, cmds in suggestions.items():
            if keyword in task:
                results.extend(cmds)
        if results:
            return "Suggested commands:\n" + \
                   "\n".join(f"  $ {c}" for c in results)
        return "Try: nmap, ss, iptables, fail2ban, tcpdump"

    def safe_run(self, command):
        """Run command only if safe."""
        risk, warning = self.check_safety(command)
        if risk in ('CRITICAL', 'HIGH'):
            return -1, '', f'BLOCKED: {warning}'
        if risk == 'MEDIUM':
            print(f"WARNING: {warning}")
            confirm = input("Proceed? (yes/no): ")
            if confirm.lower() != 'yes':
                return -1, '', 'Cancelled'
        try:
            result = subprocess.run(
                shlex.split(command),
                capture_output=True, text=True, timeout=30
            )
            self.command_history.append({
                'cmd': command,
                'time': datetime.now().isoformat(),
                'code': result.returncode
            })
            return result.returncode, result.stdout, result.stderr
        except FileNotFoundError:
            return -1, '', f'Command not found: {command.split()[0]}'
        except subprocess.TimeoutExpired:
            return -1, '', 'Command timed out (30s)'
        except Exception as e:
            return -1, '', str(e)
