# threat_detector.py
import subprocess, socket, re, os
from datetime import datetime

class ThreatDetector:
    def __init__(self):
        self.scan_history = []
        print("[ThreatDetector] Initialized")

    # ── PORT SCAN ─────────────────────────────────────
    def scan_ports(self, target='127.0.0.1', port_range='1-1000'):
        print(f"[*] Scanning {target} ports {port_range}...")
        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'open_ports': [],
            'risk_score': 0,
            'warnings': []
        }
        HIGH_RISK = {
            21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP',
            80:'HTTP', 443:'HTTPS', 445:'SMB', 3306:'MySQL',
            3389:'RDP', 5900:'VNC', 6379:'Redis', 27017:'MongoDB'
        }
        try:
            cmd = ['nmap', '-sV', '--open', '-T4',
                   f'-p{port_range}', target]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            for line in result.stdout.split('\n'):
                match = re.search(r'(\d+)/tcp\s+open\s+(\S+)', line)
                if match:
                    port = int(match.group(1))
                    service = match.group(2)
                    risk = 'HIGH' if port in HIGH_RISK else 'LOW'
                    results['open_ports'].append({
                        'port': port,
                        'service': service,
                        'risk': risk
                    })
                    if risk == 'HIGH':
                        results['warnings'].append(
                            f"Port {port} ({HIGH_RISK[port]}) is open!"
                        )
                        results['risk_score'] += 15
                    else:
                        results['risk_score'] += 3
            results['risk_score'] = min(results['risk_score'], 100)
        except FileNotFoundError:
            # nmap not found — use basic socket scan
            results = self._basic_scan(target, results, HIGH_RISK)
        except Exception as e:
            results['error'] = str(e)

        self.scan_history.append(results)
        self._display_results(results)
        return results

    def _basic_scan(self, target, results, HIGH_RISK):
        """Fallback scanner without nmap."""
        common_ports = [21,22,23,25,53,80,110,135,139,
                        143,443,445,3306,3389,5900,8080]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                r = sock.connect_ex((target, port))
                sock.close()
                if r == 0:
                    service = HIGH_RISK.get(port, 'unknown')
                    risk = 'HIGH' if port in HIGH_RISK else 'LOW'
                    results['open_ports'].append({
                        'port': port, 'service': service, 'risk': risk
                    })
                    if risk == 'HIGH':
                        results['warnings'].append(
                            f"Port {port} ({service}) is open!"
                        )
                        results['risk_score'] += 15
            except:
                pass
        results['risk_score'] = min(results['risk_score'], 100)
        return results

    def _display_results(self, results):
        print(f"\n{'='*50}")
        print(f"SCAN RESULTS: {results['target']}")
        print(f"{'='*50}")
        if results['open_ports']:
            for p in results['open_ports']:
                risk_label = "⚠ HIGH" if p['risk']=='HIGH' else "✓ LOW"
                print(f"  Port {p['port']:5d} | {p['service']:15s} | {risk_label}")
        else:
            print("  No open ports found.")
        print(f"\nRisk Score: {results['risk_score']}/100")
        for w in results['warnings']:
            print(f"  ⚠ {w}")
        print(f"{'='*50}\n")

    # ── NETWORK ANOMALIES ─────────────────────────────
    def detect_anomalies(self):
        anomalies = []
        # Check suspicious ports
        try:
            result = subprocess.run(
                ['ss', '-tlnp'], capture_output=True, text=True
            )
            suspicious = {4444, 1337, 31337, 5555, 6666, 7777}
            for line in result.stdout.split('\n'):
                for port in suspicious:
                    if f':{port}' in line:
                        anomalies.append(
                            f"SUSPICIOUS: Port {port} is listening!"
                        )
        except Exception as e:
            anomalies.append(f"Could not check ports: {e}")
        return anomalies

    # ── LOG ANALYSIS ──────────────────────────────────
    def check_logs(self, log_path='/var/log/auth.log'):
        results = {'failed_logins': {}, 'anomalies': []}
        if not os.path.exists(log_path):
            results['anomalies'].append(
                f"Log file not found: {log_path}"
            )
            return results
        try:
            with open(log_path, 'r', errors='replace') as f:
                for line in f:
                    m = re.search(
                        r'Failed password.*from ([\d.]+)', line
                    )
                    if m:
                        ip = m.group(1)
                        results['failed_logins'][ip] = \
                            results['failed_logins'].get(ip, 0) + 1
            for ip, count in results['failed_logins'].items():
                if count >= 5:
                    results['anomalies'].append(
                        f"BRUTE FORCE: {ip} tried {count} times!"
                    )
        except PermissionError:
            results['anomalies'].append(
                "Permission denied. Run as root: sudo python3 -m core.main"
            )
        return results

    def get_summary(self):
        return {
            'total_scans': len(self.scan_history),
            'last_scan': self.scan_history[-1] if self.scan_history else None
        }
