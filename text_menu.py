import os
from threat_detector import ThreatDetector
from linux_assistant import LinuxAssistant
from ai_explainer import AIExplainer

# ── Colors ────────────────────────────────────────────
R  = '\033[91m'   # Red
G  = '\033[92m'   # Green
Y  = '\033[93m'   # Yellow
B  = '\033[94m'   # Blue
M  = '\033[95m'   # Magenta
C  = '\033[96m'   # Cyan
W  = '\033[97m'   # White
BLD= '\033[1m'    # Bold
DIM= '\033[2m'    # Dim
RST= '\033[0m'    # Reset

td   = ThreatDetector()
la   = LinuxAssistant()
ai   = AIExplainer()
lang = 'en'

def clear():
    os.system('clear')

def banner():
    clear()
    print(f"{G}{BLD}")
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║     SMART CYBERSECURITY ASSISTANT v1.0          ║")
    print("  ║   AI-Powered | Telugu+English | Kali Linux      ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print(f"{RST}")

def menu():
    banner()
    print(f"  {C}{BLD}┌─────────────────────────────────────┐{RST}")
    print(f"  {C}{BLD}│           MAIN MENU                 │{RST}")
    print(f"  {C}{BLD}└─────────────────────────────────────┘{RST}")
    print()
    print(f"  {G}{BLD}[1]{RST}{W}  🔍 Scan Ports          {DIM}Network Threat Detection{RST}")
    print(f"  {Y}{BLD}[2]{RST}{W}  📋 Analyze Logs         {DIM}Brute Force Detection{RST}")
    print(f"  {C}{BLD}[3]{RST}{W}  🐧 Explain Linux Cmd    {DIM}AI Command Guide{RST}")
    print(f"  {M}{BLD}[4]{RST}{W}  🌐 Network Anomalies    {DIM}Live Threat Monitor{RST}")
    print(f"  {B}{BLD}[5]{RST}{W}  💡 Command Suggester    {DIM}Task-based Help{RST}")
    print(f"  {G}{BLD}[6]{RST}{W}  🤖 AI Cyber Chat        {DIM}Ask Anything{RST}")
    print(f"  {Y}{BLD}[7]{RST}{W}  📊 Full Security Audit  {DIM}Complete Report{RST}")
    print(f"  {C}{BLD}[8]{RST}{W}  🌍 Switch Language      {DIM}Telugu / English{RST}")
    print(f"  {R}{BLD}[0]{RST}{W}  ❌ Exit{RST}")
    print()
    print(f"  {DIM}Current Language: {'Telugu 🇮🇳' if lang=='te' else 'English 🇬🇧'}{RST}")
    print(f"  {G}{'─'*42}{RST}")

def wait():
    input(f"\n  {DIM}Press Enter to return to menu...{RST}")

def section(title, color=C):
    print(f"\n  {color}{BLD}{'─'*42}")
    print(f"  {title}")
    print(f"  {'─'*42}{RST}\n")

while True:
    menu()
    choice = input(f"  {BLD}{G}Enter choice (0-8): {RST}").strip()

    if choice == '0':
        banner()
        print(f"  {G}{BLD}Goodbye! Stay Secure. 🛡️{RST}\n")
        break

    elif choice == '1':
        section("🔍 PORT SCANNER", G)
        target = input(f"  {Y}Target IP address : {RST}").strip()
        ports  = input(f"  {Y}Port range        : {RST}").strip() or '1-1000'
        print(f"\n  {C}Scanning {W}{BLD}{target}{RST}{C}...{RST}\n")
        td.scan_ports(target, ports)
        wait()

    elif choice == '2':
        section("📋 LOG ANALYZER", Y)
        print(f"  {G}[1]{RST} Auth Log  {DIM}/var/log/auth.log{RST}")
        print(f"  {G}[2]{RST} Custom log path")
        sub = input(f"\n  {Y}Choose (1/2): {RST}").strip()
        path = '/var/log/auth.log' if sub == '1' else input(f"  {Y}Enter path: {RST}").strip()
        result = td.check_logs(path)
        print(f"\n  {W}Failed Logins : {R}{BLD}{len(result['failed_logins'])}{RST}")
        if result['anomalies']:
            print(f"  {R}{BLD}ANOMALIES DETECTED:{RST}")
            for a in result['anomalies']:
                print(f"  {R}⚠  {a}{RST}")
        else:
            print(f"  {G}✓  No anomalies found. System looks clean!{RST}")
        wait()

    elif choice == '3':
        section("🐧 LINUX COMMAND EXPLAINER", C)
        cmd = input(f"  {Y}Command to explain (e.g. nmap, ss): {RST}").strip()
        print(f"\n  {G}{BLD}Explanation:{RST}")
        explanation = la.explain(cmd, lang)
        print(f"  {W}{explanation}{RST}")
        wait()

    elif choice == '4':
        section("🌐 NETWORK ANOMALY DETECTOR", M)
        print(f"  {C}Scanning for suspicious activity...{RST}\n")
        anomalies = td.detect_anomalies()
        if anomalies:
            print(f"  {R}{BLD}THREATS DETECTED:{RST}")
            for a in anomalies:
                print(f"  {R}⚠  {a}{RST}")
        else:
            print(f"  {G}{BLD}✓  All clear! No anomalies detected.{RST}")
        wait()

    elif choice == '5':
        section("💡 COMMAND SUGGESTER", B)
        task = input(f"  {Y}What do you want to do? : {RST}").strip()
        print(f"\n  {G}{BLD}Suggestions:{RST}")
        print(f"  {W}{la.suggest(task)}{RST}")
        wait()

    elif choice == '6':
        section("🤖 AI CYBERSECURITY CHAT", G)
        print(f"  {DIM}Type 'back' to return to menu{RST}\n")
        while True:
            q = input(f"  {C}{BLD}You: {RST}").strip()
            if q.lower() == 'back':
                break
            resp = ai.explain(q, lang)
            print(f"\n  {G}{BLD}AI :{RST} {W}{resp}{RST}\n")

    elif choice == '7':
        section("📊 FULL SECURITY AUDIT", Y)
        target = input(f"  {Y}Target IP (Enter = localhost): {RST}").strip() or '127.0.0.1'
        print(f"\n  {C}[1/3] Running port scan...{RST}")
        scan = td.scan_ports(target)
        print(f"  {C}[2/3] Analyzing logs...{RST}")
        logs = td.check_logs()
        print(f"  {C}[3/3] Checking anomalies...{RST}")
        anomalies = td.detect_anomalies()
        status = f"{R}CRITICAL" if scan['risk_score']>70 else f"{Y}MODERATE" if scan['risk_score']>30 else f"{G}SAFE"
        print(f"\n  {BLD}{C}{'═'*42}")
        print(f"  {'SECURITY AUDIT REPORT':^42}")
        print(f"  {'═'*42}{RST}")
        print(f"  {W}Target     : {BLD}{target}{RST}")
        print(f"  {W}Open Ports : {Y}{BLD}{len(scan['open_ports'])}{RST}")
        print(f"  {W}Risk Score : {R}{BLD}{scan['risk_score']}/100{RST}")
        print(f"  {W}Log Issues : {Y}{BLD}{len(logs['anomalies'])}{RST}")
        print(f"  {W}Anomalies  : {Y}{BLD}{len(anomalies)}{RST}")
        print(f"  {W}Status     : {BLD}{status}{RST}")
        print(f"  {C}{BLD}{'═'*42}{RST}")
        wait()

    elif choice == '8':
        lang = 'te' if lang == 'en' else 'en'
        name = f"{G}Telugu 🇮🇳" if lang == 'te' else f"{B}English 🇬🇧"
        print(f"\n  Language switched to: {BLD}{name}{RST}")
        wait()

    else:
        print(f"\n  {R}Invalid choice. Enter 0-8.{RST}")
        wait()
