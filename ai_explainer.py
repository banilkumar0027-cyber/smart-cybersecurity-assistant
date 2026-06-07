import os
try:
    from dotenv import load_dotenv
    load_dotenv()
except:
    pass

GROQ_KEY = os.getenv('GROQ_API_KEY', '')

try:
    from groq import Groq
    GROQ_OK = True
except:
    GROQ_OK = False

OFFLINE_DB = {
    'sql injection': 'SQL Injection attacks databases by inserting malicious SQL. Example: entering  OR 1=1  in login fields to bypass authentication.',
    'xss': 'Cross-Site Scripting injects malicious JavaScript into web pages to steal cookies or redirect users.',
    'nmap': 'Nmap scans networks for open ports. Usage: nmap -sV 192.168.1.1 to detect services.',
    'brute force': 'Brute force tries all password combinations. Prevented by account lockouts and strong passwords.',
    'phishing': 'Phishing tricks users via fake emails/websites to steal credentials.',
    'firewall': 'Firewall monitors and filters network traffic using rules to block threats.',
    'ddos': 'DDoS floods a server with traffic from multiple sources to make it unavailable.',
    'malware': 'Malware is malicious software including viruses, ransomware, spyware, and trojans.',
    'ransomware': 'Ransomware encrypts your files and demands payment to restore access.',
    'vpn': 'VPN encrypts internet traffic and masks your IP address for privacy.',
    'ssh': 'SSH provides encrypted remote terminal access on port 22.',
    'port': 'Ports are numbered endpoints for network communication. Port 80=HTTP, 443=HTTPS, 22=SSH.',
    'kali': 'Kali Linux is a Debian-based OS with 600+ pre-installed security and hacking tools.',
    'metasploit': 'Metasploit is a penetration testing framework for finding and exploiting vulnerabilities.',
    'wireshark': 'Wireshark captures and analyzes network packets in real time.',
    'burpsuite': 'Burp Suite intercepts and modifies web traffic for security testing.',
    'vulnerability': 'A vulnerability is a weakness in software that attackers can exploit.',
    'exploit': 'An exploit is code that takes advantage of a vulnerability to gain unauthorized access.',
    'cve': 'CVE is a list of publicly known cybersecurity vulnerabilities with unique IDs.',
    'encryption': 'Encryption converts data into unreadable format. Only authorized parties can decrypt it.',
    'zero day': 'Zero-day is an unknown vulnerability with no available patch yet.',
    'penetration': 'Penetration testing simulates attacks to find security weaknesses before hackers do.',
    'social engineering': 'Social engineering manipulates people psychologically to reveal confidential info.',
    'rootkit': 'Rootkits hide malware by modifying the OS kernel to avoid detection.',
    'botnet': 'Botnet is a network of infected computers controlled by attackers for attacks.',
}

class AIExplainer:
    def __init__(self, api_key=None):
        self.key = api_key or GROQ_KEY
        self.client = None
        self.history = []
        if GROQ_OK and self.key:
            try:
                self.client = Groq(api_key=self.key)
                print("[AI] Groq LLaMA3 loaded — Online mode active!")
            except Exception as e:
                print(f"[AI] Groq failed: {e}")
        if not self.client:
            print("[AI] Offline mode — add GROQ_API_KEY to .env for online AI")

    def explain(self, query, lang='en'):
        if not query or not query.strip():
            return "Please ask a cybersecurity question."
        if self.client:
            try:
                if lang == 'te':
                    prompt = f"తెలుగులో సమాధానం ఇవ్వండి (cybersecurity expert గా): {query}"
                else:
                    prompt = f"You are a cybersecurity expert on Kali Linux. Answer clearly and practically: {query}"
                self.history.append({"role": "user", "content": prompt})
                if len(self.history) > 10:
                    self.history = self.history[-10:]
                resp = self.client.chat.completions.create(
                    model="llama3-70b-8192",
                    messages=[
                        {"role": "system", "content":
                         "You are a smart cybersecurity assistant running on Kali Linux. "
                         "Give practical, clear answers. Support Telugu and English."},
                        *self.history
                    ],
                    max_tokens=500,
                    temperature=0.3,
                )
                answer = resp.choices[0].message.content
                self.history.append({"role": "assistant", "content": answer})
                return answer
            except Exception as e:
                return self._offline(query)
        return self._offline(query)

    def _offline(self, query):
        q = query.lower()
        for keyword, answer in OFFLINE_DB.items():
            if keyword in q:
                return f"[Offline] {answer}"
        return (
            "[Offline Mode] I don't have an answer for that locally.\n"
            "Get FREE Groq API key at: https://console.groq.com\n"
            "Then add to .env: GROQ_API_KEY=your-key"
        )

    def explain_command(self, cmd, lang='en'):
        return self.explain(f"Explain Linux command: {cmd}", lang)

    def explain_threat(self, data):
        return self.explain(f"Explain this network threat: {data}")

    def chat(self, msg, lang='en'):
        return self.explain(msg, lang)
