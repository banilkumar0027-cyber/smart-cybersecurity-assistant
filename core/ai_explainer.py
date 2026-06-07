"""
Smart Cybersecurity Assistant - AI Explanation Engine
Powered by Google Gemini API
Provides intelligent, context-aware explanations in Telugu and English
"""

from datetime import datetime
from typing import Optional, Dict, List

import google.generativeai as genai
from loguru import logger
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from config import GEMINI_API_KEY

console = Console()


class AIExplainer:
    """
    Google Gemini-powered AI Explanation Engine
    
    Capabilities:
    - Explain cybersecurity threats in simple language
    - Translate between Telugu and English
    - Provide step-by-step remediation guidance
    - Answer security questions
    - Analyze log excerpts
    - Explain Linux commands
    """

    # System prompt that defines the AI's behavior
    SYSTEM_PROMPT = """You are CyberGuard AI, an expert ethical hacking assistant and cybersecurity educator.

Your expertise includes:
- Network security (port scanning, vulnerability assessment)
- Log analysis and threat detection
- Linux system administration and security hardening
- Malware analysis (theoretical)
- MITRE ATT&CK framework
- Incident response procedures

Language capabilities:
- You can respond in both English and Telugu (తెలుగు)
- When asked in Telugu, respond primarily in Telugu with technical terms in English
- When asked in English, respond in English

Guidelines:
- Always emphasize ETHICAL use of security tools
- Include MITRE ATT&CK technique IDs where relevant
- Provide actionable remediation steps
- Explain concepts clearly for students and professionals
- Never provide instructions for illegal activities
- Add Telugu translations for key security terms when responding in Telugu

Format:
- Use markdown formatting
- Include code blocks for commands
- Use emojis strategically (🛡️ for security, 🔍 for analysis, ⚠️ for warnings)"""

    def __init__(self):
        """Initialize Gemini AI connection"""
        if not GEMINI_API_KEY:
            logger.warning("⚠️  GEMINI_API_KEY not set. AI features will be limited.")
            self.model = None
        else:
            try:
                genai.configure(api_key=GEMINI_API_KEY)
                self.model = genai.GenerativeModel(
                    model_name="gemini-1.5-flash",
                    system_instruction=self.SYSTEM_PROMPT,
                )
                self.chat = self.model.start_chat(history=[])
                logger.info("✅ Gemini AI initialized successfully")
            except Exception as e:
                logger.error(f"Gemini init failed: {e}")
                self.model = None

        self.conversation_history: List[Dict] = []

    def explain(self, question: str, language: str = "en",
                context: str = None) -> str:
        """
        Get AI explanation for a cybersecurity concept or event
        
        Args:
            question: Question or topic to explain
            language: 'en' for English, 'te' for Telugu
            context: Optional context (e.g., log excerpt, threat report)
        
        Returns:
            AI-generated explanation string
        """
        if not self.model:
            return self._fallback_response(question, language)

        # Build prompt
        lang_instruction = (
            "Please respond in Telugu (తెలుగు) language. "
            "Use English for technical terms and commands." 
            if language == "te"
            else "Please respond in English."
        )

        prompt_parts = [lang_instruction, "\n\nQuestion: ", question]

        if context:
            prompt_parts.insert(1, f"\n\nContext:\n```\n{context[:2000]}\n```")

        full_prompt = "".join(prompt_parts)

        try:
            console.print(f"🤖 [cyan]Asking Gemini AI...[/cyan]")
            response = self.chat.send_message(full_prompt)
            answer = response.text

            # Display formatted response
            console.print(Panel(
                Markdown(answer),
                title="🤖 CyberGuard AI Response",
                border_style="cyan"
            ))

            # Save to history
            self.conversation_history.append({
                "timestamp": datetime.now().isoformat(),
                "question": question,
                "answer": answer,
                "language": language,
            })

            return answer

        except Exception as e:
            logger.error(f"Gemini API error: {e}")
            return self._fallback_response(question, language)

    def explain_threat(self, threat: Dict, language: str = "en") -> str:
        """
        Get AI explanation for a specific detected threat
        
        Args:
            threat: ThreatAlert.to_dict() result
            language: Response language
        """
        question = (
            f"Explain this security threat and provide remediation steps:\n"
            f"Threat Type: {threat.get('threat_type', 'Unknown')}\n"
            f"Severity: {threat.get('severity', 'Unknown')}\n"
            f"Description: {threat.get('description', 'No description')}\n"
            f"MITRE Technique: {threat.get('mitre_technique', 'Unknown')}\n"
            f"Source IP: {threat.get('source_ip', 'Unknown')}"
        )
        return self.explain(question, language)

    def explain_log_anomaly(self, log_excerpt: str, language: str = "en") -> str:
        """Explain suspicious patterns found in logs"""
        question = ("What security events are happening in these logs? "
                   "Are there any threats? What should I do?")
        return self.explain(question, language, context=log_excerpt)

    def explain_command(self, command: str, language: str = "en") -> str:
        """Explain what a Linux command does from a security perspective"""
        question = (
            f"Explain this Linux command from a cybersecurity perspective. "
            f"Include what it does, when to use it, and any security implications:\n"
            f"Command: {command}"
        )
        return self.explain(question, language)

    def get_remediation_steps(self, threat_type: str,
                              language: str = "en") -> str:
        """Get step-by-step remediation for a threat type"""
        question = (
            f"Provide step-by-step remediation steps for: {threat_type}\n"
            f"Include: immediate actions, investigation steps, and prevention measures.\n"
            f"Format as numbered list with Linux commands where applicable."
        )
        return self.explain(question, language)

    def interactive_qa(self, language: str = "en"):
        """
        Start interactive Q&A session with AI
        Maintains conversation context
        """
        lang_name = "Telugu" if language == "te" else "English"
        console.print(Panel(
            f"🤖 [bold cyan]CyberGuard AI Interactive Mode[/bold cyan]\n"
            f"Language: {lang_name}\n"
            f"Type 'exit' or 'quit' to stop\n"
            f"Type 'history' to see conversation history",
            border_style="cyan"
        ))

        while True:
            try:
                user_input = console.input("\n[bold green]You > [/bold green]")
                
                if user_input.lower() in ['exit', 'quit', 'bye']:
                    console.print("👋 [cyan]Session ended. Stay secure![/cyan]")
                    break
                
                if user_input.lower() == 'history':
                    for i, h in enumerate(self.conversation_history[-5:], 1):
                        console.print(f"\n[dim]{i}. {h['question'][:80]}...[/dim]")
                    continue

                if user_input.strip():
                    self.explain(user_input, language)

            except KeyboardInterrupt:
                console.print("\n👋 [cyan]Session interrupted.[/cyan]")
                break

    def _fallback_response(self, question: str, language: str) -> str:
        """Provide basic response when AI is unavailable"""
        if language == "te":
            return (
                f"⚠️ AI సేవ అందుబాటులో లేదు. దయచేసి GEMINI_API_KEY సెట్ చేయండి.\n\n"
                f"మీ ప్రశ్న: {question}"
            )
        else:
            return (
                f"⚠️ AI service unavailable. Please set GEMINI_API_KEY in .env\n\n"
                f"Your question: {question}\n\n"
                f"For manual assistance, try: man <command> or --help flag"
            )