"""
Smart Cybersecurity Assistant - Voice Engine
Supports: Telugu (తెలుగు) and English
Technologies: SpeechRecognition, gTTS, pyttsx3, googletrans
"""

import os
import io
import time
import threading
import tempfile
from pathlib import Path
from typing import Optional, Tuple

# Third-party imports
import speech_recognition as sr
from gtts import gTTS
import pyttsx3
from googletrans import Translator
from rich.console import Console
from rich.panel import Panel
from loguru import logger

# Local imports
from config import VoiceConfig

console = Console()


class VoiceEngine:
    """
    Bilingual Voice Engine for Telugu and English
    
    Capabilities:
    - Speech-to-Text in Telugu and English
    - Text-to-Speech in both languages
    - Auto language detection
    - Translation between Telugu ↔ English
    """

    def __init__(self, language: str = "te"):
        """
        Initialize Voice Engine
        
        Args:
            language: 'te' for Telugu, 'en' for English
        """
        self.language = language
        self.config = VoiceConfig.LANGUAGES.get(language, VoiceConfig.LANGUAGES["en"])
        self.recognizer = sr.Recognizer()
        self.translator = Translator()
        self.is_listening = False
        self.tts_engine = None

        # Configure recognizer sensitivity
        self.recognizer.energy_threshold = VoiceConfig.ENERGY_THRESHOLD
        self.recognizer.dynamic_energy_threshold = True
        self.recognizer.pause_threshold = 0.8

        # Initialize offline TTS as fallback
        self._init_offline_tts()

        logger.info(f"Voice Engine initialized: {self.config['name']} ({self.config['native_name']})")

    def _init_offline_tts(self):
        """Initialize pyttsx3 as offline TTS fallback"""
        try:
            self.tts_engine = pyttsx3.init()
            self.tts_engine.setProperty('rate', VoiceConfig.VOICE_SPEED)
            self.tts_engine.setProperty('volume', 0.9)
            # Set English voice (pyttsx3 doesn't support Telugu well)
            voices = self.tts_engine.getProperty('voices')
            if voices:
                self.tts_engine.setProperty('voice', voices[0].id)
            logger.info("Offline TTS (pyttsx3) initialized")
        except Exception as e:
            logger.warning(f"Offline TTS init failed: {e}")
            self.tts_engine = None

    def listen(self, timeout: int = None) -> Optional[str]:
        """
        Listen for voice input and convert to text
        
        Args:
            timeout: Seconds to wait (default from config)
        
        Returns:
            Recognized text string or None if failed
        """
        timeout = timeout or VoiceConfig.VOICE_TIMEOUT
        
        console.print(Panel(
            f"🎤 [bold cyan]Listening in {self.config['name']}...[/bold cyan]\n"
            f"Speak now | Timeout: {timeout}s",
            border_style="cyan"
        ))

        try:
            with sr.Microphone() as source:
                # Adjust for ambient noise
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                self.is_listening = True

                audio = self.recognizer.listen(
                    source,
                    timeout=timeout,
                    phrase_time_limit=VoiceConfig.PHRASE_TIMEOUT
                )
                self.is_listening = False

            # Try Google Speech Recognition
            text = self.recognizer.recognize_google(
                audio,
                language=self.config["google_stt_code"]
            )
            
            console.print(f"✅ [green]Heard:[/green] {text}")
            logger.info(f"Voice recognized: '{text}' (language: {self.language})")
            return text

        except sr.WaitTimeoutError:
            console.print("⏱️ [yellow]Timeout - No speech detected[/yellow]")
            return None
        except sr.UnknownValueError:
            console.print("❓ [yellow]Could not understand speech[/yellow]")
            return None
        except sr.RequestError as e:
            console.print(f"🌐 [red]Google STT API error: {e}[/red]")
            return None
        except Exception as e:
            logger.error(f"Voice listen error: {e}")
            return None
        finally:
            self.is_listening = False

    def speak(self, text: str, language: str = None, use_gtts: bool = True):
        """
        Convert text to speech
        
        Args:
            text: Text to speak
            language: Override language ('te' or 'en')
            use_gtts: Use Google TTS (online) vs pyttsx3 (offline)
        """
        lang = language or self.language
        lang_code = VoiceConfig.LANGUAGES[lang]["gtts_code"]

        console.print(f"🔊 [bold magenta]Speaking ({lang}):[/bold magenta] {text[:80]}...")
        logger.info(f"TTS output: '{text[:50]}...' (lang: {lang})")

        if use_gtts:
            self._speak_gtts(text, lang_code)
        else:
            self._speak_offline(text)

    def _speak_gtts(self, text: str, lang_code: str):
        """Speak using Google TTS (online, supports Telugu)"""
        try:
            # Generate audio
            tts = gTTS(text=text, lang=lang_code, slow=False)
            
            # Save to temp file and play
            with tempfile.NamedTemporaryFile(suffix=".mp3", delete=False) as fp:
                tts.save(fp.name)
                temp_path = fp.name

            # Play audio
            os.system(f"mpg321 {temp_path} -q 2>/dev/null || "
                     f"ffplay -nodisp -autoexit {temp_path} 2>/dev/null || "
                     f"mpg123 {temp_path} 2>/dev/null")
            
            os.unlink(temp_path)  # Cleanup

        except Exception as e:
            logger.warning(f"gTTS failed: {e}, falling back to offline TTS")
            self._speak_offline(text)

    def _speak_offline(self, text: str):
        """Speak using pyttsx3 (offline, English only)"""
        if self.tts_engine:
            try:
                self.tts_engine.say(text)
                self.tts_engine.runAndWait()
            except Exception as e:
                logger.error(f"Offline TTS error: {e}")
        else:
            console.print(f"💬 [dim](<No audio output available>)[/dim]")

    def translate(self, text: str, src: str = "auto", dest: str = "en") -> str:
        """
        Translate text between Telugu and English
        
        Args:
            text: Input text
            src: Source language code ('te', 'en', 'auto')
            dest: Destination language code ('te', 'en')
        
        Returns:
            Translated text string
        """
        try:
            result = self.translator.translate(text, src=src, dest=dest)
            return result.text
        except Exception as e:
            logger.error(f"Translation error: {e}")
            return text  # Return original if translation fails

    def detect_language(self, text: str) -> str:
        """
        Detect if text is Telugu or English
        
        Returns:
            'te' or 'en'
        """
        try:
            detected = self.translator.detect(text)
            lang = detected.lang
            return "te" if lang == "te" else "en"
        except:
            # Heuristic: check for Telugu Unicode characters
            telugu_chars = sum(1 for c in text if '\u0c00' <= c <= '\u0c7f')
            return "te" if telugu_chars > 2 else "en"

    def process_bilingual_command(self, text: str) -> Tuple[str, str]:
        """
        Process a command in either language and return (english_text, original_lang)
        
        Args:
            text: Voice command (Telugu or English)
        
        Returns:
            Tuple of (english_version, detected_language)
        """
        detected_lang = self.detect_language(text)
        
        if detected_lang == "te":
            # Translate Telugu to English for processing
            english_text = self.translate(text, src="te", dest="en")
            console.print(f"🔄 Telugu → English: [cyan]{english_text}[/cyan]")
            return english_text, "te"
        else:
            return text, "en"

    def greet(self):
        """Speak a greeting in configured language"""
        greetings = self.config["greetings"]
        greeting = greetings[0]
        self.speak(greeting)

    def announce_threat(self, threat_name: str, severity: str):
        """Announce a detected threat"""
        if self.language == "te":
            msg = f"హెచ్చరిక! {severity} తీవ్రత ముప్పు కనుగొనబడింది: {threat_name}"
        else:
            msg = f"Warning! {severity} severity threat detected: {threat_name}"
        
        self.speak(msg)

    def set_language(self, language: str):
        """Switch language dynamically"""
        if language in VoiceConfig.LANGUAGES:
            self.language = language
            self.config = VoiceConfig.LANGUAGES[language]
            console.print(f"🌐 Language switched to: [bold]{self.config['name']}[/bold]")
        else:
            logger.warning(f"Unsupported language: {language}")