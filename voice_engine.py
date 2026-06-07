import speech_recognition as sr
import pyttsx3
from gtts import gTTS
import os, tempfile, pygame, time

class VoiceEngine:
    def __init__(self, language='en', lang=None):
        self.lang = lang or language
        self.language = self.lang
        self.config = {
            'name': 'Smart Cybersecurity Assistant',
            'native_name': 'స్మార్ట్ సైబర్ అసిస్టెంట్',
            'version': '1.0.0',
            'language': self.lang,
            'voice_enabled': True,
        }
        self.recognizer = sr.Recognizer()
        # VirtualBox optimized settings
        self.recognizer.energy_threshold = 300
        self.recognizer.dynamic_energy_threshold = False
        self.recognizer.pause_threshold = 1.0
        self.recognizer.phrase_threshold = 0.3
        self.recognizer.non_speaking_duration = 0.5
        pygame.mixer.init()
        try:
            self.engine = pyttsx3.init()
            self.engine.setProperty('rate', 150)
        except:
            self.engine = None
        self._find_mic()

    def _find_mic(self):
        """Find and display available microphones."""
        mics = sr.Microphone.list_microphone_names()
        print(f"\n[MIC] Found {len(mics)} audio device(s):")
        for i, m in enumerate(mics):
            print(f"  [{i}] {m}")
        self.mic_index = None
        # Auto-select best mic
        for i, m in enumerate(mics):
            if 'default' in m.lower():
               self.mic_index = i
                print(f"[MIC] Selected: [{i}] {m}")
                break
        if self.mic_index is None:
            self.mic_index = 0
            print(f"[MIC] Using default: {mics[0]}")
        print()

    def speak(self, text):
        print(f"\n\033[92m[Assistant]: {text}\033[0m\n")
        try:
            tts = gTTS(text=text, lang=self.lang, slow=False)
            tmp = tempfile.mktemp(suffix='.mp3')
            tts.save(tmp)
            pygame.mixer.music.load(tmp)
            pygame.mixer.music.play()
            while pygame.mixer.music.get_busy():
                time.sleep(0.1)
            os.remove(tmp)
        except Exception as e:
            if self.engine:
                self.engine.say(text)
                self.engine.runAndWait()

    def listen(self):
        print("\033[96m[Listening...] Speak now:\033[0m")
        try:
            mic = sr.Microphone(device_index=self.mic_index)
            with mic as source:
                print("[Adjusting for noise...]")
                self.recognizer.adjust_for_ambient_noise(source, duration=1)
                print(f"[Energy threshold: {self.recognizer.energy_threshold:.0f}]")
                print("[GO! Speak now...]")
                audio = self.recognizer.listen(
                    source,
                    timeout=8,
                    phrase_time_limit=15
                )
            print("[Processing speech...]")
            lang_code = 'te-IN' if self.lang == 'te' else 'en-US'
            text = self.recognizer.recognize_google(
                audio, language=lang_code
            )
            print(f"\033[93m[You said]: {text}\033[0m")
            return text.strip()
        except sr.WaitTimeoutError:
            print("\033[91m[Timeout] No speech detected\033[0m")
            print("→ Check: Devices → Audio → Enable Audio Input in VirtualBox")
            return self._type_fallback()
        except sr.UnknownValueError:
            print("\033[91m[Could not understand audio]\033[0m")
            return self._type_fallback()
        except sr.RequestError as e:
            print(f"\033[91m[Google STT Error]: {e}\033[0m")
            return self._type_fallback()
        except Exception as e:
            print(f"\033[91m[Mic Error]: {e}\033[0m")
            return self._type_fallback()

    def _type_fallback(self):
        """Allow typing when voice fails."""
        print("\033[93m[Type mode] Voice failed — type your command:\033[0m")
        try:
            return input("  ⌨ You: ").strip()
        except:
            return ""

    def greet(self):
        msg = ("Smart Cybersecurity Assistant activated. "
               "Say scan, analyze logs, explain command, or ask anything.")
        self.speak(msg)

    def get_command(self):
        return self.listen()

    def respond(self, text):
        self.speak(text)

    def farewell(self):
        self.speak("Goodbye! Stay secure.")

    def confirm(self, question):
        self.speak(question + " Say yes or no.")
        response = self.listen()
        return 'yes' in response.lower()

    def announce(self, title, message):
        self.speak(f"{title}. {message}")

    def set_language(self, lang):
        self.lang = lang
        self.language = lang
        self.config['language'] = lang
        name = 'Telugu' if lang == 'te' else 'English'
        print(f"[Language: {name}]")
# PATCH - overwrite _find_mic
