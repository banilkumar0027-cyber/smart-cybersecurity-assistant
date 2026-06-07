"""Unit tests for Voice Engine"""
import unittest
from unittest.mock import patch, MagicMock
from core.voice_engine import VoiceEngine


class TestVoiceEngine(unittest.TestCase):

    def setUp(self):
        """Set up test fixtures"""
        with patch('core.voice_engine.pyttsx3.init') as mock_pyttsx3:
            mock_pyttsx3.return_value = MagicMock()
            self.voice_te = VoiceEngine(language="te")
            self.voice_en = VoiceEngine(language="en")

    def test_language_initialization(self):
        """Test language configuration"""
        self.assertEqual(self.voice_te.language, "te")
        self.assertEqual(self.voice_en.language, "en")
        self.assertEqual(self.voice_te.config["name"], "Telugu")
        self.assertEqual(self.voice_en.config["name"], "English")

    def test_detect_language_telugu(self):
        """Test Telugu language detection"""
        telugu_text = "నమస్కారం, నేను తెలుగులో మాట్లాడుతున్నాను"
        with patch.object(self.voice_te.translator, 'detect') as mock_detect:
            mock_detect.return_value = MagicMock(lang='te')
            result = self.voice_te.detect_language(telugu_text)
            self.assertEqual(result, "te")

    def test_detect_language_english(self):
        """Test English language detection"""
        english_text = "Hello, I am speaking in English"
        with patch.object(self.voice_en.translator, 'detect') as mock_detect:
            mock_detect.return_value = MagicMock(lang='en')
            result = self.voice_en.detect_language(english_text)
            self.assertEqual(result, "en")

    def test_set_language(self):
        """Test dynamic language switching"""
        self.voice_te.set_language("en")
        self.assertEqual(self.voice_te.language, "en")

    def test_bilingual_processing(self):
        """Test bilingual command processing"""
        with patch.object(self.voice_te, 'detect_language', return_value='en'):
            text, lang = self.voice_te.process_bilingual_command("scan ports")
            self.assertEqual(lang, "en")


class TestThreatDetector(unittest.TestCase):

    def setUp(self):
        from core.threat_detector import ThreatDetector
        self.detector = ThreatDetector()

    def test_threat_alert_creation(self):
        from core.threat_detector import ThreatAlert
        alert = ThreatAlert(
            threat_type="BRUTE_FORCE",
            severity="HIGH",
            description="Test alert",
            source_ip="192.168.1.100",
        )
        self.assertEqual(alert.threat_type, "BRUTE_FORCE")
        self.assertEqual(alert.severity, "HIGH")
        self.assertIsNotNone(alert.id)

    def test_threat_to_dict(self):
        from core.threat_detector import ThreatAlert
        alert = ThreatAlert(
            threat_type="PORT_SCAN",
            severity="MEDIUM",
            description="Port scan detected",
        )
        d = alert.to_dict()
        self.assertIn("threat_type", d)
        self.assertIn("severity", d)
        self.assertIn("timestamp", d)


class TestLinuxAssistant(unittest.TestCase):

    def setUp(self):
        from core.linux_assistant import LinuxAssistant
        self.assistant = LinuxAssistant()

    def test_risk_assessment_safe(self):
        from core.linux_assistant import CommandRiskChecker
        risk, reason = CommandRiskChecker.assess_risk("ls -la /tmp")
        self.assertEqual(risk, "safe")

    def test_risk_assessment_dangerous(self):
        from core.linux_assistant import CommandRiskChecker
        risk, reason = CommandRiskChecker.assess_risk("rm -rf /")
        self.assertEqual(risk, "blocked")

    def test_command_suggestions(self):
        suggestions = self.assistant.suggest_commands("find open ports")
        self.assertIsInstance(suggestions, list)
        self.assertGreater(len(suggestions), 0)
        # Should suggest nmap-related commands
        all_cmds = " ".join(suggestions).lower()
        self.assertIn("nmap", all_cmds)


if __name__ == '__main__':
    unittest.main(verbosity=2)