"""
Database Models for Smart Cybersecurity Assistant
ORM: SQLAlchemy with SQLite (dev) / PostgreSQL (prod)
"""

from datetime import datetime
from web import db


class ThreatRecord(db.Model):
    """Stores all detected threats"""
    __tablename__ = 'threat_records'

    id          = db.Column(db.Integer, primary_key=True)
    threat_id   = db.Column(db.String(50), unique=True, nullable=False)
    threat_type = db.Column(db.String(100), nullable=False)
    severity    = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text)
    source_ip   = db.Column(db.String(45))
    affected_port = db.Column(db.Integer)
    evidence    = db.Column(db.Text)
    mitre_technique = db.Column(db.String(200))
    is_resolved = db.Column(db.Boolean, default=False)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)

    def to_dict(self):
        return {
            "id": self.id,
            "threat_id": self.threat_id,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "description": self.description,
            "source_ip": self.source_ip,
            "affected_port": self.affected_port,
            "mitre_technique": self.mitre_technique,
            "is_resolved": self.is_resolved,
            "created_at": self.created_at.isoformat(),
        }


class LogEntry(db.Model):
    """Stores analyzed log entries"""
    __tablename__ = 'log_entries'

    id          = db.Column(db.Integer, primary_key=True)
    log_source  = db.Column(db.String(100))     # auth.log, syslog, etc.
    level       = db.Column(db.String(20))       # INFO, WARNING, CRITICAL
    message     = db.Column(db.Text)
    source_ip   = db.Column(db.String(45))
    username    = db.Column(db.String(100))
    is_suspicious = db.Column(db.Boolean, default=False)
    event_time  = db.Column(db.DateTime)
    recorded_at = db.Column(db.DateTime, default=datetime.utcnow)


class CommandHistory(db.Model):
    """Records all executed commands"""
    __tablename__ = 'command_history'

    id          = db.Column(db.Integer, primary_key=True)
    command     = db.Column(db.Text, nullable=False)
    risk_level  = db.Column(db.String(20))
    stdout      = db.Column(db.Text)
    stderr      = db.Column(db.Text)
    return_code = db.Column(db.Integer)
    executed    = db.Column(db.Boolean, default=False)
    executed_at = db.Column(db.DateTime, default=datetime.utcnow)


class AIConversation(db.Model):
    """Stores AI chat history"""
    __tablename__ = 'ai_conversations'

    id          = db.Column(db.Integer, primary_key=True)
    question    = db.Column(db.Text)
    answer      = db.Column(db.Text)
    language    = db.Column(db.String(5))      # 'te' or 'en'
    session_id  = db.Column(db.String(50))
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)