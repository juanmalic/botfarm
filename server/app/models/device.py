from app import db
from datetime import datetime
import json

class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(16), default='offline')  # online, offline, error
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relaciones
    tasks = db.relationship('Task', backref='device', lazy=True)
    social_accounts = db.relationship('SocialAccount', backref='device', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'device_id': self.device_id,
            'name': self.name,
            'status': self.status,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'created_at': self.created_at.isoformat()
        }
