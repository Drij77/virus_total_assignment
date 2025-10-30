"""
Database Models
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, JSON
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class DomainReport(db.Model):
    """Store VirusTotal domain reports"""
    __tablename__ = 'domain_reports'

    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    reputation = Column(Integer)
    harmless = Column(Integer)
    malicious = Column(Integer)
    suspicious = Column(Integer)
    undetected = Column(Integer)
    categories = Column(JSON)
    last_analysis_date = Column(DateTime)
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'domain': self.domain,
            'reputation': self.reputation,
            'stats': {
                'harmless': self.harmless,
                'malicious': self.malicious,
                'suspicious': self.suspicious,
                'undetected': self.undetected
            },
            'categories': self.categories,
            'last_analysis_date': self.last_analysis_date.isoformat() if self.last_analysis_date else None,
            'updated_at': self.updated_at.isoformat()
        }


class IPReport(db.Model):
    """Store VirusTotal IP address reports"""
    __tablename__ = 'ip_reports'

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), unique=True, nullable=False, index=True)  # IPv6 support
    reputation = Column(Integer)
    harmless = Column(Integer)
    malicious = Column(Integer)
    suspicious = Column(Integer)
    undetected = Column(Integer)
    country = Column(String(2))
    asn = Column(Integer)
    as_owner = Column(String(255))
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'reputation': self.reputation,
            'stats': {
                'harmless': self.harmless,
                'malicious': self.malicious,
                'suspicious': self.suspicious,
                'undetected': self.undetected
            },
            'country': self.country,
            'asn': self.asn,
            'as_owner': self.as_owner,
            'updated_at': self.updated_at.isoformat()
        }


class FileReport(db.Model):
    """Store VirusTotal file hash reports"""
    __tablename__ = 'file_reports'

    id = Column(Integer, primary_key=True)
    file_hash = Column(String(64), unique=True, nullable=False, index=True)
    hash_type = Column(String(10))  # md5, sha1, sha256
    meaningful_name = Column(String(255))
    size = Column(Integer)
    type_description = Column(String(255))
    harmless = Column(Integer)
    malicious = Column(Integer)
    suspicious = Column(Integer)
    undetected = Column(Integer)
    raw_data = Column(JSON)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'file_hash': self.file_hash,
            'hash_type': self.hash_type,
            'name': self.meaningful_name,
            'size': self.size,
            'type': self.type_description,
            'stats': {
                'harmless': self.harmless,
                'malicious': self.malicious,
                'suspicious': self.suspicious,
                'undetected': self.undetected
            },
            'updated_at': self.updated_at.isoformat()
        }


class APIRateLimit(db.Model):
    """Track API rate limiting"""
    __tablename__ = 'api_rate_limits'

    id = Column(Integer, primary_key=True)
    minute_timestamp = Column(DateTime, nullable=False, index=True)
    request_count = Column(Integer, default=0)
