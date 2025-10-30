
"""
VirusTotal Data Pipeline Challenge
Complete solution with API integration, caching, and REST API
"""

import os
import time
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from functools import wraps
from dotenv import load_dotenv
import requests
import redis
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_caching import Cache
from flask_migrate import Migrate
from flask_swagger_ui import get_swaggerui_blueprint
from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean, select
from sqlalchemy.exc import IntegrityError
load_dotenv()

app = Flask(__name__)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'postgresql://localhost/virustotal_db'  
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


cache_type = os.getenv('CACHE_TYPE', 'RedisCache')
app.config['CACHE_TYPE'] = cache_type
app.config['CACHE_REDIS_URL'] = os.getenv('REDIS_URL', 'redis://localhost:6379/0')


if 'redis' in (cache_type or '').lower():
    try:
        import redis  # noqa: F401
    except Exception:
        print("Warning: 'redis' Python package not found. Falling back to SimpleCache.\nInstall it with: pip install redis")
        app.config['CACHE_TYPE'] = 'SimpleCache'

cache = Cache(app)

# VirusTotal API Configuration
VT_API_KEY = os.getenv('VT_API_KEY', 'your_api_key_here')
VT_API_BASE = 'https://www.virustotal.com/api/v3'
# Allow overriding the VirusTotal requests-per-minute limit via environment.
try:
    VT_RATE_LIMIT = int(os.getenv('VT_RATE_LIMIT', '4'))
except Exception:
    print("Warning: invalid VT_RATE_LIMIT environment value; falling back to 4")
    VT_RATE_LIMIT = 4  # requests per minute for free tier

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
cache = Cache(app)

# Configure Swagger UI
SWAGGER_URL = '/api/docs'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={'app_name': "VirusTotal Data Pipeline API"}
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Redis client for rate limiting (separate from cache)
redis_client = redis.from_url(os.getenv('REDIS_URL', 'redis://localhost:6379/0'))

# ============================================================================
# DATABASE MODELS
# ============================================================================

from models import DomainReport, IPReport, FileReport, APIRateLimit


# ============================================================================
# VIRUSTOTAL API CLIENT
# ============================================================================

class VirusTotalClient:
    """VirusTotal API client with rate limiting"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = VT_API_BASE
        self.headers = {
            'x-apikey': api_key,
            'Accept': 'application/json'
        }
    
    def _rate_limit_check(self):
        """Check and enforce rate limiting using Redis atomic counters"""
        current_minute = datetime.utcnow().replace(second=0, microsecond=0)
        key = f"vt_rate:{current_minute.isoformat()}"
        
        try:
            # Atomic increment and get
            pipe = redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, 65)  # 65 seconds to handle clock skew
            result = pipe.execute()
            count = result[0]
            
            if count > VT_RATE_LIMIT:
                # Log rate limit hit
                logging.warning(f"Rate limit exceeded: {count} requests in minute {current_minute}")
                # Wait until next minute
                wait_time = 60 - datetime.utcnow().second
                time.sleep(wait_time + 1)
                return self._rate_limit_check()
            return True
            
        except redis.RedisError:
            # Fallback to DB-based limiting if Redis fails
            logging.warning("Redis rate limiting failed, falling back to DB")
            return self._db_rate_limit_check(current_minute)
    
    def _db_rate_limit_check(self, current_minute: datetime) -> bool:
        """Database-backed rate limiting with row locking"""
        try:
            # Use SELECT FOR UPDATE to prevent race conditions
            with db.session.begin():
                stmt = select(APIRateLimit).where(
                    APIRateLimit.minute_timestamp == current_minute
                ).with_for_update()
                
                rate_limit = db.session.execute(stmt).scalar_one_or_none()
                
                if not rate_limit:
                    rate_limit = APIRateLimit(
                        minute_timestamp=current_minute,
                        request_count=0
                    )
                    db.session.add(rate_limit)
                
                if rate_limit.request_count >= VT_RATE_LIMIT:
                    wait_time = 60 - datetime.utcnow().second
                    time.sleep(wait_time + 1)
                    return self._rate_limit_check()
                
                rate_limit.request_count += 1
                db.session.commit()
                
            return True
            
        except Exception as e:
            logging.error(f"DB rate limiting failed: {e}")
            # If both Redis and DB fail, enforce delay anyway
            time.sleep(15)  # Conservative delay
            return True
    
    def get_domain_report(self, domain: str) -> Optional[Dict]:
        """Fetch domain report from VirusTotal"""
        self._rate_limit_check()
        
        url = f"{self.base_url}/domains/{domain}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching domain report: {e}")
            return None
    
    def get_ip_report(self, ip_address: str) -> Optional[Dict]:
        """Fetch IP address report from VirusTotal"""
        self._rate_limit_check()
        
        url = f"{self.base_url}/ip_addresses/{ip_address}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching IP report: {e}")
            return None
    
    def get_file_report(self, file_hash: str) -> Optional[Dict]:
        """Fetch file hash report from VirusTotal"""
        self._rate_limit_check()
        
        url = f"{self.base_url}/files/{file_hash}"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None
            else:
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching file report: {e}")
            return None


# ============================================================================
# DATA INGESTION SERVICE
# ============================================================================

class DataIngestionService:
    """Service to ingest and store VirusTotal data"""
    
    def __init__(self, vt_client: VirusTotalClient):
        self.vt_client = vt_client
    
    def ingest_domain(self, domain: str, force_refresh: bool = False) -> Optional[DomainReport]:
        """Ingest domain report"""
        # Check if exists and is recent (unless force refresh)
        if not force_refresh:
            existing = DomainReport.query.filter_by(domain=domain).first()
            if existing and (datetime.utcnow() - existing.updated_at) < timedelta(hours=24):
                return existing
        
        # Fetch from VirusTotal
        data = self.vt_client.get_domain_report(domain)
        if not data:
            return None
        
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        # Create or update record
        report = DomainReport.query.filter_by(domain=domain).first()
        if not report:
            report = DomainReport(domain=domain)
        
        report.reputation = attributes.get('reputation', 0)
        report.harmless = stats.get('harmless', 0)
        report.malicious = stats.get('malicious', 0)
        report.suspicious = stats.get('suspicious', 0)
        report.undetected = stats.get('undetected', 0)
        report.categories = attributes.get('categories', {})
        
        last_analysis = attributes.get('last_analysis_date')
        if last_analysis:
            report.last_analysis_date = datetime.fromtimestamp(last_analysis)
        
        report.raw_data = data
        report.updated_at = datetime.utcnow()
        
        db.session.add(report)
        db.session.commit()
        
        # Invalidate cache
        cache.delete(f'domain_{domain}')
        
        return report
    
    def ingest_ip(self, ip_address: str, force_refresh: bool = False) -> Optional[IPReport]:
        """Ingest IP address report"""
        if not force_refresh:
            existing = IPReport.query.filter_by(ip_address=ip_address).first()
            if existing and (datetime.utcnow() - existing.updated_at) < timedelta(hours=24):
                return existing
        
        data = self.vt_client.get_ip_report(ip_address)
        if not data:
            return None
        
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        report = IPReport.query.filter_by(ip_address=ip_address).first()
        if not report:
            report = IPReport(ip_address=ip_address)
        
        report.reputation = attributes.get('reputation', 0)
        report.harmless = stats.get('harmless', 0)
        report.malicious = stats.get('malicious', 0)
        report.suspicious = stats.get('suspicious', 0)
        report.undetected = stats.get('undetected', 0)
        report.country = attributes.get('country')
        report.asn = attributes.get('asn')
        report.as_owner = attributes.get('as_owner')
        report.raw_data = data
        report.updated_at = datetime.utcnow()
        
        db.session.add(report)
        db.session.commit()
        
        cache.delete(f'ip_{ip_address}')
        
        return report
    
    def ingest_file(self, file_hash: str, force_refresh: bool = False) -> Optional[FileReport]:
        """Ingest file hash report"""
        if not force_refresh:
            existing = FileReport.query.filter_by(file_hash=file_hash).first()
            if existing and (datetime.utcnow() - existing.updated_at) < timedelta(hours=24):
                return existing
        
        data = self.vt_client.get_file_report(file_hash)
        if not data:
            return None
        
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        
        report = FileReport.query.filter_by(file_hash=file_hash).first()
        if not report:
            report = FileReport(file_hash=file_hash)
        
        # Determine hash type
        if len(file_hash) == 32:
            report.hash_type = 'md5'
        elif len(file_hash) == 40:
            report.hash_type = 'sha1'
        elif len(file_hash) == 64:
            report.hash_type = 'sha256'
        
        report.meaningful_name = attributes.get('meaningful_name')
        report.size = attributes.get('size')
        report.type_description = attributes.get('type_description')
        report.harmless = stats.get('harmless', 0)
        report.malicious = stats.get('malicious', 0)
        report.suspicious = stats.get('suspicious', 0)
        report.undetected = stats.get('undetected', 0)
        report.raw_data = data
        report.updated_at = datetime.utcnow()
        
        db.session.add(report)
        db.session.commit()
        
        cache.delete(f'file_{file_hash}')
        
        return report


# Initialize services
vt_client = VirusTotalClient(VT_API_KEY)
ingestion_service = DataIngestionService(vt_client)


# ============================================================================
# REST API ENDPOINTS
# ============================================================================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    })


@app.route('/api/v1/domain/<domain>', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=lambda: f"domain_{request.view_args['domain']}")
def get_domain(domain: str):
    """Get domain report"""
    report = DomainReport.query.filter_by(domain=domain).first()
    
    if not report:
        # Ingest if not found
        report = ingestion_service.ingest_domain(domain)
        if not report:
            return jsonify({'error': 'Domain not found'}), 404
    
    return jsonify({
        'success': True,
        'data': report.to_dict()
    })


@app.route('/api/v1/ip/<ip_address>', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=lambda: f"ip_{request.view_args['ip_address']}")
def get_ip(ip_address: str):
    """Get IP address report"""
    report = IPReport.query.filter_by(ip_address=ip_address).first()
    
    if not report:
        report = ingestion_service.ingest_ip(ip_address)
        if not report:
            return jsonify({'error': 'IP address not found'}), 404
    
    return jsonify({
        'success': True,
        'data': report.to_dict()
    })


@app.route('/api/v1/file/<file_hash>', methods=['GET'])
@cache.cached(timeout=3600, key_prefix=lambda: f"file_{request.view_args['file_hash']}")
def get_file(file_hash: str):
    """Get file hash report"""
    report = FileReport.query.filter_by(file_hash=file_hash).first()
    
    if not report:
        report = ingestion_service.ingest_file(file_hash)
        if not report:
            return jsonify({'error': 'File hash not found'}), 404
    
    return jsonify({
        'success': True,
        'data': report.to_dict()
    })


@app.route('/api/v1/refresh/domain/<domain>', methods=['POST'])
def refresh_domain(domain: str):
    """Force refresh domain report"""
    report = ingestion_service.ingest_domain(domain, force_refresh=True)
    
    if not report:
        return jsonify({'error': 'Failed to refresh domain report'}), 500
    
    return jsonify({
        'success': True,
        'message': 'Domain report refreshed',
        'data': report.to_dict()
    })


@app.route('/api/v1/refresh/ip/<ip_address>', methods=['POST'])
def refresh_ip(ip_address: str):
    """Force refresh IP report"""
    report = ingestion_service.ingest_ip(ip_address, force_refresh=True)
    
    if not report:
        return jsonify({'error': 'Failed to refresh IP report'}), 500
    
    return jsonify({
        'success': True,
        'message': 'IP report refreshed',
        'data': report.to_dict()
    })


@app.route('/api/v1/refresh/file/<file_hash>', methods=['POST'])
def refresh_file(file_hash: str):
    """Force refresh file report"""
    report = ingestion_service.ingest_file(file_hash, force_refresh=True)
    
    if not report:
        return jsonify({'error': 'Failed to refresh file report'}), 500
    
    return jsonify({
        'success': True,
        'message': 'File report refreshed',
        'data': report.to_dict()
    })


@app.route('/api/v1/stats', methods=['GET'])
def get_stats():
    """Get pipeline statistics"""
    return jsonify({
        'success': True,
        'data': {
            'total_domains': DomainReport.query.count(),
            'total_ips': IPReport.query.count(),
            'total_files': FileReport.query.count(),
            'malicious_domains': DomainReport.query.filter(DomainReport.malicious > 0).count(),
            'malicious_ips': IPReport.query.filter(IPReport.malicious > 0).count(),
            'malicious_files': FileReport.query.filter(FileReport.malicious > 0).count()
        }
    })


# ============================================================================
# DIAGNOSTICS ENDPOINTS
# ============================================================================

@app.route('/api/v1/diagnostics', methods=['GET'])
def get_diagnostics():
    """Get system diagnostics including cache and rate limit status"""
    # Get current rate limit counter
    current_minute = datetime.utcnow().replace(second=0, microsecond=0)
    rate_key = f"vt_rate:{current_minute.isoformat()}"
    
    try:
        current_rate = int(redis_client.get(rate_key) or 0)
        rate_ttl = redis_client.ttl(rate_key)
    except Exception:
        current_rate = None
        rate_ttl = None
    
    # Check a sample cache key
    cache_key = "domain_example.com"
    try:
        cache_ttl = cache.get_backend().ttl(cache_key)
    except Exception:
        cache_ttl = None
    
    return jsonify({
        'cache': {
            'type': app.config['CACHE_TYPE'],
            'backend': str(type(cache.cache)),
            'sample_key_ttl': cache_ttl
        },
        'rate_limit': {
            'limit': VT_RATE_LIMIT,
            'current_minute': current_minute.isoformat(),
            'current_count': current_rate,
            'ttl_seconds': rate_ttl
        },
        'db': {
            'uri': app.config['SQLALCHEMY_DATABASE_URI'].split('@')[-1],  # Hide credentials
            'total_reports': {
                'domains': DomainReport.query.count(),
                'ips': IPReport.query.count(),
                'files': FileReport.query.count()
            }
        }
    })

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

@app.cli.command()
def init_db():
    """Initialize the database"""
    db.create_all()
    print("Database initialized successfully!")


if __name__ == '__main__':
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    with app.app_context():
        db.create_all()
    app.run(debug=True, host='0.0.0.0', port=5000)