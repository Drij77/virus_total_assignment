# VirusTotal Data Pipeline

A Flask-based data pipeline that fetches data from the VirusTotal API, stores it in PostgreSQL, and provides a REST API with Redis caching.

## Features

- Fetches and stores VirusTotal reports for:
  - Domains
  - IP addresses
  - File hashes
- PostgreSQL persistence with SQLAlchemy models
- Redis caching for API responses
- Rate limiting (respects VT free tier limits)
- Refresh endpoints to force re-ingestion
- Docker Compose setup for Redis and Postgres

## Quick Start

1. **Clone and install dependencies**
```bash
# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

2. **Configure environment**
```bash
# Copy example env file and edit
copy .env.example .env
# Edit .env and add your VirusTotal API key
```

3. **Start Redis and PostgreSQL**
```bash
docker compose up -d
```

4. **Run the application**
```bash
python app.py
```

## API Endpoints

### Fetch Reports
- `GET /api/v1/domain/<domain>` - Get domain report
- `GET /api/v1/ip/<ip_address>` - Get IP address report
- `GET /api/v1/file/<file_hash>` - Get file hash report

### Force Refresh
- `POST /api/v1/refresh/domain/<domain>` - Re-fetch domain data
- `POST /api/v1/refresh/ip/<ip_address>` - Re-fetch IP data
- `POST /api/v1/refresh/file/<file_hash>` - Re-fetch file data

### Other
- `GET /health` - Health check endpoint
- `GET /api/v1/stats` - Pipeline statistics

## Configuration

Key environment variables (see .env.example for all options):

- `VT_API_KEY` - Your VirusTotal API key
- `VT_RATE_LIMIT` - API rate limit (default: 4 requests/minute for free tier)
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `CACHE_TYPE` - Cache backend ('RedisCache' or 'SimpleCache')

## Development

### Running Tests
```bash
pytest tests/
```

### Rate Limiting

The app respects VirusTotal's rate limits:
- Free tier: 4 requests per minute
- Set `VT_RATE_LIMIT` in .env to match your plan

### Caching

- Redis recommended for production (set `CACHE_TYPE=RedisCache`)
- Falls back to SimpleCache if Redis unavailable
- Default TTL: 1 hour
- Refresh endpoints invalidate cache