from app import app
import pytest
import time

def test_rate_limit():
    """Test that VT rate limiting is enforced"""
    with app.test_client() as client:
        # Make multiple requests quickly
        start_time = time.time()
        responses = []
        for _ in range(5):  # Should trigger rate limit (>4/min)
            response = client.get('/api/v1/domain/example.com')
            responses.append(response)
        end_time = time.time()
        
        # Check that we got some responses and some rate limits
        assert any(r.status_code == 200 for r in responses), "Should get some successful responses"
        # Verify it took appropriate time (>60s) for rate-limited requests
        assert end_time - start_time >= 60, "Rate limiting should enforce delays"

def test_cache_behavior():
    """Test that caching works as expected"""
    with app.test_client() as client:
        # First request - should be slow (no cache)
        start = time.time()
        resp1 = client.get('/api/v1/domain/example.com')
        time1 = time.time() - start
        
        # Second request - should be fast (cached)
        start = time.time()
        resp2 = client.get('/api/v1/domain/example.com')
        time2 = time.time() - start
        
        assert resp1.status_code == resp2.status_code == 200
        assert time2 < time1, "Cached response should be faster"
        
        # Force refresh should bypass cache
        resp3 = client.post('/api/v1/refresh/domain/example.com')
        assert resp3.status_code == 200
        
        # Verify data was refreshed
        resp4 = client.get('/api/v1/domain/example.com')
        assert resp4.status_code == 200
        # Could also verify timestamps differ