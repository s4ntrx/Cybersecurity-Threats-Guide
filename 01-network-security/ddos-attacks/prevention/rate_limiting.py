#!/usr/bin/env python3
"""
Rate Limiting Implementation for DDoS Prevention
Location: 01-network-security/ddos-attacks/prevention/rate_limiting.py

This script demonstrates various rate limiting techniques to prevent DDoS attacks.
"""

import time
from collections import defaultdict, deque
import threading
import argparse
import logging
from datetime import datetime, timedelta
import redis
import hashlib
import re

class RateLimiter:
    """Base class for rate limiters"""
    
    def __init__(self, max_requests, time_window):
        """
        Initialize rate limiter
        
        Args:
            max_requests: Maximum requests allowed in time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        
    def is_allowed(self, key):
        """Check if request is allowed for given key"""
        raise NotImplementedError

class TokenBucketRateLimiter(RateLimiter):
    """
    Token Bucket Algorithm
    - Tokens added at constant rate
    - Each request consumes one token
    - If no tokens available, request is denied
    """
    
    def __init__(self, max_requests, time_window, refill_rate=None):
        super().__init__(max_requests, time_window)
        self.buckets = {}
        self.refill_rate = refill_rate or (max_requests / time_window)
        self.lock = threading.Lock()
        
    def _get_bucket(self, key):
        """Get or create token bucket for key"""
        if key not in self.buckets:
            self.buckets[key] = {
                'tokens': self.max_requests,
                'last_refill': time.time()
            }
        return self.buckets[key]
    
    def _refill_bucket(self, bucket):
        """Refill tokens based on elapsed time"""
        now = time.time()
        elapsed = now - bucket['last_refill']
        new_tokens = elapsed * self.refill_rate
        bucket['tokens'] = min(self.max_requests, bucket['tokens'] + new_tokens)
        bucket['last_refill'] = now
        
    def is_allowed(self, key):
        with self.lock:
            bucket = self._get_bucket(key)
            self._refill_bucket(bucket)
            
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                return True
            return False

class SlidingWindowRateLimiter(RateLimiter):
    """
    Sliding Window Log Algorithm
    - Maintains timestamp log of requests
    - Counts requests in current time window
    - More accurate but uses more memory
    """
    
    def __init__(self, max_requests, time_window):
        super().__init__(max_requests, time_window)
        self.requests = defaultdict(deque)
        self.lock = threading.Lock()
        
    def _clean_old_requests(self, key):
        """Remove requests outside current time window"""
        now = time.time()
        while self.requests[key] and self.requests[key][0] < now - self.time_window:
            self.requests[key].popleft()
            
    def is_allowed(self, key):
        with self.lock:
            self._clean_old_requests(key)
            
            if len(self.requests[key]) < self.max_requests:
                self.requests[key].append(time.time())
                return True
            return False

class FixedWindowRateLimiter(RateLimiter):
    """
    Fixed Window Counter Algorithm
    - Simple counter per time window
    - Can allow double the requests at boundaries
    """
    
    def __init__(self, max_requests, time_window):
        super().__init__(max_requests, time_window)
        self.counters = defaultdict(int)
        self.window_starts = {}
        self.lock = threading.Lock()
        
    def _get_current_window(self):
        """Get current window start time"""
        return int(time.time() / self.time_window) * self.time_window
        
    def is_allowed(self, key):
        with self.lock:
            current_window = self._get_current_window()
            
            # Reset counter if new window
            if key not in self.window_starts or self.window_starts[key] != current_window:
                self.counters[key] = 0
                self.window_starts[key] = current_window
            
            if self.counters[key] < self.max_requests:
                self.counters[key] += 1
                return True
            return False

class RedisRateLimiter(RateLimiter):
    """
    Distributed rate limiting using Redis
    Suitable for microservices and distributed systems
    """
    
    def __init__(self, max_requests, time_window, redis_host='localhost', redis_port=6379):
        super().__init__(max_requests, time_window)
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        
    def is_allowed(self, key):
        """Using Redis INCR with expiration"""
        pipe = self.redis_client.pipeline()
        now = time.time()
        key_name = f"rate_limit:{key}"
        
        # Clean old requests
        pipe.zremrangebyscore(key_name, 0, now - self.time_window)
        
        # Count requests in window
        pipe.zcard(key_name)
        
        # Add current request
        pipe.zadd(key_name, {str(now): now})
        pipe.expire(key_name, self.time_window)
        
        results = pipe.execute()
        request_count = results[1]  # zcard result
        
        return request_count < self.max_requests

class WebApplicationFirewall:
    """
    Web Application Firewall with rate limiting
    Demonstrates practical DDoS prevention
    """
    
    def __init__(self):
        self.rate_limiters = {
            'ip': TokenBucketRateLimiter(max_requests=100, time_window=60),
            'user': SlidingWindowRateLimiter(max_requests=50, time_window=60),
            'endpoint': FixedWindowRateLimiter(max_requests=500, time_window=60),
            'global': TokenBucketRateLimiter(max_requests=10000, time_window=60)
        }
        
        self.blocked_ips = set()
        self.request_log = []
        self.counters = {'allowed': 0, 'blocked': 0}
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('waf.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def get_client_ip(self, request):
        """Extract client IP from request (simulated)"""
        # In real implementation, get from request object
        return request.get('remote_addr', '127.0.0.1')
    
    def get_user_id(self, request):
        """Extract user ID from request (simulated)"""
        return request.get('user_id', 'anonymous')
    
    def get_endpoint(self, request):
        """Extract endpoint from request (simulated)"""
        return request.get('path', '/')
    
    def is_malicious(self, request):
        """Check for malicious patterns"""
        # Inspect the VALUES of the request. (str(request) of a dict always contains
        # apostrophes, so the old check flagged every request as SQL injection.)
        values = ' '.join(str(v) for v in request.values())

        sql_patterns = {
            'quote followed by OR/AND': r"'\s*(or|and)\s+\S",
            'OR 1=1': r"\bor\s+1\s*=\s*1\b",
            'UNION SELECT': r"\bunion\s+(all\s+)?select\b",
            'DROP TABLE': r"\bdrop\s+table\b",
            'comment terminator': r"'\s*(--|#|/\*)",
        }
        for label, pattern in sql_patterns.items():
            if re.search(pattern, values, re.IGNORECASE):
                return True, f"SQL injection pattern: {label}"

        xss_patterns = {'<script': r"<\s*script", 'javascript:': r"javascript\s*:", 'onerror=': r"onerror\s*="}
        for label, pattern in xss_patterns.items():
            if re.search(pattern, values, re.IGNORECASE):
                return True, f"XSS pattern: {label}"

        return False, "Clean"
    
    def process_request(self, request):
        """Process incoming request with rate limiting and security checks"""
        client_ip = self.get_client_ip(request)
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            self.logger.warning(f"Blocked request from {client_ip} (IP blocked)")
            self.counters['blocked'] += 1
            return False, "IP is blocked"
        
        # Check for malicious content
        is_malicious, reason = self.is_malicious(request)
        if is_malicious:
            self.logger.error(f"Malicious request from {client_ip}: {reason}")
            self.blocked_ips.add(client_ip)
            self.counters['blocked'] += 1
            return False, f"Malicious request detected: {reason}"
        
        # Apply rate limiting
        limits = [
            (self.rate_limiters['ip'].is_allowed(client_ip), "IP rate limit exceeded"),
            (self.rate_limiters['user'].is_allowed(self.get_user_id(request)), "User rate limit exceeded"),
            (self.rate_limiters['endpoint'].is_allowed(self.get_endpoint(request)), "Endpoint rate limit exceeded"),
            (self.rate_limiters['global'].is_allowed("global"), "Global rate limit exceeded")
        ]
        
        for allowed, message in limits:
            if not allowed:
                self.logger.warning(f"Rate limit: {message} for {client_ip}")
                self.counters['blocked'] += 1
                return False, message
        
        # Request allowed
        self.logger.info(f"Request allowed from {client_ip}")
        self.counters['allowed'] += 1
        self.request_log.append({
            'timestamp': datetime.now().isoformat(),
            'ip': client_ip,
            'path': self.get_endpoint(request),
            'user': self.get_user_id(request)
        })
        
        return True, "Request allowed"
    
    def get_stats(self):
        """Get WAF statistics"""
        return {
            'total_requests': self.counters['allowed'] + self.counters['blocked'],
            'allowed_requests': self.counters['allowed'],
            'blocked_requests': self.counters['blocked'],
            'blocked_ips': len(self.blocked_ips),
            'active_rate_limiters': {
                'ip': len(self.rate_limiters['ip'].buckets),
                'user': len(self.rate_limiters['user'].requests),
                'endpoint': len(self.rate_limiters['endpoint'].counters)
            }
        }

def demonstrate_rate_limiting():
    """Demonstrate rate limiting in action"""
    print("\n📊 Rate Limiting Demonstration")
    print("="*60)
    
    # Test different rate limiters
    limiters = [
        ("Token Bucket", TokenBucketRateLimiter(5, 10)),
        ("Sliding Window", SlidingWindowRateLimiter(5, 10)),
        ("Fixed Window", FixedWindowRateLimiter(5, 10))
    ]
    
    for name, limiter in limiters:
        print(f"\n{name} Rate Limiter:")
        print("-" * 30)
        
        key = "test_user"
        for i in range(10):
            allowed = limiter.is_allowed(key)
            status = "✅" if allowed else "❌"
            print(f"  Request {i+1:2d}: {status}")
            time.sleep(0.5)  # Simulate request间隔
    
    # Demonstrate WAF
    print("\n🛡️ Web Application Firewall Demo")
    print("="*60)
    
    waf = WebApplicationFirewall()
    
    # Simulate normal requests
    normal_requests = [
        {'remote_addr': '192.168.1.100', 'path': '/home', 'user_id': 'user1'},
        {'remote_addr': '192.168.1.101', 'path': '/api/data', 'user_id': 'user2'},
        {'remote_addr': '192.168.1.102', 'path': '/login', 'user_id': 'user3'}
    ]
    
    # Simulate malicious requests
    malicious_requests = [
        {'remote_addr': '10.0.0.1', 'path': '/search?q=" OR 1=1--', 'user_id': 'attacker1'},
        {'remote_addr': '10.0.0.2', 'path': '/comment', 'user_id': 'attacker2', 'data': '<script>alert(1)</script>'},
        {'remote_addr': '10.0.0.3', 'path': '/api', 'user_id': 'attacker3'}
    ]
    
    # Simulate DDoS attack (many requests from same IP)
    ddos_requests = [
        {'remote_addr': '192.168.1.200', 'path': '/api/data', 'user_id': 'user4'}
        for _ in range(150)  # 150 requests from same IP
    ]
    
    print("\n[1] Testing normal requests:")
    for req in normal_requests:
        allowed, message = waf.process_request(req)
        print(f"  {req['remote_addr']}: {message}")
    
    print("\n[2] Testing malicious requests:")
    for req in malicious_requests:
        allowed, message = waf.process_request(req)
        print(f"  {req['remote_addr']}: {message}")
    
    print("\n[3] Simulating DDoS attack (150 requests from same IP):")
    for i, req in enumerate(ddos_requests[:10]):  # Show first 10 for brevity
        allowed, message = waf.process_request(req)
        print(f"  Request {i+1}: {message}")
    
    # Show statistics
    stats = waf.get_stats()
    print(f"\n📈 WAF Statistics:")
    print(f"  Total requests: {stats['total_requests']}")
    print(f"  Blocked IPs: {stats['blocked_ips']}")
    print(f"  Active rate limiters: {stats['active_rate_limiters']}")

def main():
    parser = argparse.ArgumentParser(description='Rate Limiting for DDoS Prevention')
    parser.add_argument('--demo', action='store_true', help='Run demonstration')
    parser.add_argument('--test-ip', help='Test specific IP with rate limiter')
    parser.add_argument('--requests', type=int, default=20, help='Number of test requests')
    
    args = parser.parse_args()
    
    print("""
    ╔═══════════════════════════════════════╗
    ║     Rate Limiting for DDoS Prevention  ║
    ║         FOR EDUCATIONAL USE ONLY       ║
    ╚═══════════════════════════════════════╝
    """)
    
    if args.demo:
        demonstrate_rate_limiting()
    elif args.test_ip:
        limiter = TokenBucketRateLimiter(10, 60)  # 10 requests per minute
        print(f"\nTesting rate limiting for IP: {args.test_ip}")
        print("-" * 40)
        
        allowed = 0
        denied = 0
        
        for i in range(args.requests):
            if limiter.is_allowed(args.test_ip):
                allowed += 1
                status = "✅ ALLOWED"
            else:
                denied += 1
                status = "❌ DENIED"
            print(f"Request {i+1:2d}: {status}")
            time.sleep(1)  # 1 second间隔
        
        print(f"\nSummary: {allowed} allowed, {denied} denied")
    else:
        print("Use --demo for demonstration or --test-ip <IP> for testing")

if __name__ == "__main__":
    main()
