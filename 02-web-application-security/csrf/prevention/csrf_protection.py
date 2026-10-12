#!/usr/bin/env python3
"""
CSRF protection: signed, session-bound tokens plus Origin checking
Location: 02-web-application-security/csrf/prevention/csrf_protection.py

Framework-free building blocks:

  CSRFProtector.generate_token(session_id)  -> token to embed in a hidden form field or header
  CSRFProtector.validate(session_id, token) -> True only for a fresh token made for THIS session
  check_origin(headers, allowed_origins)     -> Origin/Referer check for state-changing requests

Token = nonce.timestamp.HMAC-SHA256(secret, session_id|nonce|timestamp).
Because the HMAC covers the session id, a token stolen from one session is useless in another, and
nothing has to be stored server-side. Comparison is constant-time.

Use it with: SameSite=Lax/Strict cookies, tokens on every POST/PUT/PATCH/DELETE, and never
change state on GET requests.

Flask example:
    protector = CSRFProtector(app.secret_key)
    @app.before_request
    def csrf_check():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            if not (check_origin(request.headers, {"https://app.example.com"})
                    and protector.validate(session["sid"], token)):
                abort(403)
"""

import hashlib
import hmac
import secrets
import time
from urllib.parse import urlsplit


class CSRFProtector:
    def __init__(self, secret, ttl_seconds=3600):
        if isinstance(secret, str):
            secret = secret.encode()
        if len(secret) < 16:
            raise ValueError("secret must be at least 16 bytes")
        self.secret = secret
        self.ttl = ttl_seconds

    def _mac(self, session_id, nonce, timestamp):
        message = f"{session_id}|{nonce}|{timestamp}".encode()
        return hmac.new(self.secret, message, hashlib.sha256).hexdigest()

    def generate_token(self, session_id, now=None):
        nonce = secrets.token_urlsafe(16)
        timestamp = str(int(now if now is not None else time.time()))
        return f"{nonce}.{timestamp}.{self._mac(session_id, nonce, timestamp)}"

    def validate(self, session_id, token, now=None):
        try:
            nonce, timestamp, mac = token.split(".")
            issued = int(timestamp)
        except (AttributeError, ValueError):
            return False
        current = now if now is not None else time.time()
        if not (0 <= current - issued <= self.ttl):
            return False
        return hmac.compare_digest(mac, self._mac(session_id, nonce, timestamp))


def check_origin(headers, allowed_origins):
    """Accept a request only if its Origin (or, failing that, Referer) is an allowed origin.
    Requests with neither header are rejected: browsers always send one on cross-site POSTs."""
    origin = headers.get("Origin")
    if not origin:
        referer = headers.get("Referer")
        if not referer:
            return False
        parts = urlsplit(referer)
        origin = f"{parts.scheme}://{parts.netloc}"
    return origin in allowed_origins


if __name__ == "__main__":
    demo = CSRFProtector("demo-secret-change-me-please")
    token = demo.generate_token("session-123")
    print("token:", token)
    print("valid for the same session  :", demo.validate("session-123", token))
    print("valid for another session   :", demo.validate("session-999", token))
    print("valid after expiry          :", demo.validate("session-123", token, now=time.time() + 7200))
    print("origin ok / evil            :", check_origin({"Origin": "https://app.example.com"}, {"https://app.example.com"}),
          check_origin({"Origin": "https://evil.example"}, {"https://app.example.com"}))
