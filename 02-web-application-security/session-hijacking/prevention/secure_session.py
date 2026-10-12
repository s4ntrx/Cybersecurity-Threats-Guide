#!/usr/bin/env python3
"""
Secure server-side session manager
Location: 02-web-application-security/session-hijacking/prevention/secure_session.py

Defences against session hijacking and fixation, in one small class:

  * 256-bit random session ids from the OS CSPRNG (`secrets`), never guessable
  * only a SHA-256 hash of each id is stored, so a leaked session table cannot be replayed
  * a NEW id is issued at login (`rotate`), which defeats session fixation
  * idle timeout and absolute timeout
  * the session is tied to a hash of the User-Agent (and optionally the client IP network)
  * logout and "log out everywhere" really destroy the server-side session
  * cookie attributes are generated for you: __Host- prefix, Secure, HttpOnly, SameSite

This is an in-memory teaching version; production code should keep the same logic in Redis or a
database, and always serve over HTTPS.
"""

import hashlib
import secrets
import time

COOKIE_NAME = "__Host-session"          # __Host- forces Secure, Path=/ and no Domain attribute


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class SessionManager:
    def __init__(self, idle_timeout=900, absolute_timeout=28800, bind_ip_prefix=False):
        self.idle_timeout = idle_timeout
        self.absolute_timeout = absolute_timeout
        self.bind_ip_prefix = bind_ip_prefix
        self._sessions = {}                 # sha256(session id) -> record

    @staticmethod
    def _ip_prefix(ip):
        return ".".join(ip.split(".")[:3]) if "." in ip else ip.rsplit(":", 4)[0]

    def create(self, user_id, user_agent, ip, now=None):
        session_id = secrets.token_urlsafe(32)
        now = now if now is not None else time.time()
        self._sessions[_hash(session_id)] = {
            "user": user_id, "created": now, "last_seen": now,
            "ua": _hash(user_agent), "net": self._ip_prefix(ip),
        }
        return session_id

    def validate(self, session_id, user_agent, ip, now=None):
        """Return the user id, or None if the session is unknown, expired or looks stolen."""
        key = _hash(session_id or "")
        record = self._sessions.get(key)
        if record is None:
            return None
        now = now if now is not None else time.time()
        expired = now - record["last_seen"] > self.idle_timeout or now - record["created"] > self.absolute_timeout
        stolen = record["ua"] != _hash(user_agent) or (self.bind_ip_prefix and record["net"] != self._ip_prefix(ip))
        if expired or stolen:
            del self._sessions[key]          # fail closed: destroy it
            return None
        record["last_seen"] = now
        return record["user"]

    def rotate(self, old_session_id, user_agent, ip, now=None):
        """Call after login or privilege change: returns a fresh id and destroys the old one."""
        record = self._sessions.pop(_hash(old_session_id or ""), None)
        user = record["user"] if record else None
        return self.create(user, user_agent, ip, now) if user is not None else None

    def destroy(self, session_id):
        self._sessions.pop(_hash(session_id or ""), None)

    def destroy_all(self, user_id):
        for key in [k for k, v in self._sessions.items() if v["user"] == user_id]:
            del self._sessions[key]

    def cookie_header(self, session_id):
        return (f"{COOKIE_NAME}={session_id}; Path=/; Secure; HttpOnly; SameSite=Lax; "
                f"Max-Age={self.absolute_timeout}")


if __name__ == "__main__":
    manager = SessionManager(idle_timeout=900)
    sid = manager.create("alice", "Mozilla/5.0", "203.0.113.7", now=0)
    print("valid session            :", manager.validate(sid, "Mozilla/5.0", "203.0.113.7", now=60))
    print("different browser (theft):", manager.validate(sid, "curl/8.0", "203.0.113.7", now=61))
    sid = manager.create("alice", "Mozilla/5.0", "203.0.113.7", now=0)
    new_sid = manager.rotate(sid, "Mozilla/5.0", "203.0.113.7", now=10)
    print("old id after rotation    :", manager.validate(sid, "Mozilla/5.0", "203.0.113.7", now=11))
    print("new id works             :", manager.validate(new_sid, "Mozilla/5.0", "203.0.113.7", now=12))
    print("after idle timeout       :", manager.validate(new_sid, "Mozilla/5.0", "203.0.113.7", now=12 + 1000))
    print("cookie                   :", manager.cookie_header("<id>"))
