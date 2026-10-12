#!/usr/bin/env python3
"""
Context-aware output encoding (the real fix for XSS)
Location: 02-web-application-security/xss-attacks/prevention/output_encoding.py

Encode data for the place it is printed, at output time:

  html_text(x)       between tags:           <p>HERE</p>
  html_attribute(x)  inside a QUOTED value:  <input value="HERE">
  js_string(x)       inside a JS string:     <script>var s = "HERE"</script>
  url_param(x)       inside a URL parameter: /search?q=HERE
  safe_url(x)        for href/src: only http, https and mailto are allowed (blocks javascript:)

Input validation helps but is not the fix: the same text needs different encoding in each context.
Prefer a template engine that auto-escapes (Jinja2, React, Django templates) and add a CSP.
"""

import html
import json
from urllib.parse import quote, urlsplit


def html_text(value) -> str:
    return html.escape(str(value), quote=False)


def html_attribute(value) -> str:
    return html.escape(str(value), quote=True)


def js_string(value) -> str:
    """JSON-encode, then escape characters that could close a <script> block or start HTML."""
    encoded = json.dumps(str(value))
    return (encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029").replace("'", "\\u0027"))


def url_param(value) -> str:
    return quote(str(value), safe="")


def safe_url(value, default="#") -> str:
    candidate = str(value).strip()
    scheme = urlsplit(candidate).scheme.lower()
    if scheme in ("", "http", "https", "mailto") and not candidate.lower().startswith(("javascript:", "data:", "vbscript:")):
        return candidate
    return default


if __name__ == "__main__":
    evil = "<script>alert(1)</script>\"' onmouseover=alert(1)"
    print("html_text     :", html_text(evil))
    print("html_attribute:", html_attribute(evil))
    print("js_string     :", js_string("</script><script>alert(1)//"))
    print("url_param     :", url_param("a&b=<c>"))
    for u in ("https://example.com/a", "javascript:alert(1)", "JaVaScRiPt:alert(1)", "/relative/path"):
        print(f"safe_url({u!r}) ->", safe_url(u))
