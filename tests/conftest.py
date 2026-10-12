"""Shared helpers: load scripts from hyphenated folders and run a tiny local HTTP target."""
import importlib.util
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

ROOT = Path(__file__).resolve().parent.parent


def load(relative_path):
    path = ROOT / relative_path
    spec = importlib.util.spec_from_file_location(path.stem + "_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        url = urlparse(self.path)
        value = parse_qs(url.query).get("q", [""])[0]
        if url.path == "/sqlerr":                      # database error inside an HTTP 500 page
            code, body = (500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server") if "'" in value else (200, "ok")
        elif url.path == "/reflect":                   # reflected XSS, nothing encoded
            code, body = 200, f"<h1>Results for {value}</h1>"
        elif url.path == "/reflect_safe":
            import html
            code, body = 200, f"<h1>Results for {html.escape(value)}</h1>"
        else:
            code, body = 200, "ok"
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


@pytest.fixture(scope="session")
def server():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    httpd = HTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    httpd.shutdown()


@pytest.fixture
def dead_url():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}"          # nothing is listening here
