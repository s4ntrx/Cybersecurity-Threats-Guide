import pytest
from conftest import load

sqli = load("02-web-application-security/sql-injection/detection/sql_injection_detector.py")
xss = load("02-web-application-security/xss-attacks/detection/xss_detector.py")
csrf = load("02-web-application-security/csrf/detection/csrf_detector.py")
csrf_prot = load("02-web-application-security/csrf/prevention/csrf_protection.py")
session = load("02-web-application-security/session-hijacking/detection/session_security_checker.py")
secure_session = load("02-web-application-security/session-hijacking/prevention/secure_session.py")
files = load("02-web-application-security/file-inclusion/prevention/safe_file_access.py")
headers = load("02-web-application-security/security-misconfig/detection/security_headers_checker.py")
encoding = load("02-web-application-security/xss-attacks/prevention/output_encoding.py")
csp = load("02-web-application-security/xss-attacks/prevention/csp_analyzer.py")


def test_sqli_detects_error_inside_http_500(server):
    scanner = sqli.SQLInjectionDetector(server + "/sqlerr?q=1", timeout=5)
    scanner.scan()
    assert scanner.results["vulnerable"] and scanner.results["scan_completed"]


def test_sqli_clean_endpoint_is_clean(server):
    scanner = sqli.SQLInjectionDetector(server + "/other?q=1", timeout=5)
    scanner.scan()
    assert scanner.results["scan_completed"] and not scanner.results["vulnerable"]


def test_sqli_unreachable_target_is_not_reported_as_safe(dead_url):
    scanner = sqli.SQLInjectionDetector(dead_url + "/x?q=1", timeout=2)
    scanner.scan()
    assert not scanner.results["scan_completed"] and scanner.results["error"]


def test_sqli_payloads_are_not_destructive():
    everything = " ".join(sqli.ERROR_PAYLOADS + [p for _, p in sqli.TIME_PAYLOADS] + [x for pair in sqli.BOOLEAN_PAIRS for x in pair]).upper()
    for word in ("DROP ", "DELETE ", "INSERT ", "UPDATE ", "OUTFILE", "TRUNCATE"):
        assert word not in everything


def test_xss_flags_unencoded_reflection_only(server):
    bad = xss.XSSDetector(server + "/reflect?q=x", timeout=5)
    bad.scan()
    good = xss.XSSDetector(server + "/reflect_safe?q=x", timeout=5)
    good.scan()
    assert bad.results["vulnerable"] and not good.results["vulnerable"]


def test_xss_unreachable_is_incomplete(dead_url):
    scanner = xss.XSSDetector(dead_url + "/x?q=1", timeout=2)
    scanner.scan()
    assert not scanner.results["scan_completed"]


def test_csrf_form_analysis():
    bad, _ = csrf.analyse_forms('<form method="post"><input name="amount"></form>')
    good, _ = csrf.analyse_forms('<form method="post"><input type="hidden" name="csrf_token" value="a" ></form>'.replace('value="a"', 'value="' + "x" * 32 + '"'))
    assert bad and bad[0]["type"] == "form-without-token" and not good
    assert csrf.analyse_cookies(["sid=1; Path=/"])[0]["type"] == "cookie-no-samesite"


def test_csrf_tokens_are_session_bound_and_expire():
    p = csrf_prot.CSRFProtector("a-long-enough-secret-key", ttl_seconds=60)
    token = p.generate_token("s1", now=1000)
    assert p.validate("s1", token, now=1030)
    assert not p.validate("s2", token, now=1030)
    assert not p.validate("s1", token, now=1100)
    assert not p.validate("s1", token[:-3] + "abc", now=1030)
    assert not csrf_prot.check_origin({}, {"https://a.example"})


def test_session_cookie_and_id_checks():
    cookie = session.parse_set_cookie("PHPSESSID=abc; Path=/")
    kinds = [m for _, m in session.check_cookie(cookie, https=True)]
    assert any("HttpOnly" in m for m in kinds) and any("Secure" in m for m in kinds)
    assert session.check_session_ids([str(1000 + i) for i in range(10)])
    assert not session.check_session_ids(["A" * 3 + __import__("secrets").token_urlsafe(32) for _ in range(10)])


def test_session_manager_rotation_timeout_and_theft():
    m = secure_session.SessionManager(idle_timeout=100)
    sid = m.create("alice", "UA", "203.0.113.7", now=0)
    assert m.validate(sid, "UA", "203.0.113.7", now=10) == "alice"
    assert m.validate(sid, "other-browser", "203.0.113.7", now=11) is None          # stolen: destroyed
    sid = m.create("alice", "UA", "203.0.113.7", now=0)
    new = m.rotate(sid, "UA", "203.0.113.7", now=1)
    assert m.validate(sid, "UA", "203.0.113.7", now=2) is None and m.validate(new, "UA", "203.0.113.7", now=3) == "alice"
    assert m.validate(new, "UA", "203.0.113.7", now=3 + 500) is None                # idle timeout


def test_safe_join_blocks_traversal_and_symlinks(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("x")
    (tmp_path / "link").symlink_to("/etc")
    assert files.safe_join(str(tmp_path), "sub/a.txt").endswith("a.txt")
    for bad in ["../x", "link/passwd", "/etc/passwd", "a\x00b", "sub/../../x"]:
        with pytest.raises(files.UnsafePath):
            files.safe_join(str(tmp_path), bad)


def test_security_headers_grade():
    weak = headers.check_headers({"Server": "Apache/2.4.1"}, https=True)
    assert headers.grade(weak) in "DF"
    strong = {"Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
              "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "Permissions-Policy": "x=()"}
    assert headers.grade(headers.check_headers(strong, https=True)) == "A"


def test_output_encoding_and_csp():
    assert "</script>" not in encoding.js_string("</script><script>")
    assert encoding.safe_url("JaVaScRiPt:alert(1)") == "#"
    assert '"' not in encoding.html_attribute('a"b')
    assert csp.analyse("script-src 'unsafe-inline' https:")
    assert not csp.analyse("default-src 'self'; script-src 'self' 'nonce-x'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
