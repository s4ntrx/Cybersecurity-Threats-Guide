import json
import os
import stat
from conftest import ROOT, load

import pytest
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP

dns_mod = load("01-network-security/dns-spoofing/detection/dns_spoof_detector.py")
dnssec = load("01-network-security/dns-spoofing/prevention/dnssec_check.py")
keylog = load("03-malware-analysis/keyloggers/detection/keylogger_detector.py")
usb = load("04-social-engineering/baiting/detection/usb_bait_scanner.py")
tail = load("04-social-engineering/tailgating/detection/tailgating_log_analyzer.py")
rsa_mod = load("05-cryptography/encryption/asymmetric/rsa_example.py")
signer = load("05-cryptography/digital-signatures/file_signer.py")
keys = load("05-cryptography/key-management/key_manager.py")
report = load("06-incident-response/post-incident/post_incident_report.py")
integrity = load("05-cryptography/hashing/integrity_checker.py")
waf = load("01-network-security/ddos-attacks/prevention/rate_limiting.py")

C, S = "192.0.2.10", "192.0.2.53"


def q(i, name):
    return IP(src=C, dst=S) / UDP(sport=40000, dport=53) / DNS(id=i, rd=1, qd=DNSQR(qname=name))


def r(i, name, ans, src=S):
    return IP(src=src, dst=C) / UDP(sport=53, dport=40000) / DNS(id=i, qr=1, qd=DNSQR(qname=name),
                                                                  an=DNSRR(rrname=name, type="A", ttl=60, rdata=ans), ancount=1)


def alerts(packets, **kw):
    d = dns_mod.DNSSpoofDetector(**kw)
    for k, p in enumerate(packets):
        d.process_packet(p, now=100 + k * 0.01)
    return sorted({a["type"] for a in d.alerts})


@pytest.mark.parametrize("packets,expected,kw", [
    ([q(1, "example.com"), r(1, "example.com", "93.184.216.34")], [], {}),
    ([q(2, "bank.example"), r(2, "bank.example", "198.51.100.66"), r(2, "bank.example", "203.0.113.5")], ["CONFLICTING_ANSWERS"], {}),
    ([q(3, "example.org"), r(3, "example.org", "203.0.113.9", src="203.0.113.250")], ["WRONG_SOURCE"], {}),
    ([r(4, "login.example", "203.0.113.7")], ["UNSOLICITED_RESPONSE"], {}),
    ([q(5, "update.vendor.com"), r(5, "update.vendor.com", "10.0.0.5")], ["PRIVATE_ANSWER"], {}),
    ([q(6, "files.corp.example"), r(6, "files.corp.example", "10.0.0.5")], [], {"internal_domains": ["corp.example"]}),
])
def test_dns_detector_cases(packets, expected, kw):
    assert alerts(packets, **kw) == expected


def test_dnssec_statuses():
    import dns.flags, dns.message, dns.rcode, dns.rrset

    def fake(has_key, ad, rcode=dns.rcode.NOERROR):
        def query(request, ip, timeout=5.0):
            m = dns.message.make_response(request)
            m.set_rcode(rcode)
            if ad:
                m.flags |= dns.flags.AD
            if has_key:
                m.answer.append(dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY",
                                "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="))
            return m
        return query
    check = lambda fn: dnssec.check_domain("example.com", "192.0.2.53", query=fn)[0]
    assert check(fake(True, True)) == "VALIDATED"
    assert check(fake(True, False)) == "SIGNED_NOT_CHECKED"
    assert check(fake(False, False)) == "UNSIGNED"
    assert check(fake(False, False, dns.rcode.SERVFAIL)) == "ERROR"


def test_keylogger_scanner_with_fake_proc(tmp_path):
    proc, dev = tmp_path / "proc", tmp_path / "dev"
    dev.mkdir()
    (dev / "event0").write_text("")
    def process(pid, comm, cmdline="", environ="", device=False):
        d = proc / str(pid)
        (d / "fd").mkdir(parents=True)
        (d / "comm").write_text(comm + "\n")
        (d / "cmdline").write_bytes(cmdline.replace(" ", "\0").encode())
        (d / "environ").write_bytes(environ.encode())
        if device:
            (d / "fd" / "3").symlink_to(dev / "event0")
    process(10, "Xorg", device=True)                                   # allowed: desktop input stack
    process(11, "weird", device=True)                                  # HIGH
    process(12, "sleep", environ="LD_PRELOAD=/tmp/hook.so\0")          # HIGH
    process(13, "sh", cmdline="sh -c echo logkeys is mentioned here")  # must NOT match
    process(14, "logkeys", cmdline="/usr/bin/logkeys --start")         # HIGH
    found = keylog.scan(input_glob=str(dev / "event*"), proc_root=str(proc), preload_file=str(tmp_path / "none"))
    pairs = sorted((f["type"], f["pid"]) for f in found)
    assert pairs == [("INPUT_DEVICE", 11), ("KNOWN_TOOL", 14), ("LD_PRELOAD", 12)]


def test_usb_scanner(tmp_path):
    (tmp_path / "invoice.pdf.exe").write_text("")
    (tmp_path / "autorun.inf").write_text("")
    (tmp_path / "notes.txt").write_text("hello")
    issues = [f["issue"] for f in usb.scan_directory(str(tmp_path))]
    assert any("double extension" in i for i in issues) and any("autorun" in i for i in issues)
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "notes.txt").write_text("hello")
    assert usb.scan_directory(str(clean)) == []

    sysfs = tmp_path / "sys"
    for name, cls, proto in [("1-2:1.0", "08", "06"), ("1-2:1.1", "03", "01"), ("1-3:1.0", "03", "01")]:
        (sysfs / name).mkdir(parents=True)
        (sysfs / name / "bInterfaceClass").write_text(cls)
        (sysfs / name / "bInterfaceProtocol").write_text(proto)
    for dev in ("1-2", "1-3"):
        (sysfs / dev).mkdir(exist_ok=True)
    found = usb.inspect_usb_devices(str(sysfs))
    assert [f["file"] for f in found] == ["1-2"] and found[0]["severity"] == "HIGH"


def test_tailgating_rules():
    rows = tail.load(str(ROOT / "04-social-engineering/tailgating/detection/sample_access_log.csv"))
    rules = {f["rule"] for f in tail.analyse(rows)}
    assert rules == {"PEOPLE_MISMATCH", "ANTI_PASSBACK", "IMPOSSIBLE_TRAVEL", "DENIED_THEN_GRANTED", "FORCED_OR_HELD", "AFTER_HOURS"}


def test_rsa_and_signatures_detect_tampering(tmp_path):
    key = rsa_mod.generate_keypair(str(tmp_path / "priv.pem"), str(tmp_path / "pub.pem"), b"pw", bits=2048)
    pub = rsa_mod.load_public(str(tmp_path / "pub.pem"))
    assert rsa_mod.decrypt(key, rsa_mod.encrypt(pub, b"secret")) == b"secret"
    sig = rsa_mod.sign(key, b"release")
    assert rsa_mod.verify(pub, sig, b"release") and not rsa_mod.verify(pub, sig, b"release2")
    with pytest.raises(ValueError):
        rsa_mod.generate_keypair(str(tmp_path / "a"), str(tmp_path / "b"), b"pw", bits=1024)

    signer.generate_keys(str(tmp_path / "s.pem"), str(tmp_path / "p.pem"), b"pw")
    target = tmp_path / "release.tar"
    target.write_text("v1")
    signer.sign_file(str(target), str(tmp_path / "s.pem"), b"pw")
    assert signer.verify_file(str(target), str(tmp_path / "p.pem"))[0]
    target.write_text("v1 tampered")
    ok, reason = signer.verify_file(str(target), str(tmp_path / "p.pem"))
    assert not ok and "changed" in reason


def test_key_manager_lifecycle(tmp_path):
    store = keys.KeyStore(str(tmp_path / "ks"), "long passphrase")
    store.init()
    store.open()
    store.create("payments")
    old = store.encrypt("payments", b"data")
    store.rotate("payments")
    new = store.encrypt("payments", b"data")
    assert old["key_id"] == "payments-v1" and new["key_id"] == "payments-v2"
    assert store.decrypt(old) == b"data"                       # old version still readable after rotation
    store.set_status("payments-v1", "destroyed")
    with pytest.raises(keys.KeyStoreError):
        store.decrypt(old)
    assert store.decrypt(new) == b"data"
    assert store.verify_audit()[0]
    with pytest.raises(keys.KeyStoreError):
        keys.KeyStore(str(tmp_path / "ks"), "wrong").open()
    audit = tmp_path / "ks" / "audit.log"
    audit.write_text(audit.read_text().replace('"create"', '"delete"', 1))
    assert not store.verify_audit()[0]
    assert stat.S_IMODE(os.stat(tmp_path / "ks" / "keystore.json").st_mode) == 0o600


def test_incident_report_metrics_and_warnings():
    incident = json.load(open(ROOT / "06-incident-response/post-incident/sample_incident.json"))
    events, metrics, problems = report.analyse(incident)
    assert report.human(metrics["Time to contain (detected to contained)"]) == "50m" and problems == []
    _, _, problems = report.analyse({"events": [{"time": "bad", "type": "start"}], "action_items": [{"item": "x"}]})
    assert any("invalid" in p for p in problems) and any("owner" in p for p in problems)


def test_integrity_checker_finds_modified_missing_new(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    checker = integrity.IntegrityChecker()
    manifest = checker.create_manifest(str(tmp_path))
    (tmp_path / "a.txt").write_text("tampered")
    (tmp_path / "b.txt").unlink()
    (tmp_path / "new.txt").write_text("n")
    results = checker.verify_manifest(manifest)
    assert [os.path.basename(x) for x in results["modified"]] == ["a.txt"]
    assert [os.path.basename(x) for x in results["missing"]] == ["b.txt"]
    assert [os.path.basename(x) for x in results["new"]] == ["new.txt"]


def test_waf_blocks_attacks_not_normal_or_apostrophe_requests():
    import inspect
    cls = next(c for _, c in inspect.getmembers(waf, inspect.isclass) if hasattr(c, "process_request"))
    w = cls()
    assert w.process_request({"remote_addr": "10.0.0.1", "path": "/", "user": "u1"})[0]
    assert w.process_request({"remote_addr": "10.0.0.2", "path": "/p", "user": "o'brien"})[0]
    assert not w.process_request({"remote_addr": "10.0.0.3", "path": "/p", "q": "1' OR 1=1--"})[0]
    assert not w.process_request({"remote_addr": "10.0.0.4", "path": "/p", "q": "<script>x</script>"})[0]
    stats = w.get_stats()
    assert stats["total_requests"] == stats["allowed_requests"] + stats["blocked_requests"] == 4
