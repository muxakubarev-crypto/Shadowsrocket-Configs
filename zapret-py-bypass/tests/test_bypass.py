"""Unit tests for bypass.py — runs on any OS (no pydivert needed)."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bypass  # noqa: E402


def _build_clienthello(sni: bytes) -> bytes:
    """Build a syntactically valid TLS 1.2 ClientHello with the given SNI."""
    sni_ext = (
        b"\x00\x00"  # ext type: server_name
        + struct.pack(">H", 5 + len(sni))  # ext length
        + struct.pack(">H", 3 + len(sni))  # server_name list length
        + b"\x00"  # name type: host_name
        + struct.pack(">H", len(sni))
        + sni
    )
    extensions = sni_ext
    body = (
        b"\x03\x03"          # client_version
        + b"\x00" * 32       # random
        + b"\x00"            # session_id length = 0
        + b"\x00\x02\x00\x35"  # cipher_suites: 1 suite (TLS_RSA_WITH_AES_256_CBC_SHA)
        + b"\x01\x00"        # compression_methods: null
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body  # ClientHello
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


def test_parse_sni_basic():
    pkt = _build_clienthello(b"www.youtube.com")
    assert bypass.parse_sni(pkt) == "www.youtube.com"


def test_parse_sni_uppercase_domain():
    pkt = _build_clienthello(b"WWW.X.COM")
    assert bypass.parse_sni(pkt) == "www.x.com"


def test_parse_sni_not_handshake():
    assert bypass.parse_sni(b"\x17\x03\x03\x00\x00") is None  # ApplicationData
    assert bypass.parse_sni(b"") is None
    assert bypass.parse_sni(b"\x16\x03") is None


def test_parse_sni_truncated():
    pkt = _build_clienthello(b"example.com")
    assert bypass.parse_sni(pkt[:30]) is None


def test_parse_sni_no_sni_extension():
    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\x00\x35"
        + b"\x01\x00"
        + b"\x00\x00"  # zero extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    assert bypass.parse_sni(record) is None


def test_domain_matches_exact():
    assert bypass.domain_matches("youtube.com", ["youtube.com"]) is True


def test_domain_matches_subdomain():
    assert bypass.domain_matches("www.youtube.com", ["youtube.com"]) is True
    assert bypass.domain_matches("a.b.youtube.com", ["youtube.com"]) is True


def test_domain_matches_does_not_match_partial():
    assert bypass.domain_matches("notyoutube.com", ["youtube.com"]) is False
    assert bypass.domain_matches("youtube.com.evil.com", ["youtube.com"]) is False


def test_domain_matches_case_insensitive():
    assert bypass.domain_matches("WWW.X.COM", ["x.com"]) is True


def test_load_domains_filters_comments_and_blanks(tmp_path, monkeypatch):
    f = tmp_path / "d.txt"
    f.write_text("# comment\n\nyoutube.com\n  X.COM \n# trailing\n", encoding="utf-8")
    monkeypatch.setattr(bypass, "DOMAINS_FILE", f)
    assert bypass.load_domains() == ["youtube.com", "x.com"]


def test_add_domain_dedup(tmp_path, monkeypatch):
    f = tmp_path / "d.txt"
    f.write_text("youtube.com\n", encoding="utf-8")
    monkeypatch.setattr(bypass, "DOMAINS_FILE", f)
    monkeypatch.setattr(bypass, "LOGS_DIR", tmp_path / "logs")
    msg = bypass.add_domain("YouTube.com")
    assert "уже" in msg
    msg = bypass.add_domain("x.com")
    assert "добавлен" in msg.lower()
    assert "x.com" in f.read_text(encoding="utf-8")


def test_add_domain_rejects_garbage(tmp_path, monkeypatch):
    f = tmp_path / "d.txt"
    f.write_text("", encoding="utf-8")
    monkeypatch.setattr(bypass, "DOMAINS_FILE", f)
    monkeypatch.setattr(bypass, "LOGS_DIR", tmp_path / "logs")
    msg = bypass.add_domain("bad domain with spaces")
    assert "Некорректный" in msg


def test_main_list(tmp_path, monkeypatch, capsys):
    f = tmp_path / "d.txt"
    f.write_text("youtube.com\nx.com\n", encoding="utf-8")
    monkeypatch.setattr(bypass, "DOMAINS_FILE", f)
    monkeypatch.setattr(bypass, "LOGS_DIR", tmp_path / "logs")
    rc = bypass.main(["list"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "youtube.com" in out
    assert "x.com" in out


def test_main_status_when_stopped(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(bypass, "PID_FILE", tmp_path / "bypass.pid")
    rc = bypass.main(["status"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "остановлен" in out


def test_fake_tls_payload_is_valid_clienthello():
    sni = bypass.parse_sni(bypass.FAKE_TLS_GOOGLE)
    assert sni == "www.google.com", f"FAKE_TLS_GOOGLE has bad SNI: {sni!r}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
