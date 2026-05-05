"""Connectivity & speed tests for the DPI-bypass project.

Usage (called from service.bat, but works standalone):
    python tester.py            # tests youtube.com and x.com (default golden set)
    python tester.py host1 host2 ...

The tester:
  * does a DNS lookup,
  * opens a TCP socket to :443,
  * performs a TLS handshake,
  * sends a minimal HTTPS HEAD request,
  * waits for the first byte,
  * reads the full response (or up to a cap) and times everything.

Results are printed to the console in plain Russian (so service.bat can show them
to the user) and ALSO appended to logs/log_YYYY-MM-DD.txt with full details so
you have an evidence trail when something fails.
"""

from __future__ import annotations

import datetime as _dt
import socket
import ssl
import sys
import time
from pathlib import Path

# Reuse the project logger so console + log file are consistent.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bypass import err, info, load_domains, log, warn  # noqa: E402

DEFAULT_HOSTS = ["youtube.com", "www.youtube.com", "x.com", "www.x.com"]

# Speed thresholds in seconds (total time per request)
FAST_THRESHOLD = 2.0
OK_THRESHOLD = 5.0


def _verdict(seconds: float | None, ok: bool) -> str:
    if not ok or seconds is None:
        return "ОШИБКА"
    if seconds < FAST_THRESHOLD:
        return "БЫСТРО"
    if seconds < OK_THRESHOLD:
        return "СРЕДНЕ"
    return "МЕДЛЕННО"


def test_one(host: str, port: int = 443, total_timeout: float = 10.0) -> dict:
    """Run a single end-to-end test. Returns a dict with timings + verdict."""
    result: dict = {
        "host": host,
        "ok": False,
        "error": None,
        "dns_ms": None,
        "tcp_ms": None,
        "tls_ms": None,
        "ttfb_ms": None,
        "total_ms": None,
        "bytes": 0,
        "verdict": "ОШИБКА",
    }

    deadline = time.monotonic() + total_timeout

    # 1. DNS
    t0 = time.monotonic()
    try:
        addrs = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        ip = addrs[0][4][0]
    except OSError as e:
        result["error"] = f"DNS: {e}"
        return result
    result["dns_ms"] = round((time.monotonic() - t0) * 1000, 1)

    # 2. TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(max(0.1, deadline - time.monotonic()))
    t1 = time.monotonic()
    try:
        sock.connect((ip, port))
    except OSError as e:
        result["error"] = f"TCP: {e}"
        sock.close()
        return result
    result["tcp_ms"] = round((time.monotonic() - t1) * 1000, 1)

    # 3. TLS
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    t2 = time.monotonic()
    try:
        ssock = ctx.wrap_socket(sock, server_hostname=host)
    except (ssl.SSLError, OSError, socket.timeout) as e:
        result["error"] = f"TLS: {e}"
        sock.close()
        return result
    result["tls_ms"] = round((time.monotonic() - t2) * 1000, 1)

    # 4. HTTP HEAD + TTFB + body
    req = (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: zapret-py-tester/1.0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("ascii")
    t3 = time.monotonic()
    try:
        ssock.sendall(req)
        first = ssock.recv(4096)
        result["ttfb_ms"] = round((time.monotonic() - t3) * 1000, 1)
        total_bytes = len(first)
        # Read the rest until close or deadline
        ssock.settimeout(max(0.1, deadline - time.monotonic()))
        while True:
            chunk = ssock.recv(8192)
            if not chunk:
                break
            total_bytes += len(chunk)
            if time.monotonic() > deadline:
                break
        result["bytes"] = total_bytes
        if not first.startswith(b"HTTP/"):
            result["error"] = "Bad HTTP response"
        else:
            # Extract status line for the log
            status_line = first.split(b"\r\n", 1)[0].decode("ascii", "replace")
            result["status"] = status_line
            result["ok"] = True
    except (ssl.SSLError, OSError, socket.timeout) as e:
        result["error"] = f"HTTP: {e}"
    finally:
        try:
            ssock.close()
        except OSError:
            pass

    result["total_ms"] = round((time.monotonic() - t0) * 1000, 1)
    result["verdict"] = _verdict(
        (result["total_ms"] / 1000) if result["total_ms"] is not None else None,
        result["ok"],
    )
    return result


def _print_summary(rows: list[dict]) -> None:
    print()
    print("=" * 70)
    print(" РЕЗУЛЬТАТЫ ТЕСТА ПОДКЛЮЧЕНИЯ")
    print("=" * 70)
    fmt = "{:<28} {:>10} {:>9} {:>9}"
    print(fmt.format("Сайт", "Итог", "Время", "Размер"))
    print("-" * 70)
    for r in rows:
        total = (
            f"{(r['total_ms'] / 1000):.2f} с" if r["total_ms"] is not None else "-"
        )
        size = f"{r['bytes']} б" if r["bytes"] else "-"
        print(fmt.format(r["host"][:28], r["verdict"], total, size))
    print("-" * 70)
    fast = sum(1 for r in rows if r["ok"] and r["verdict"] == "БЫСТРО")
    ok = sum(1 for r in rows if r["ok"])
    bad = len(rows) - ok
    print(f"  Быстро: {fast}    Успешно всего: {ok}    Ошибок: {bad}")
    if bad:
        print()
        print(" ДЕТАЛИ ОШИБОК:")
        for r in rows:
            if not r["ok"]:
                print(f"   - {r['host']}: {r['error']}")
    print("=" * 70)


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    hosts = argv if argv else DEFAULT_HOSTS

    info("=" * 60)
    info(f"ТЕСТ ПОДКЛЮЧЕНИЯ старт. Хосты: {hosts}")
    domains = load_domains()
    in_list = [h for h in hosts if any(h == d or h.endswith("." + d) for d in domains)]
    not_in_list = [h for h in hosts if h not in in_list]
    if not_in_list:
        warn(
            "Внимание: эти хосты НЕ в domains.txt (обход не применится): "
            + ", ".join(not_in_list)
        )

    rows: list[dict] = []
    for h in hosts:
        info(f"--> Тестирую {h}")
        r = test_one(h)
        log(
            "INFO" if r["ok"] else "ERROR",
            f"  {h}: ok={r['ok']} dns={r['dns_ms']}мс tcp={r['tcp_ms']}мс "
            f"tls={r['tls_ms']}мс ttfb={r['ttfb_ms']}мс total={r['total_ms']}мс "
            f"bytes={r['bytes']} status={r.get('status', '-')} err={r['error']}",
        )
        rows.append(r)

    _print_summary(rows)

    # Persist a machine-readable summary line per run
    summary = ", ".join(f"{r['host']}={r['verdict']}({r['total_ms']}мс)" for r in rows)
    log("INFO", f"ИТОГ ТЕСТА: {summary}")

    # Verdict for service.bat: exit 0 if all FAST, 1 if any failure, 2 if slow
    if any(not r["ok"] for r in rows):
        err("ТЕСТ: были ОШИБКИ.")
        return 1
    if all(r["verdict"] == "БЫСТРО" for r in rows):
        info("ТЕСТ: все сайты БЫСТРО.")
        return 0
    info("ТЕСТ: все сайты загрузились, но не все БЫСТРО.")
    return 2


if __name__ == "__main__":
    # ensure log shows wall-clock start
    print(f"# Запуск тестов: {_dt.datetime.now():%Y-%m-%d %H:%M:%S}")
    sys.exit(main())
