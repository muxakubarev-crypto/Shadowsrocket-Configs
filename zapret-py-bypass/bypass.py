"""DPI-bypass engine for Windows, inspired by zapret/zapret2 and Flowseal's general (ALT11).

Strategy (TCP/443):
  1. Capture outbound TLS ClientHello packets via WinDivert (pydivert).
  2. If the SNI matches a domain from domains.txt — apply DPI desync:
       a) Inject FAKE_REPEATS fake ClientHello packets with SNI=www.google.com
          and TTL=FAKE_TTL (low, e.g. 3) so they expire before reaching the real
          server but DO reach the operator DPI box.
       b) Drop the original packet and re-send it split into two TCP segments
          (multisplit, split-pos=1) so the SNI extension straddles a packet
          boundary and the DPI cannot reassemble it.
  3. Anything that doesn't match passes through unchanged.

The script is designed to be controlled exclusively from service.bat. It exposes
sub-commands: start | stop | status | add <domain> | list. It writes a PID file
(`bypass.pid`) on start and a daily log file `logs/log_YYYY-MM-DD.txt`.

NOTE: pydivert / WinDivert only run on Windows. The non-network sub-commands
(add, list, status) work on any OS so service.bat can call them safely.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import signal
import struct
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Tunables (kept conservative; mirror Flowseal "general (ALT11)" spirit)
# ---------------------------------------------------------------------------
FAKE_TTL = 3           # fake packet dies after a few hops, never reaches server
FAKE_REPEATS = 6       # how many fake packets to send before the real one
SPLIT_POS = 1          # split real ClientHello after byte 1 of TLS payload
TCP_PORT_HTTPS = 443

def _build_fake_clienthello_blob(host: bytes) -> bytes:
    """Build a syntactically valid TLS 1.2 ClientHello with the given SNI.

    Used purely as a decoy. Only the SNI extension matters for DPI; the rest is
    minimal but well-formed so DPI engines that try to parse the record do
    accept it.
    """
    sni_ext = (
        b"\x00\x00"  # ext type: server_name
        + struct.pack(">H", 5 + len(host))  # ext length
        + struct.pack(">H", 3 + len(host))  # server_name list length
        + b"\x00"  # name type: host_name
        + struct.pack(">H", len(host))
        + host
    )
    # Minimal additional extensions to look realistic
    extra_exts = (
        b"\x00\x0a\x00\x04\x00\x02\x00\x17"  # supported_groups: secp256r1
        + b"\x00\x0b\x00\x02\x01\x00"          # ec_point_formats: uncompressed
        + b"\x00\x0d\x00\x06\x00\x04\x04\x03\x08\x04"  # sig_algs: ecdsa+sha256, rsa_pss
    )
    extensions = sni_ext + extra_exts
    body = (
        b"\x03\x03"          # client_version TLS 1.2
        + b"\x00" * 32       # random (zeros — fake packet, doesn't matter)
        + b"\x00"            # session_id length = 0
        + b"\x00\x02\x00\x35"  # cipher_suites: 1 suite
        + b"\x01\x00"        # compression_methods: null
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body  # ClientHello
    record = b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake
    return record


# Decoy TLS ClientHello with SNI=www.google.com, sent ahead of the real one.
FAKE_TLS_GOOGLE = _build_fake_clienthello_blob(b"www.google.com")


# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
DOMAINS_FILE = ROOT / "domains.txt"
LOGS_DIR = ROOT / "logs"
PID_FILE = ROOT / "bypass.pid"
STOP_FLAG = ROOT / "bypass.stop"


# ---------------------------------------------------------------------------
# Logging (always to logs/log_YYYY-MM-DD.txt; also to stdout)
# ---------------------------------------------------------------------------
def _log_path() -> Path:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    today = _dt.datetime.now().strftime("%Y-%m-%d")
    return LOGS_DIR / f"log_{today}.txt"


def log(level: str, msg: str) -> None:
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    line = f"[{ts}] [{level:<5}] {msg}"
    try:
        with _log_path().open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        # Never let a logging error kill the bypass loop.
        pass
    try:
        print(line, flush=True)
    except OSError:
        pass


def info(msg: str) -> None:
    log("INFO", msg)


def warn(msg: str) -> None:
    log("WARN", msg)


def err(msg: str) -> None:
    log("ERROR", msg)


# ---------------------------------------------------------------------------
# Domain list management
# ---------------------------------------------------------------------------
def load_domains() -> list[str]:
    if not DOMAINS_FILE.exists():
        return []
    out: list[str] = []
    for raw in DOMAINS_FILE.read_text(encoding="utf-8").splitlines():
        s = raw.strip().lower()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def add_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if not domain:
        return "Пустой домен — ничего не добавлено."
    if any(c in domain for c in (" ", "/", "\\")):
        return f"Некорректный домен: {domain!r}"
    existing = set(load_domains())
    if domain in existing:
        return f"Домен уже в списке: {domain}"
    with DOMAINS_FILE.open("a", encoding="utf-8") as f:
        f.write(domain + "\n")
    info(f"Добавлен домен: {domain}")
    return f"Домен добавлен: {domain}"


def list_domains_str() -> str:
    items = load_domains()
    if not items:
        return "(список пуст — добавьте через пункт 3 меню)"
    return "\n".join(f"  {i + 1:>3}. {d}" for i, d in enumerate(items))


def domain_matches(sni: str, domains: list[str]) -> bool:
    sni = sni.lower()
    for d in domains:
        if sni == d or sni.endswith("." + d):
            return True
    return False


# ---------------------------------------------------------------------------
# TLS ClientHello SNI parser (pure-python, defensive)
# ---------------------------------------------------------------------------
def parse_sni(payload: bytes) -> str | None:
    """Return the SNI hostname from a TLS ClientHello, or None on any failure."""
    try:
        if len(payload) < 5 or payload[0] != 0x16:  # not TLS handshake
            return None
        # TLS record header: type(1) + version(2) + length(2)
        rec_len = struct.unpack(">H", payload[3:5])[0]
        if 5 + rec_len > len(payload):
            # Fragmented record — we'd see the rest in a later packet; bail.
            return None
        body = payload[5 : 5 + rec_len]
        if len(body) < 4 or body[0] != 0x01:  # not ClientHello
            return None
        # Handshake header: msg_type(1) + length(3)
        # then: client_version(2) + random(32) + session_id_length(1) + ...
        i = 4 + 2 + 32  # skip header + version + random
        if i + 1 > len(body):
            return None
        sid_len = body[i]
        i += 1 + sid_len
        if i + 2 > len(body):
            return None
        cs_len = struct.unpack(">H", body[i : i + 2])[0]
        i += 2 + cs_len
        if i + 1 > len(body):
            return None
        cm_len = body[i]
        i += 1 + cm_len
        if i + 2 > len(body):
            return None
        ext_total = struct.unpack(">H", body[i : i + 2])[0]
        i += 2
        end = i + ext_total
        while i + 4 <= end:
            ext_type = struct.unpack(">H", body[i : i + 2])[0]
            ext_len = struct.unpack(">H", body[i + 2 : i + 4])[0]
            i += 4
            if i + ext_len > end:
                return None
            if ext_type == 0x0000:  # server_name
                # SNI extension body: list_length(2) + entries
                if ext_len < 5:
                    return None
                # snl_len = struct.unpack(">H", body[i:i+2])[0]
                name_type = body[i + 2]
                name_len = struct.unpack(">H", body[i + 3 : i + 5])[0]
                if name_type != 0x00 or i + 5 + name_len > end:
                    return None
                host = body[i + 5 : i + 5 + name_len]
                try:
                    return host.decode("ascii").lower()
                except UnicodeDecodeError:
                    return None
            i += ext_len
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Bypass loop (Windows-only — uses pydivert)
# ---------------------------------------------------------------------------
def _build_split_segments(packet, split_pos: int):
    """Return two pydivert.Packet objects: first <split_pos> bytes, then the rest.

    Each segment has correct TCP SEQ numbers so the receiver reassembles them as
    one TLS record. Checksums are recalculated by pydivert on send.
    """
    import pydivert  # local import — Windows only

    payload = packet.payload
    if len(payload) <= split_pos:
        return None  # nothing to split

    # First fragment
    p1 = pydivert.Packet(bytes(packet.raw), packet.interface, packet.direction)
    p1.payload = payload[:split_pos]

    # Second fragment (advance SEQ by split_pos)
    p2 = pydivert.Packet(bytes(packet.raw), packet.interface, packet.direction)
    p2.tcp.seq_num = (packet.tcp.seq_num + split_pos) & 0xFFFFFFFF
    p2.payload = payload[split_pos:]

    return p1, p2


def _build_fake_clienthello(packet):
    """Clone the outgoing packet, replace payload with FAKE_TLS_GOOGLE,
    and lower TTL so it dies in transit."""
    import pydivert

    fake = pydivert.Packet(bytes(packet.raw), packet.interface, packet.direction)
    fake.payload = FAKE_TLS_GOOGLE
    # IPv4 has ttl, IPv6 has hop_limit; pydivert exposes both.
    if fake.ipv4 is not None:
        fake.ipv4.ttl = FAKE_TTL
    if fake.ipv6 is not None:
        fake.ipv6.hop_limit = FAKE_TTL
    return fake


def run_bypass() -> int:
    """Main capture loop. Returns process exit code."""
    info("=" * 60)
    info("Запуск DPI-обхода. Платформа: " + sys.platform)
    if sys.platform != "win32":
        err("Этот режим работает только на Windows (pydivert/WinDivert).")
        return 2

    try:
        import pydivert
    except ImportError as e:
        err(f"pydivert не установлен: {e}. Запустите service.bat -> пункт setup.")
        return 3

    domains = load_domains()
    info(f"Загружено доменов из списка: {len(domains)}")
    if not domains:
        warn("Список доменов пуст — обход применяться не будет.")

    # Write PID + clear stop flag
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    if STOP_FLAG.exists():
        STOP_FLAG.unlink()
    info(f"PID сервиса: {os.getpid()} (файл {PID_FILE.name})")

    # Capture only outbound TCP/443 packets that carry payload
    flt = f"outbound and tcp.DstPort == {TCP_PORT_HTTPS} and tcp.PayloadLength > 0"
    info(f"WinDivert фильтр: {flt}")

    stats = {"seen": 0, "matched": 0, "sni_seen": 0, "errors": 0}
    last_status = time.time()

    try:
        with pydivert.WinDivert(flt) as w:
            info("WinDivert открыт. Перехват трафика начат.")
            for packet in w:
                stats["seen"] += 1

                # Periodic status
                now = time.time()
                if now - last_status > 30:
                    info(
                        f"Статистика: пакетов={stats['seen']}, SNI={stats['sni_seen']}, "
                        f"совпадений={stats['matched']}, ошибок={stats['errors']}"
                    )
                    last_status = now

                if STOP_FLAG.exists():
                    info("Получен флаг остановки. Завершение цикла.")
                    w.send(packet)
                    break

                try:
                    sni = parse_sni(bytes(packet.payload))
                    if sni is None:
                        w.send(packet)
                        continue

                    stats["sni_seen"] += 1
                    if not domain_matches(sni, domains):
                        info(f"Пропуск: SNI={sni} не в списке.")
                        w.send(packet)
                        continue

                    stats["matched"] += 1
                    info(f"Применяю обход для SNI={sni}")

                    # Step 1: send N fake ClientHellos with TTL=3
                    fake = _build_fake_clienthello(packet)
                    for _ in range(FAKE_REPEATS):
                        w.send(fake)

                    # Step 2: split real ClientHello into 2 TCP segments
                    pieces = _build_split_segments(packet, SPLIT_POS)
                    if pieces is None:
                        # Payload too short to split — just send as-is
                        w.send(packet)
                    else:
                        p1, p2 = pieces
                        w.send(p1)
                        w.send(p2)

                except Exception as e:  # noqa: BLE001
                    stats["errors"] += 1
                    err(f"Ошибка при обработке пакета: {e!r}")
                    try:
                        w.send(packet)  # best-effort: don't break the connection
                    except Exception as e2:  # noqa: BLE001
                        err(f"Не удалось переслать пакет после ошибки: {e2!r}")
    except KeyboardInterrupt:
        info("Прерывание с клавиатуры — завершаю.")
    except Exception as e:  # noqa: BLE001
        err(f"Фатальная ошибка цикла перехвата: {e!r}")
        return 4
    finally:
        if PID_FILE.exists():
            try:
                PID_FILE.unlink()
            except OSError:
                pass
        if STOP_FLAG.exists():
            try:
                STOP_FLAG.unlink()
            except OSError:
                pass
        info(
            f"Итог: пакетов={stats['seen']}, SNI={stats['sni_seen']}, "
            f"совпадений={stats['matched']}, ошибок={stats['errors']}"
        )
        info("DPI-обход остановлен.")
    return 0


def stop_bypass() -> int:
    if not PID_FILE.exists():
        info("Сервис не запущен (нет файла bypass.pid).")
        return 0
    try:
        pid = int(PID_FILE.read_text(encoding="utf-8").strip())
    except ValueError:
        warn("Файл bypass.pid повреждён, удаляю.")
        try:
            PID_FILE.unlink()
        except OSError:
            pass
        return 0

    # First, polite stop via flag file
    STOP_FLAG.write_text("1", encoding="utf-8")
    info(f"Установлен флаг остановки. Жду завершения PID={pid}...")
    for _ in range(30):  # up to ~3 sec
        time.sleep(0.1)
        if not PID_FILE.exists():
            info("Сервис корректно остановлен.")
            return 0

    # Hard stop
    warn("Мягкая остановка не сработала, пытаюсь убить процесс.")
    try:
        if sys.platform == "win32":
            os.system(f"taskkill /PID {pid} /F >nul 2>&1")  # noqa: S605
        else:
            os.kill(pid, signal.SIGTERM)
    except Exception as e:  # noqa: BLE001
        err(f"Не удалось остановить PID={pid}: {e!r}")
        return 1
    if PID_FILE.exists():
        try:
            PID_FILE.unlink()
        except OSError:
            pass
    info("Сервис остановлен принудительно.")
    return 0


def status_bypass() -> int:
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        except ValueError:
            print("СТАТУС: файл bypass.pid повреждён.")
            return 1
        print(f"СТАТУС: запущен (PID={pid})")
        return 0
    print("СТАТУС: остановлен")
    return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="bypass.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("start", help="запустить обход (требует прав администратора)")
    sub.add_parser("stop", help="остановить обход")
    sub.add_parser("status", help="показать статус")
    a = sub.add_parser("add", help="добавить домен")
    a.add_argument("domain")
    sub.add_parser("list", help="показать домены")

    ns = p.parse_args(argv)

    if ns.cmd == "start":
        return run_bypass()
    if ns.cmd == "stop":
        return stop_bypass()
    if ns.cmd == "status":
        return status_bypass()
    if ns.cmd == "add":
        print(add_domain(ns.domain))
        return 0
    if ns.cmd == "list":
        print(list_domains_str())
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
