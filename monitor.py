#!/usr/bin/env python3
"""
monitor.py - Hujumlarni real vaqtda aniqlash va avtomatik bloklash.

Manbalar:
  1) /var/log/suricata/eve.json  - Suricata alertlari
  2) /var/log/auth.log           - SSH xato urinishlari

Qoida: bitta IP WINDOW soniya ichida THRESHOLD dan ortiq hodisa bersa,
UFW orqali bloklanadi va log yoziladi.
"""
import json
import os
import re
import subprocess
import time
import ipaddress
from collections import defaultdict, deque

EVE_LOG = "/var/log/suricata/eve.json"
AUTH_LOG = "/var/log/auth.log"
OUT_LOG = "/var/log/attack-monitor.log"

WINDOW = 60          # soniya
THRESHOLD = 5        # hodisalar soni
WHITELIST = {"127.0.0.1", "::1"}   # bloklanmaydigan IP lar (o'zingizniki qo'shing)

SSH_FAIL = re.compile(r"Failed password .* from (\d+\.\d+\.\d+\.\d+)")
SSH_INVALID = re.compile(r"Invalid user .* from (\d+\.\d+\.\d+\.\d+)")

events = defaultdict(deque)   # ip -> vaqtlar
blocked = set()


def log(msg: str) -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    with open(OUT_LOG, "a") as f:
        f.write(line + "\n")


def is_valid_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return ip not in WHITELIST and not addr.is_loopback


def block(ip: str, reason: str) -> None:
    if ip in blocked or not is_valid_public(ip):
        return
    result = subprocess.run(
        ["ufw", "insert", "1", "deny", "from", ip, "to", "any"],
        capture_output=True, text=True,
    )
    blocked.add(ip)
    status = "OK" if result.returncode == 0 else f"XATO: {result.stderr.strip()}"
    log(f"[BLOKLANDI] {ip} | sabab: {reason} | ufw: {status}")


def register(ip: str, reason: str) -> None:
    if not is_valid_public(ip) or ip in blocked:
        return
    now = time.time()
    q = events[ip]
    q.append(now)
    while q and now - q[0] > WINDOW:
        q.popleft()
    log(f"[HODISA] {ip} | {reason} | {len(q)}/{THRESHOLD}")
    if len(q) >= THRESHOLD:
        block(ip, f"{reason} ({len(q)} ta hodisa/{WINDOW}s)")


def follow(path: str):
    """tail -f ga o'xshash generator."""
    while not os.path.exists(path):
        time.sleep(2)
    with open(path, "r", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        inode = os.fstat(f.fileno()).st_ino
        while True:
            line = f.readline()
            if line:
                yield line
                continue
            time.sleep(0.5)
            try:   # log aylantirilganini (rotate) aniqlash
                if os.stat(path).st_ino != inode:
                    return
            except FileNotFoundError:
                return


def handle_eve(line: str) -> None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return
    if data.get("event_type") != "alert":
        return
    ip = data.get("src_ip", "")
    sig = data.get("alert", {}).get("signature", "noma'lum")
    register(ip, f"Suricata: {sig}")


def handle_auth(line: str) -> None:
    for pattern in (SSH_FAIL, SSH_INVALID):
        m = pattern.search(line)
        if m:
            register(m.group(1), "SSH xato urinishi")
            return


def tail_loop(path: str, handler) -> None:
    while True:
        for line in follow(path):
            handler(line)


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Root huquqi kerak: sudo python3 monitor.py")
    log("monitor.py ishga tushdi")
    import threading
    threads = [
        threading.Thread(target=tail_loop, args=(EVE_LOG, handle_eve), daemon=True),
        threading.Thread(target=tail_loop, args=(AUTH_LOG, handle_auth), daemon=True),
    ]
    for t in threads:
        t.start()
    while True:
        time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("monitor.py to'xtatildi")
