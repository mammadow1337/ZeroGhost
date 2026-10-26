#!/usr/bin/env python3
# zeroghost - small TCP port scanner
# By : mammadow1337

import argparse
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[90m"
BOLD = "\033[1m"
END = "\033[0m"

BANNER = r"""
 _____                   ________               __
/__  /  ___  _________  / ____/ /_  ____  _____/ /_
  / /  / _ \/ ___/ __ \/ / __/ __ \/ __ \/ ___/ __/
 / /__/  __/ /  / /_/ / /_/ / / / / /_/ (__  ) /_
/____/\___/_/   \____/\____/_/ /_/\____/____/\__/

        By : mammadow1337
"""

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
    27017: "mongodb",
}

HIGH = {21, 23, 135, 139, 445, 1433, 3389, 5900, 6379, 27017}
MEDIUM = {22, 25, 110, 143, 3306, 5432, 8080}

_lock = threading.Lock()
_done = 0


def parse_ports(spec):
    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            lo, hi = chunk.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 0 < p < 65536)


def risk_of(port):
    if port in HIGH:
        return "HIGH"
    if port in MEDIUM:
        return "MED"
    return "LOW"


def grab_banner(sock):
    try:
        sock.settimeout(1.0)
        sock.sendall(b"\r\n")
        data = sock.recv(128)
        return data.decode(errors="ignore").strip().split("\n")[0][:50]
    except Exception:
        return ""


def probe(host, port, timeout, want_banner, total, quiet):
    global _done
    result = None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((host, port)) == 0:
            result = (port, grab_banner(s) if want_banner else "")
    except OSError:
        pass
    finally:
        s.close()

    with _lock:
        _done += 1
        if not quiet and (_done % 500 == 0 or _done == total):
            pct = _done * 100 // total
            sys.stderr.write(f"\r{DIM}[~] progress {pct:3d}%  ({_done}/{total}){END}")
            sys.stderr.flush()
    return result


def to_ranges(nums):
    """[1,2,3,7,8] -> ['1-3', '7-8']"""
    out = []
    if not nums:
        return out
    start = prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
            continue
        out.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = n
    out.append(f"{start}-{prev}" if start != prev else str(start))
    return out


def color_risk(r):
    return {"HIGH": RED, "MED": YELLOW, "LOW": GREEN}[r] + r + END


def print_report(target, ip, ports, found, took):
    open_ports = [p for p, _ in found]
    closed = [p for p in ports if p not in set(open_ports)]
    high = sum(1 for p in open_ports if risk_of(p) == "HIGH")
    med = sum(1 for p in open_ports if risk_of(p) == "MED")
    low = len(open_ports) - high - med

    width = 58
    line = "═" * width

    def row(text, style=""):
        pad = " " * (width - len(text))
        print(f"{CYAN}║{END}{style}{text}{END if style else ''}{pad}{CYAN}║{END}")

    print(f"\n{CYAN}╔{line}╗{END}")
    row(" ZEROGHOST REPORT", BOLD)
    print(f"{CYAN}╠{line}╣{END}")
    row(f"  target   {target} ({ip})")
    row(f"  scanned  {len(ports)} ports in {took:.2f}s")
    row(f"  open     {len(open_ports)}   closed/filtered  {len(closed)}")
    print(f"{CYAN}╚{line}╝{END}\n")

    if found:
        print(f"{BOLD}  OPEN PORTS{END}")
        for port, info in found:
            svc = SERVICES.get(port, "unknown")
            extra = f"  {DIM}» {info}{END}" if info else ""
            print(f"  {GREEN}●{END} {port:<6} {svc:<12} [{color_risk(risk_of(port))}]{extra}")
    else:
        print(f"  {DIM}no open ports found{END}")

    print(f"\n{BOLD}  RISK SUMMARY{END}")
    print(f"  {RED}HIGH{END} {high}   {YELLOW}MED{END} {med}   {GREEN}LOW{END} {low}")

    print(f"\n{BOLD}  CLOSED / FILTERED{END}")
    ranges = to_ranges(closed)
    shown = ", ".join(ranges[:12])
    more = f" ... (+{len(ranges) - 12} more ranges)" if len(ranges) > 12 else ""
    print(f"  {DIM}{shown}{more}{END}\n")


def save_report(path, target, ip, ports, found, took):
    open_ports = [p for p, _ in found]
    open_set = set(open_ports)
    closed = [p for p in ports if p not in open_set]
    with open(path, "w") as f:
        f.write("ZEROGHOST REPORT - By : mammadow1337\n")
        f.write(f"target : {target} ({ip})\n")
        f.write(f"date   : {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"ports  : {len(ports)} scanned in {took:.2f}s\n\n")
        f.write(f"[OPEN] ({len(open_ports)})\n")
        for port, info in found:
            f.write(f"  {port:<6} {SERVICES.get(port, 'unknown'):<12} "
                    f"{risk_of(port):<5} {info}\n")
        f.write(f"\n[CLOSED/FILTERED] ({len(closed)})\n")
        f.write("  " + ", ".join(to_ranges(closed)) + "\n")
    print(f"{GREEN}[+] full report saved to {path}{END}")


def main():
    ap = argparse.ArgumentParser(description="zeroghost - TCP port scanner")
    ap.add_argument("target", help="IP or hostname")
    ap.add_argument("-p", "--ports", default="1-65535",
                    help="e.g. 80,443 or 1-1024 (default: all 65535)")
    ap.add_argument("-t", "--threads", type=int, default=500)
    ap.add_argument("-T", "--timeout", type=float, default=0.6)
    ap.add_argument("-b", "--banner", action="store_true",
                    help="try to grab service banner")
    ap.add_argument("-o", "--output", help="save full report to a file")
    ap.add_argument("-q", "--quiet", action="store_true", help="no progress")
    args = ap.parse_args()

    print(CYAN + BANNER + END)

    try:
        ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"{RED}[!] cannot resolve {args.target}{END}")
        sys.exit(1)

    ports = parse_ports(args.ports)
    print(f"[*] target : {args.target} ({ip})")
    print(f"[*] ports  : {len(ports)}")
    print(f"[*] started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

    start = time.time()
    found = []
    total = len(ports)

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = [pool.submit(probe, ip, p, args.timeout, args.banner,
                                   total, args.quiet) for p in ports]
            for f in futures:
                res = f.result()
                if res:
                    found.append(res)
    except KeyboardInterrupt:
        print(f"\n{RED}[!] interrupted{END}")

    found.sort()
    sys.stderr.write("\r" + " " * 50 + "\r")
    took = time.time() - start
    print_report(args.target, ip, ports, found, took)

    if args.output:
        save_report(args.output, args.target, ip, ports, found, took)


if __name__ == "__main__":
    main()
