# ZeroGhost

Small multithreaded TCP port scanner written in Python. No external dependencies.

```
 _____                   ________               __
/__  /  ___  _________  / ____/ /_  ____  _____/ /_
  / /  / _ \/ ___/ __ \/ / __/ __ \/ __ \/ ___/ __/
 / /__/  __/ /  / /_/ / /_/ / / / / /_/ (__  ) /_
/____/\___/_/   \____/\____/_/ /_/\____/____/\__/

        By : mammadow1337
```

## Features

- TCP connect scan with a thread pool
- Port lists and ranges (`22,80,443` or `1-65535`)
- Boxed report with risk tags (HIGH/MED/LOW) and a closed-port summary
- Scans all 65535 ports by default, full report can be saved with `-o`
- Optional banner grabbing (`-b`)
- Hostname resolving, clean Ctrl+C handling

## Install

```bash
git clone https://github.com/mammadow1337/zeroghost.git
cd zeroghost
python3 zeroghost.py -h
```

Python 3.7+ is enough. Nothing to pip install.

## Usage

```bash
python3 zeroghost.py 127.0.0.1
python3 zeroghost.py 127.0.0.1 -p 1-1024
python3 zeroghost.py 192.168.1.1 -b -o report.txt
python3 zeroghost.py example.com -p 22,80,443 -t 100 -T 1.5
```

| Flag | Description | Default |
|------|-------------|---------|
| `-p` | ports to scan | `1-65535` |
| `-t` | number of threads | `500` |
| `-T` | timeout per port (seconds) | `0.6` |
| `-b` | grab service banner | off |
| `-o` | save full report to file | - |
| `-q` | hide progress | off |

## Example output

```
╔══════════════════════════════════════════════════════════╗
║ ZEROGHOST REPORT                                         ║
╠══════════════════════════════════════════════════════════╣
║  target   192.168.1.10 (192.168.1.10)                    ║
║  scanned  65535 ports in 14.20s                          ║
║  open     3   closed/filtered  65532                     ║
╚══════════════════════════════════════════════════════════╝

  OPEN PORTS
  ● 22     ssh          [MED]  » SSH-2.0-OpenSSH_8.9p1
  ● 80     http         [LOW]
  ● 445    smb          [HIGH]

  RISK SUMMARY
  HIGH 1   MED 1   LOW 1

  CLOSED / FILTERED
  1-21, 23-79, 81-444, 446-65535
```

## Notes

- Only TCP connect scans, no SYN/UDP scanning.
- Service names come from a small built-in list, not a fingerprint database.

## Disclaimer

For educational use and authorized testing only. Scan only systems you own or have written permission to test (your own machine, a home lab, a CTF or lab environment). The author is not responsible for misuse.

## License

MIT, see [LICENSE](LICENSE).
