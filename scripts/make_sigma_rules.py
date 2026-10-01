"""One-off helper that (re)generates the bundled Sigma rule files.

Kept in the repo so the rules stay reproducible; edit the YAML files directly for normal tuning.
"""

import uuid
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "src" / "intellidetect" / "rules" / "sigma"
NS = uuid.UUID("6f1b7c1e-0000-4000-8000-000000000000")

RULES = [
    (
        "idt-sg-001-powershell-encoded-command",
        "Suspicious Encoded PowerShell Command Line",
        "Detects PowerShell started with an encoded command or a hidden, execution-policy-bypass "
        "launch. Common in phishing payload stagers and living-off-the-land intrusions.",
        ["attack.execution", "attack.t1059.001"],
        "process_creation",
        r"""    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_flags:
        CommandLine|contains:
            - ' -enc '
            - ' -encodedcommand '
            - '-w hidden'
            - '-windowstyle hidden'
            - 'bypass'
    condition: selection_img and selection_flags""",
        "high",
        ["Admin scripts that use -ExecutionPolicy Bypass (tune by parent process or signer)"],
    ),
    (
        "idt-sg-002-office-spawns-shell",
        "Office Application Spawning Script Interpreter or Shell",
        "A Microsoft Office process launching cmd, PowerShell, wscript, cscript or mshta is a "
        "classic malicious-document execution pattern (macro or exploit).",
        ["attack.initial_access", "attack.t1566.001", "attack.t1204.002"],
        "process_creation",
        r"""    selection_parent:
        ParentImage|endswith:
            - '\winword.exe'
            - '\excel.exe'
            - '\powerpnt.exe'
            - '\outlook.exe'
    selection_child:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\mshta.exe'
    condition: selection_parent and selection_child""",
        "high",
        ["Rare: some legacy Office add-ins launch cmd.exe"],
    ),
    (
        "idt-sg-003-certutil-download",
        "Certutil Used to Download or Decode Files",
        "certutil.exe with -urlcache or -decode is a well known way to fetch and unpack payloads "
        "while avoiding custom download tools.",
        ["attack.command_and_control", "attack.t1105"],
        "process_creation",
        r"""    selection_img:
        Image|endswith: '\certutil.exe'
    selection_args:
        CommandLine|contains:
            - 'urlcache'
            - '-decode'
            - 'verifyctl'
    condition: selection_img and selection_args""",
        "high",
        ["Administrators decoding certificates (rare)"],
    ),
    (
        "idt-sg-004-lsass-memory-access",
        "Process Accessing LSASS Memory",
        "A non-system process opening lsass.exe with read or dump access rights indicates "
        "credential dumping (Mimikatz, procdump, comsvcs MiniDump).",
        ["attack.credential_access", "attack.t1003.001"],
        "process_access",
        r"""    selection:
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess:
            - '0x1010'
            - '0x1410'
            - '0x1438'
            - '0x143a'
            - '0x1fffff'
    filter_system:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Program Files\Windows Defender\'
    condition: selection and not filter_system""",
        "critical",
        ["EDR and AV agents reading LSASS (add their paths to the filter)"],
    ),
    (
        "idt-sg-005-psexec-remote-execution",
        "PsExec Style Remote Service Execution",
        "psexec.exe, PSEXESVC or paexec on a host indicates remote execution over SMB, a staple "
        "of lateral movement.",
        ["attack.lateral_movement", "attack.t1021.002", "attack.t1569.002"],
        "process_creation",
        r"""    selection:
        - Image|endswith:
              - '\psexec.exe'
              - '\psexesvc.exe'
              - '\paexec.exe'
        - CommandLine|contains: 'psexec'
    condition: selection""",
        "high",
        ["Sysadmins using Sysinternals PsExec (keep an approved-use list)"],
    ),
    (
        "idt-sg-006-ad-discovery-commands",
        "Account and Domain Discovery Commands",
        "net user /domain, nltest and whoami /priv are typically run in quick succession by an "
        "attacker orienting inside a network.",
        ["attack.discovery", "attack.t1087"],
        "process_creation",
        r"""    selection:
        CommandLine|contains:
            - 'net user /domain'
            - 'net group "domain admins"'
            - 'nltest /dclist'
            - 'whoami /priv'
            - 'whoami /groups'
    condition: selection""",
        "medium",
        ["Help-desk and admin troubleshooting"],
    ),
    (
        "idt-sg-007-scheduled-task-creation",
        "Scheduled Task Created From Command Line",
        "schtasks /create is a common persistence mechanism. Review the task action and the "
        "parent process.",
        ["attack.persistence", "attack.t1053.005"],
        "process_creation",
        r"""    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains: '/create'
    condition: selection""",
        "medium",
        ["Software installers and IT automation"],
    ),
    (
        "idt-sg-008-web-sql-injection",
        "SQL Injection Pattern in Web Request",
        "Common SQL injection payloads (UNION SELECT, boolean tautologies, time-based "
        "functions) in the request URL.",
        ["attack.initial_access", "attack.t1190"],
        "webserver",
        r"""    selection:
        url|contains:
            - 'union select'
            - 'union%20select'
            - "' or 1=1"
            - "'%20or%201=1"
            - 'sleep('
            - 'information_schema'
    condition: selection""",
        "high",
        ["Security scanners run by the owner of the application"],
    ),
    (
        "idt-sg-009-web-path-traversal",
        "Path Traversal Attempt in Web Request",
        "Directory traversal sequences (including URL-encoded variants) aimed at reading files "
        "outside the web root.",
        ["attack.initial_access", "attack.t1190"],
        "webserver",
        r"""    selection:
        url|contains:
            - '../../'
            - '..%2f'
            - '%2e%2e%2f'
            - '/etc/passwd'
    condition: selection""",
        "high",
        ["None expected"],
    ),
    (
        "idt-sg-010-web-shell-activity",
        "Web Shell Upload or Command Parameter Access",
        "Requests to a script inside an upload directory or passing a command parameter "
        "indicate a web shell has been planted or is being used.",
        ["attack.persistence", "attack.t1505.003"],
        "webserver",
        r"""    selection_upload:
        uri_path|contains: '/uploads/'
        uri_path|endswith:
            - '.php'
            - '.jsp'
            - '.aspx'
    selection_cmd:
        uri_query|contains:
            - 'cmd='
            - 'exec='
    condition: selection_upload or selection_cmd""",
        "critical",
        ["None expected"],
    ),
    (
        "idt-sg-011-sudo-download-and-execute",
        "Sudo Used to Download and Execute a Script",
        "A sudo command that pipes curl or wget output into a shell downloads and runs remote "
        "code as root.",
        ["attack.execution", "attack.t1059.004", "attack.t1105"],
        "sudo",
        r"""    selection_dl:
        command|contains:
            - 'curl '
            - 'wget '
    selection_exec:
        command|contains:
            - '| bash'
            - '| sh'
            - '|bash'
            - '|sh'
    condition: selection_dl and selection_exec""",
        "high",
        ["Documented installers (for example package manager bootstrap scripts)"],
    ),
    (
        "idt-sg-012-dns-suspicious-tld",
        "DNS Query to Abuse-Prone Top-Level Domain",
        "Queries for .top, .xyz, .click or .zip domains are overrepresented in malware C2 and "
        "phishing infrastructure. Treat as a lead, not a verdict.",
        ["attack.command_and_control", "attack.t1071.001"],
        "dns_query",
        r"""    selection:
        QueryName|endswith:
            - '.top'
            - '.xyz'
            - '.click'
            - '.zip'
    condition: selection""",
        "low",
        ["Legitimate sites on these TLDs"],
    ),
]


def logsource(category: str) -> str:
    if category == "sudo":
        return "service: sudo\n    product: linux"
    if category == "webserver":
        return "category: webserver"
    return f"category: {category}\n    product: windows"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for n, (slug, title, desc, tags, cat, detection, level, fps) in enumerate(RULES, 1):
        tag_lines = "\n".join(f"    - {t}" for t in tags)
        fp_lines = "\n".join(f"    - {f}" for f in fps)
        text = (
            f"title: {title}\n"
            f"id: {uuid.uuid5(NS, slug)}\n"
            f"name: IDT-SG-{n:03d}\n"
            "status: stable\n"
            f"description: |\n    {desc}\n"
            "author: Chandan Kumar\n"
            "date: 2026/09/30\n"
            f"tags:\n{tag_lines}\n"
            f"logsource:\n    {logsource(cat)}\n"
            f"detection:\n{detection}\n"
            f"falsepositives:\n{fp_lines}\n"
            f"level: {level}\n"
        )
        (OUT / f"{slug}.yml").write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {len(RULES)} Sigma rules to {OUT}")


if __name__ == "__main__":
    main()
