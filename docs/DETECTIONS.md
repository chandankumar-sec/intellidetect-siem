# Detection catalog

20 detections, each mapped to a MITRE ATT&CK tactic and technique. `sigma` rules are single-event and portable (see `src/intellidetect/rules/sigma/`); the other types are stateful and defined in `src/intellidetect/rules/native.yml`.

| ID | Detection | Severity | Tactic | Technique | Type |
|---|---|---|---|---|---|
| `IDT-006` | Periodic Outbound Connections (Possible C2 Beaconing) | high | Command and Control | T1071.001 Application Layer Protocol: Web Protocols | beacon |
| `IDT-SG-003` | Certutil Used to Download or Decode Files | high | Command and Control | T1105 Ingress Tool Transfer | sigma |
| `IDT-SG-012` | DNS Query to Abuse-Prone Top-Level Domain | low | Command and Control | T1071.001 Application Layer Protocol: Web Protocols | sigma |
| `IDT-001` | SSH Brute Force From Single Source | high | Credential Access | T1110.001 Brute Force: Password Guessing | threshold |
| `IDT-002` | Password Spraying (Many Accounts, One Source) | high | Credential Access | T1110.003 Brute Force: Password Spraying | distinct |
| `IDT-SG-004` | Process Accessing LSASS Memory | critical | Credential Access | T1003.001 OS Credential Dumping: LSASS Memory | sigma |
| `IDT-004` | Port Scan (Many Ports, One Source) | medium | Discovery | T1046 Network Service Discovery | distinct |
| `IDT-005` | Internal Service Sweep (Many Hosts, Admin Ports) | high | Discovery | T1046 Network Service Discovery | distinct |
| `IDT-SG-006` | Account and Domain Discovery Commands | medium | Discovery | T1087 Account Discovery | sigma |
| `IDT-SG-001` | Suspicious Encoded PowerShell Command Line | high | Execution | T1059.001 Command and Scripting Interpreter: PowerShell | sigma |
| `IDT-SG-011` | Sudo Used to Download and Execute a Script | high | Execution | T1059.004 Command and Scripting Interpreter: Unix Shell | sigma |
| `IDT-007` | Large Outbound Data Transfer | high | Exfiltration | T1048 Exfiltration Over Alternative Protocol | threshold |
| `IDT-003` | Successful Login After Brute Force | critical | Initial Access | T1078 Valid Accounts | sequence |
| `IDT-SG-002` | Office Application Spawning Script Interpreter or Shell | high | Initial Access | T1566.001 Phishing: Spearphishing Attachment | sigma |
| `IDT-SG-008` | SQL Injection Pattern in Web Request | high | Initial Access | T1190 Exploit Public-Facing Application | sigma |
| `IDT-SG-009` | Path Traversal Attempt in Web Request | high | Initial Access | T1190 Exploit Public-Facing Application | sigma |
| `IDT-SG-005` | PsExec Style Remote Service Execution | high | Lateral Movement | T1021.002 Remote Services: SMB/Windows Admin Shares | sigma |
| `IDT-SG-007` | Scheduled Task Created From Command Line | medium | Persistence | T1053.005 Scheduled Task/Job: Scheduled Task | sigma |
| `IDT-SG-010` | Web Shell Upload or Command Parameter Access | critical | Persistence | T1505.003 Server Software Component: Web Shell | sigma |
| `IDT-008` | Web Scanning (Burst of 404 Responses) | medium | Reconnaissance | T1595 Active Scanning | threshold |

## Rule types

| Type | What it detects | Example |
|---|---|---|
| `sigma` | One event matching field conditions (`contains`, `endswith`, `re`, `1 of`, `not`) | Office spawning PowerShell |
| `threshold` | N events (or a sum of a numeric field) from one key within a time window | 8 failed SSH logins in 120 s |
| `distinct` | N distinct values of a field within a window | 15 ports probed in 60 s |
| `sequence` | A trigger event preceded by N related events for the same key | Login success after 5 failures |
| `beacon` | Regular-interval connections (low jitter) from a host to one destination | C2 check-in every 60 s |

To see the Splunk version of every Sigma rule: `intellidetect sigma-to-spl`.
