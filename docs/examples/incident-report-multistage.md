# INC-002: Multi-stage intrusion (Initial Access to Exfiltration) involving WS-ALICE, FILESRV01

| Priority | Risk score | Severity | First seen (UTC) | Last seen (UTC) |
|---|---|---|---|---|
| **P1** | 96/100 | critical | 2026-03-10 11:10:00 | 2026-03-10 11:39:37 |

## Summary

Between 2026-03-10 11:10:00 and 2026-03-10 11:39:37 UTC (about 30 min), 11 detection(s) were correlated into one incident covering 8 ATT&CK tactic(s): Initial Access, Execution, Persistence, Credential Access, Discovery, Lateral Movement, Command and Control, Exfiltration. Affected hosts: WS-ALICE, FILESRV01. Accounts involved: CORP\alice. External addresses: 192.0.2.77, 192.0.2.99. Threat-intel matches: update-cdn-sync.top (Malware C2 domain); 192.0.2.77 (Malware C2 server); 192.0.2.99 (Data staging / exfiltration drop).

## Kill-chain timeline

| Time (UTC) | Tactic | Technique | Detection | Entity | Events |
|---|---|---|---|---|---|
| 2026-03-10 11:10:00 | Initial Access | T1566.001 Phishing: Spearphishing Attachment | Office Application Spawning Script Interpreter or Shell (`IDT-SG-002`) | WS-ALICE | 1 |
| 2026-03-10 11:10:05 | Execution | T1059.001 Command and Scripting Interpreter: PowerShell | Suspicious Encoded PowerShell Command Line (`IDT-SG-001`) | WS-ALICE | 1 |
| 2026-03-10 11:10:30 | Command and Control | T1071.001 Application Layer Protocol: Web Protocols | DNS Query to Abuse-Prone Top-Level Domain (`IDT-SG-012`) | WS-ALICE | 1 |
| 2026-03-10 11:10:40 | Command and Control | T1105 Ingress Tool Transfer | Certutil Used to Download or Decode Files (`IDT-SG-003`) | WS-ALICE | 1 |
| 2026-03-10 11:12:00 | Persistence | T1053.005 Scheduled Task/Job: Scheduled Task | Scheduled Task Created From Command Line (`IDT-SG-007`) | WS-ALICE | 1 |
| 2026-03-10 11:13:00 | Discovery | T1087 Account Discovery | Account and Domain Discovery Commands (`IDT-SG-006`) | WS-ALICE | 3 |
| 2026-03-10 11:13:28 | Command and Control | T1071.001 Application Layer Protocol: Web Protocols | Periodic Outbound Connections (Possible C2 Beaconing) (`IDT-006`) | WS-ALICE | 22 |
| 2026-03-10 11:18:00 | Discovery | T1046 Network Service Discovery | Internal Service Sweep (Many Hosts, Admin Ports) (`IDT-005`) | 10.0.10.21 | 23 |
| 2026-03-10 11:22:00 | Credential Access | T1003.001 OS Credential Dumping: LSASS Memory | Process Accessing LSASS Memory (`IDT-SG-004`) | WS-ALICE | 1 |
| 2026-03-10 11:26:00 | Lateral Movement | T1021.002 Remote Services: SMB/Windows Admin Shares | PsExec Style Remote Service Execution (`IDT-SG-005`) | FILESRV01 | 1 |
| 2026-03-10 11:30:00 | Exfiltration | T1048 Exfiltration Over Alternative Protocol | Large Outbound Data Transfer (`IDT-007`) | 10.0.10.21 | 11 |

## Why this score

| Points | Reason |
|---|---|
| +40 | Highest alert severity: critical |
| +24 | Kill-chain progression: 8 tactics (Initial Access > Execution > Persistence > Credential Access > Discovery > Lateral Movement > Command and Control > Exfiltration) |
| +12 | Involves critical asset FILESRV01 |
| +15 | Threat-intel match: 192.0.2.77 (Malware C2 server) |
| +5 | Sustained activity: 66 underlying detections |
| **96** | **Total** |

## Entities and indicators

- **Hosts:** `WS-ALICE`, `FILESRV01`
- **Users:** `CORP\alice`
- **External IPs:** `192.0.2.77`, `192.0.2.99`
- **Intel:** `update-cdn-sync.top`: Malware C2 domain (confidence 90, source synthetic-demo-feed)
- **Intel:** `192.0.2.77`: Malware C2 server (confidence 95, source synthetic-demo-feed)
- **Intel:** `192.0.2.99`: Data staging / exfiltration drop (confidence 90, source synthetic-demo-feed)

## Evidence

**IDT-SG-002 Office Application Spawning Script Interpreter or Shell**

```text
2026-03-10 11:10:00.000 UTC;EventID 1;ProcessCreate;Computer=WS-ALICE;User=CORP\alice;Image=C:\Windows\System32\cmd.exe;ParentImage=C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE;CommandLine=cmd.exe /c power
```

**IDT-SG-001 Suspicious Encoded PowerShell Command Line**

```text
2026-03-10 11:10:05.000 UTC;EventID 1;ProcessCreate;Computer=WS-ALICE;User=CORP\alice;Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;ParentImage=C:\Windows\System32\cmd.exe;CommandLine=powershell.exe -w 
```

**IDT-SG-012 DNS Query to Abuse-Prone Top-Level Domain**

```text
2026-03-10 11:10:30.000 UTC;EventID 22;DNSQuery;Computer=WS-ALICE;User=CORP\alice;QueryName=update-cdn-sync.top;Image=C:\Windows\System32\svchost.exe
```

**IDT-SG-003 Certutil Used to Download or Decode Files**

```text
2026-03-10 11:10:40.000 UTC;EventID 1;ProcessCreate;Computer=WS-ALICE;User=CORP\alice;Image=C:\Windows\System32\certutil.exe;ParentImage=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;CommandLine=certutil.exe 
```

**IDT-SG-007 Scheduled Task Created From Command Line**

```text
2026-03-10 11:12:00.000 UTC;EventID 1;ProcessCreate;Computer=WS-ALICE;User=CORP\alice;Image=C:\Windows\System32\schtasks.exe;ParentImage=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe;CommandLine=schtasks.exe 
```

**IDT-SG-006 Account and Domain Discovery Commands**

```text
2026-03-10 11:13:00.000 UTC;EventID 1;ProcessCreate;Computer=WS-ALICE;User=CORP\alice;Image=C:\Windows\System32\cmd.exe;ParentImage=C:\Users\alice\AppData\Local\Temp\p.exe;CommandLine=whoami /priv;ProcessId=44898
```

**IDT-006 Periodic Outbound Connections (Possible C2 Beaconing)**

```text
2026-03-10 11:13:28.737 UTC;EventID 3;NetworkConnect;Computer=WS-ALICE;User=CORP\alice;Image=C:\Users\alice\AppData\Local\Temp\p.exe;SourceIp=10.0.10.21;DestinationIp=192.0.2.77;DestinationPort=443;Protocol=tcp
2026-03-10 11:14:29.792 UTC;EventID 3;NetworkConnect;Computer=WS-ALICE;User=CORP\alice;Image=C:\Users\alice\AppData\Local\Temp\p.exe;SourceIp=10.0.10.21;DestinationIp=192.0.2.77;DestinationPort=443;Protocol=tcp
```

**IDT-005 Internal Service Sweep (Many Hosts, Admin Ports)**

```text
2026-03-10 11:18:00 ALLOW TCP 10.0.10.21:60833 -> 10.0.2.5:445 BYTES=600
2026-03-10 11:18:02 DROP TCP 10.0.10.21:31173 -> 10.0.2.6:445 BYTES=600
```

**IDT-SG-004 Process Accessing LSASS Memory**

```text
2026-03-10 11:22:00.000 UTC;EventID 10;ProcessAccess;Computer=WS-ALICE;User=CORP\alice;SourceImage=C:\Users\alice\AppData\Local\Temp\p.exe;TargetImage=C:\Windows\System32\lsass.exe;GrantedAccess=0x1410
```

**IDT-SG-005 PsExec Style Remote Service Execution**

```text
2026-03-10 11:26:00.000 UTC;EventID 1;ProcessCreate;Computer=FILESRV01;User=CORP\SYSTEM;Image=C:\Windows\PSEXESVC.exe;ParentImage=C:\Windows\System32\services.exe;CommandLine=C:\Windows\PSEXESVC.exe;ProcessId=4119
```

**IDT-007 Large Outbound Data Transfer**

```text
2026-03-10 11:30:00 ACCEPT TCP 10.0.10.21:12631 -> 192.0.2.99:443 BYTES=52026138
2026-03-10 11:30:35 ACCEPT TCP 10.0.10.21:58726 -> 192.0.2.99:443 BYTES=51809725
```

## Recommended response

1. Pull the original phishing email, delete it from all mailboxes and block the sender and URLs.
2. Isolate the host from the network (EDR containment) before further triage.
3. Decode the PowerShell payload, extract URLs, IPs and file paths, and hunt for them fleet-wide.
4. Block the C2 address and domain at the proxy, firewall and DNS.
5. Search other hosts for connections to the same destination (hunt for additional victims).
6. Retrieve the downloaded payload for sandbox analysis and block the source URL or IP.
7. Delete the rogue scheduled task after collecting its action; look for other persistence.
8. Review what the account enumerated and whether the same user ran other discovery commands.
9. Identify the scanning host; if internal, treat it as a likely compromised system.
10. Treat every credential on the host as stolen: reset the user and any admin that logged on recently.
11. Rotate krbtgt twice if a domain controller or domain admin credential may be exposed.
12. Isolate the destination host, collect the dropped service binary and check for new accounts.
13. Quantify what left the network (bytes, destination, timeframe) and involve the data owner.
14. Check legal and regulatory notification requirements before closing the incident.
15. Preserve evidence (memory, logs, disk image) before remediation.
16. Document the timeline, scope and containment steps in the ticket.

## Analyst notes

- [ ] Verdict: true positive / benign true positive / false positive
- [ ] Scope confirmed (other hosts, other accounts)
- [ ] Containment done
- [ ] Detection tuned or new rule written
