# Playbook: malicious document to data exfiltration

**Triggers:** `IDT-SG-002` Office spawning a shell, `IDT-SG-001` encoded PowerShell, `IDT-SG-003`
certutil download, `IDT-SG-007` scheduled task, `IDT-SG-006` discovery commands, `IDT-006` beaconing,
`IDT-SG-004` LSASS access, `IDT-005` internal sweep, `IDT-SG-005` PsExec, `IDT-007` large upload.
ATT&CK: T1566.001, T1059.001, T1105, T1053.005, T1071.001, T1003.001, T1021.002, T1048.

This is the pattern the pipeline ranks P1: several stages on one host within an hour. If the
incident shows three or more of these detections together, skip straight to containment.

## 1. Contain first, ask questions after

1. Isolate the workstation with your EDR (network containment, not power-off, to keep memory).
2. Disable the user account and any admin account used from that host after the LSASS alert.
3. Block the C2 IP and domain at firewall, proxy and DNS.

## 2. Scope

```spl
index=sysmon host=<HOST> earliest=-2h
| search EventCode IN (1,3,10,22)
| sort _time | table _time EventCode Image ParentImage CommandLine DestinationIp QueryName
```

- **Initial vector:** which document, from which email? Pull the message and delete it org-wide.
- **Payload:** decode the `-enc` string, recover the downloaded file (`certutil -urlcache ...`), detonate in a sandbox.
- **Persistence:** list scheduled tasks and Run keys created in the window.
- **Credential exposure:** an LSASS access alert means every credential that was cached on that host is stolen.
- **Lateral movement:** which hosts received SMB connections or PsExec from this machine? Repeat steps 1-2 for each.
- **Data loss:** how many bytes left, to where, and what was on the source file shares?

## 3. Recover

Rebuild the workstation from a clean image; reset all exposed credentials; rotate `krbtgt` twice if a
domain admin credential was exposed; remove the persistence mechanism on every touched host.

## 4. Close out

Document the timeline (the incident report already contains one), notify the data owner and
legal/compliance if data left the network, and add a detection for any stage that did not alert.
