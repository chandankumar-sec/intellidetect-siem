# Playbook: SSH brute force and account takeover

**Triggers:** `IDT-001` SSH brute force, `IDT-002` password spraying, `IDT-003` login success after
brute force (critical), `IDT-SG-011` sudo download-and-execute. ATT&CK: T1110, T1078, T1059.004.

## 1. Decide how urgent it is (2 minutes)

| Question | If yes |
|---|---|
| Did `IDT-003` fire (a login succeeded after the failures)? | Treat as a compromise. Go to step 3 now. |
| Is the source IP internal and on the scanner allow-list? | Likely an authorized scan. Confirm and close. |
| Did the account then run `sudo`? | Assume root-level access. |

## 2. Investigate

```spl
index=linux sourcetype=linux_secure "Failed password" src_ip=<ATTACKER_IP>
| stats count dc(user) AS accounts earliest(_time) AS first latest(_time) AS last by src_ip
```

```spl
index=linux sourcetype=linux_secure (Accepted OR sudo) (src_ip=<ATTACKER_IP> OR user=<ACCOUNT>)
| sort _time | table _time host user src_ip _raw
```

- Which accounts were targeted, and did any succeed? Compare against accounts that exist on the host.
- What happened between the successful login and now: new SSH keys (`~/.ssh/authorized_keys`),
  cron jobs, new users, outbound connections?
- Search for the same source IP on other hosts and in the firewall logs.

## 3. Contain

1. Block the source IP at the perimeter.
2. Disable the compromised account, kill its sessions, rotate its password and SSH keys.
3. If `sudo` ran a downloaded script, isolate the host and preserve it for forensics.
4. Hunt the downloaded URL or IP across DNS, proxy and firewall logs.

## 4. Close out

- True positive: document timeline, accounts touched and scope; write or tune a detection if one was missed.
- Benign: record the reason and add the source to `trusted_scanners` only if it is a managed scanner.
- Hardening follow-ups: key-only SSH, MFA on the jump host, fail2ban or equivalent rate limiting.
