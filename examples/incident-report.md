# SOC incident report

- Generated: 2026-11-03T18:00:00Z
- Events analyzed: 181
- Parse errors: 0
- Lines skipped by the auth parser: 2
- Alerts: 11
- Highest severity: critical
- Anomaly model ran: yes

## Executive summary

Rule matches and IsolationForest outliers are listed below, highest severity first. Confirmed access means a successful authentication followed credential failures, or a web payload received a status below 400.

## Severity

| Severity | Alerts |
| --- | ---: |
| critical | 3 |
| high | 3 |
| medium | 5 |
| low | 0 |

## MITRE ATT&CK

| Technique | Name | Alerts |
| --- | --- | ---: |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | 2 |
| [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Domain Accounts | 1 |
| [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing | 2 |
| [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | Password Spraying | 2 |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | 2 |
| [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Vulnerability Scanning | 2 |

## Alerts

### ALT-C610A4EF — CRITICAL (93) — SQL injection pattern

- Rule: `sql-injection` (rule)
- Entity: src_ip=203.0.113.70
- Events: 2
- Window: 2026-11-03T15:03:30Z → 2026-11-03T15:03:48Z
- ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) / Initial Access
- Confirmed access: yes

A request URL matches a small set of SQL injection shapes (UNION SELECT, OR 1=1, information_schema, SLEEP, BENCHMARK, xp_cmdshell) after percent-decoding. At least one matching request returned a status below 400.

**Evidence**

```text
203.0.113.70 - - [03/Nov/2026:15:03:30 +0000] "GET /search?q=%27%20OR%201%3D1-- HTTP/1.1" 500 220 "-" "sqlmap/1.8"
203.0.113.70 - - [03/Nov/2026:15:03:48 +0000] "GET /index.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1" 200 2600 "-" "sqlmap/1.8"
```

**Tier-1 action.** Treat a status below 400 as a possible successful injection and escalate with the full URL. For 4xx or 5xx responses, block the source if it is not an approved test and review the application error log.

**False-positive checks.**

- A blog or ticketing page that quotes a SQL example in a query string
- Application test fixtures that ship a literal "union select"

### ALT-C6F9F4FD — CRITICAL (91) — Path traversal

- Rule: `path-traversal` (rule)
- Entity: src_ip=203.0.113.70
- Events: 2
- Window: 2026-11-03T15:03:00Z → 2026-11-03T15:03:12Z
- ATT&CK: [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) / Initial Access
- Confirmed access: yes

A web request path or query contains a directory traversal sequence or a direct read of a sensitive Unix file. The URL is percent-decoded twice before matching. At least one matching request returned a status below 400.

**Evidence**

```text
203.0.113.70 - - [03/Nov/2026:15:03:00 +0000] "GET /static/%2e%2e/%2e%2e/etc/shadow HTTP/1.1" 400 90 "-" "curl/8.5.0"
203.0.113.70 - - [03/Nov/2026:15:03:12 +0000] "GET /download?file=../../etc/passwd HTTP/1.1" 200 1400 "-" "curl/8.5.0"
```

**Tier-1 action.** Capture the response status and body size. A status below 400 on a traversal URL is a possible file read: isolate the host and escalate to Tier-2. A 4xx can stay at high while you confirm the WAF or app rejected it.

**False-positive checks.**

- An application that legitimately echoes a path containing ".."
- A security test that was scheduled and is still in window

### ALT-F9FFF090 — CRITICAL (91) — SSH brute force

- Rule: `ssh-brute-force` (rule)
- Entity: src_ip=203.0.113.50, user=root
- Events: 16
- Window: 2026-11-03T11:00:00Z → 2026-11-03T11:06:00Z
- ATT&CK: [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) / Credential Access
- Confirmed access: yes

Many failed SSH password attempts for one account from a single source address inside a short window. This is the usual shape of online password guessing against sshd. A successful authentication followed the failures.

**Evidence**

```text
Nov  3 11:00:00 lab-ssh sshd[7000]: Failed password for root from 203.0.113.50 port 40000 ssh2
Nov  3 11:00:20 lab-ssh sshd[7001]: Failed password for root from 203.0.113.50 port 40001 ssh2
Nov  3 11:00:40 lab-ssh sshd[7002]: Failed password for root from 203.0.113.50 port 40002 ssh2
Nov  3 11:01:00 lab-ssh sshd[7003]: Failed password for root from 203.0.113.50 port 40003 ssh2
Nov  3 11:06:00 lab-ssh sshd[3016]: Accepted password for root from 203.0.113.50 port 40016 ssh2
```

**Tier-1 action.** Confirm the source is not a known scanner. If any attempt then succeeded, reset that credential, invalidate sessions, and escalate to Tier-2 with the raw lines attached.

**False-positive checks.**

- A user or script retrying one mistyped password
- An approved credential-audit appliance

### ALT-C200CD6F — HIGH (80) — Impossible travel

- Rule: `impossible-travel` (rule)
- Entity: user=alice
- Events: 2
- Window: 2026-11-03T14:08:00Z → 2026-11-03T14:22:00Z
- ATT&CK: [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) / Defense Evasion
- Confirmed access: no

The same account authenticates successfully from two points that are too far apart for the time between them, faster than 900 km/h after a 500 km minimum. Lab cities come from the built-in TEST-NET map, not from a live GeoIP database.

**Evidence**

```text
Nov  3 14:08:00 lab-ssh sshd[6002]: Accepted publickey for alice from 198.51.100.30 port 43002 ssh2
Nov  3 14:22:00 lab-ssh sshd[6003]: Accepted password for alice from 203.0.113.80 port 43003 ssh2
```

**Tier-1 action.** Ask the account owner whether they traveled or used a VPN. If they did not, reset the credential, revoke sessions, and review both source addresses.

**False-positive checks.**

- Corporate VPN or cloud egress that changes city between requests
- An account shared by operators in two regions

### ALT-71A2475C — HIGH (74) — Off-hours privileged logon

- Rule: `off-hours-admin` (rule)
- Entity: user=Administrator
- Events: 1
- Window: 2026-11-03T02:17:00Z → 2026-11-03T02:17:00Z
- ATT&CK: [T1078.002 Domain Accounts](https://attack.mitre.org/techniques/T1078/002/) / Defense Evasion
- Confirmed access: no

A privileged account (root, Administrator, an elevated Windows token, or Event ID 4672) authenticates successfully outside 08:00-18:00 UTC on a weekday, or at any time on Saturday or Sunday.

**Evidence**

```text
{"TimeCreated": "2026-11-03T02:17:00Z", "EventID": 4624, "Computer": "DC01", "TargetUserName": "Administrator", "IpAddress": "192.0.2.40", "LogonType": 10, "ElevatedToken": true}
```

**Tier-1 action.** Match the logon to a change ticket or on-call rota. Interactive logons (SSH, or Windows logon type 10) without a ticket should be escalated, the credential rotated, and the source address reviewed.

**False-positive checks.**

- A documented on-call change window
- A backup or directory job running as a privileged service account

### ALT-25E096C9 — HIGH (72) — Password spraying

- Rule: `password-spray` (rule)
- Entity: src_ip=203.0.113.60
- Events: 12
- Window: 2026-11-03T12:00:00Z → 2026-11-03T12:05:30Z
- ATT&CK: [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) / Credential Access
- Confirmed access: no

One source address fails authentication against many accounts, with only a few tries each. Spraying stays under a per-account lockout and still tests a common password.

**Evidence**

```text
Nov  3 12:00:00 lab-ssh sshd[8000]: Failed password for invalid user svc01 from 203.0.113.60 port 41000 ssh2
Nov  3 12:00:30 lab-ssh sshd[8001]: Failed password for invalid user svc02 from 203.0.113.60 port 41001 ssh2
Nov  3 12:01:00 lab-ssh sshd[8002]: Failed password for invalid user svc03 from 203.0.113.60 port 41002 ssh2
Nov  3 12:01:30 lab-ssh sshd[8003]: Failed password for invalid user svc04 from 203.0.113.60 port 41003 ssh2
Nov  3 12:02:00 lab-ssh sshd[8004]: Failed password for invalid user svc05 from 203.0.113.60 port 41004 ssh2
```

**Tier-1 action.** Compare the account list with a known jump box or vulnerability scanner. If the source is not approved, block it at the edge and reset any account that authenticated successfully from it afterward.

**False-positive checks.**

- A jump host where many users mistype a password once
- Directory-join or monitoring checks that probe a user list

### ALT-AEEB117D — MEDIUM (68) — Anomalous src_ip behavior

- Rule: `isolation-forest` (anomaly)
- Entity: src_ip=203.0.113.70
- Events: 22
- Window: 2026-11-03T15:00:00Z → 2026-11-03T15:03:48Z
- ATT&CK: [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) / Reconnaissance
- Confirmed access: no

IsolationForest fit on this batch marked the entity as an outlier. Dominant feature unique_paths=22.00. decision_function=-0.080. Review it next to any rule alerts for the same entity. Do not contain on this signal alone.

**Evidence**

```text
203.0.113.70 - - [03/Nov/2026:15:00:00 +0000] "GET /.env HTTP/1.1" 404 180 "-" "nikto/2.5.0"
203.0.113.70 - - [03/Nov/2026:15:00:08 +0000] "GET /.git/config HTTP/1.1" 404 180 "-" "nikto/2.5.0"
203.0.113.70 - - [03/Nov/2026:15:00:16 +0000] "GET /admin HTTP/1.1" 404 180 "-" "nikto/2.5.0"
```

**Tier-1 action.** Compare the entity with peer workstations or accounts from the same batch. Escalate only if a rule-based alert, a successful login, or an unusual geo corroborates the outlier.

**False-positive checks.**

- A busy but legitimate host that is rare inside this particular batch
- A population that is mostly attack traffic, which makes outliers unstable

### ALT-0C5D2AC6 — MEDIUM (64) — Anomalous user behavior

- Rule: `isolation-forest` (anomaly)
- Entity: user=root
- Events: 16
- Window: 2026-11-03T11:00:00Z → 2026-11-03T11:06:00Z
- ATT&CK: [T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001/) / Credential Access
- Confirmed access: no

IsolationForest fit on this batch marked the entity as an outlier. Dominant feature log_fail=2.77. decision_function=-0.052. Review it next to any rule alerts for the same entity. Do not contain on this signal alone.

**Evidence**

```text
Nov  3 11:00:00 lab-ssh sshd[7000]: Failed password for root from 203.0.113.50 port 40000 ssh2
Nov  3 11:00:20 lab-ssh sshd[7001]: Failed password for root from 203.0.113.50 port 40001 ssh2
Nov  3 11:00:40 lab-ssh sshd[7002]: Failed password for root from 203.0.113.50 port 40002 ssh2
```

**Tier-1 action.** Compare the entity with peer workstations or accounts from the same batch. Escalate only if a rule-based alert, a successful login, or an unusual geo corroborates the outlier.

**False-positive checks.**

- A busy but legitimate host that is rare inside this particular batch
- A population that is mostly attack traffic, which makes outliers unstable

### ALT-025A3576 — MEDIUM (61) — Anomalous src_ip behavior

- Rule: `isolation-forest` (anomaly)
- Entity: src_ip=203.0.113.60
- Events: 12
- Window: 2026-11-03T12:00:00Z → 2026-11-03T12:05:30Z
- ATT&CK: [T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003/) / Credential Access
- Confirmed access: no

IsolationForest fit on this batch marked the entity as an outlier. Dominant feature unique_users=12.00. decision_function=-0.022. Review it next to any rule alerts for the same entity. Do not contain on this signal alone.

**Evidence**

```text
Nov  3 12:00:00 lab-ssh sshd[8000]: Failed password for invalid user svc01 from 203.0.113.60 port 41000 ssh2
Nov  3 12:00:30 lab-ssh sshd[8001]: Failed password for invalid user svc02 from 203.0.113.60 port 41001 ssh2
Nov  3 12:01:00 lab-ssh sshd[8002]: Failed password for invalid user svc03 from 203.0.113.60 port 41002 ssh2
```

**Tier-1 action.** Compare the entity with peer workstations or accounts from the same batch. Escalate only if a rule-based alert, a successful login, or an unusual geo corroborates the outlier.

**False-positive checks.**

- A busy but legitimate host that is rare inside this particular batch
- A population that is mostly attack traffic, which makes outliers unstable

### ALT-098C1A27 — MEDIUM (61) — Anomalous user behavior

- Rule: `isolation-forest` (anomaly)
- Entity: user=Administrator
- Events: 5
- Window: 2026-11-03T02:17:00Z → 2026-11-03T11:15:00Z
- ATT&CK: [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) / Defense Evasion
- Confirmed access: no

IsolationForest fit on this batch marked the entity as an outlier. Dominant feature unique_ips=2.00. decision_function=-0.025. Review it next to any rule alerts for the same entity. Do not contain on this signal alone.

**Evidence**

```text
{"TimeCreated": "2026-11-03T02:17:00Z", "EventID": 4624, "Computer": "DC01", "TargetUserName": "Administrator", "IpAddress": "192.0.2.40", "LogonType": 10, "ElevatedToken": true}
{"TimeCreated": "2026-11-03T10:30:00Z", "EventID": 4624, "Computer": "DC01", "TargetUserName": "Administrator", "IpAddress": "198.51.100.31", "LogonType": 2, "ElevatedToken": true}
{"TimeCreated": "2026-11-03T10:45:00Z", "EventID": 4624, "Computer": "DC01", "TargetUserName": "Administrator", "IpAddress": "198.51.100.31", "LogonType": 2, "ElevatedToken": true}
```

**Tier-1 action.** Compare the entity with peer workstations or accounts from the same batch. Escalate only if a rule-based alert, a successful login, or an unusual geo corroborates the outlier.

**False-positive checks.**

- A busy but legitimate host that is rare inside this particular batch
- A population that is mostly attack traffic, which makes outliers unstable

### ALT-20729A74 — MEDIUM (58) — Web scanning

- Rule: `web-scanning` (rule)
- Entity: src_ip=203.0.113.70
- Events: 20
- Window: 2026-11-03T15:00:00Z → 2026-11-03T15:03:30Z
- ATT&CK: [T1595.002 Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) / Reconnaissance
- Confirmed access: no

One client requests many distinct paths and receives mostly client or server errors in a short window. Typical of vulnerability scanners walking a host.

**Evidence**

```text
203.0.113.70 - - [03/Nov/2026:15:00:00 +0000] "GET /.env HTTP/1.1" 404 180 "-" "nikto/2.5.0"
203.0.113.70 - - [03/Nov/2026:15:00:08 +0000] "GET /.git/config HTTP/1.1" 404 180 "-" "nikto/2.5.0"
203.0.113.70 - - [03/Nov/2026:15:00:16 +0000] "GET /admin HTTP/1.1" 404 180 "-" "nikto/2.5.0"
203.0.113.70 - - [03/Nov/2026:15:00:24 +0000] "GET /wp-login.php HTTP/1.1" 404 180 "-" "nikto/2.5.0"
203.0.113.70 - - [03/Nov/2026:15:00:32 +0000] "GET /phpmyadmin HTTP/1.1" 404 180 "-" "nikto/2.5.0"
```

**Tier-1 action.** Check the user agent and whether the source is an approved scanner. If it is not, block the address and look for any probe that returned a status below 400.

**False-positive checks.**

- A broken client or a deploy smoke test hitting removed routes
- An uptime checker with a long, mostly failing URL list

## Scope

This report is a batch triage aid. It does not retain a case, block an address, or replace a SIEM. Thresholds and the lab IP-to-city map are documented in the project README.
