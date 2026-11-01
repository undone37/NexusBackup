# Wazuh

NexusBackup's audit log, alerts and job results in Wazuh: the appliance forwards them as syslog, Wazuh decodes
each record's JSON and these rules give them levels (a malware finding or a console root shell high, a failed job
or a failed login lower). Configured in **Settings → Forwarding**; the records and delivery guarantees are those of
the syslog sink (manual chapter 10, "Forwarding to a SIEM").

| File | What |
|---|---|
| `nexusbackup_decoders.xml` | decoder `nexusbackup`: program name `nexus`, then Wazuh's JSON decoder |
| `nexusbackup_rules.xml` | rules 110100 to 110199 (group `nexusbackup`) |
| `samples.log` | one line per kind of record, as the appliance sends it, with the rule it must end in |
| `test_rules.py` | offline check of the three files (CI); the real check is `wazuh-logtest` |

## Wazuh manager

1. Copy the files and restart:

   ```sh
   cp nexusbackup_decoders.xml /var/ossec/etc/decoders/
   cp nexusbackup_rules.xml /var/ossec/etc/rules/
   chown wazuh:wazuh /var/ossec/etc/decoders/nexusbackup_decoders.xml /var/ossec/etc/rules/nexusbackup_rules.xml
   ```

2. A syslog listener in `/var/ossec/etc/ossec.conf`, open only to the appliance's management address:

   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>tcp</protocol>
     <allowed-ips>192.0.2.10/32</allowed-ips>
   </remote>
   ```

3. `systemctl restart wazuh-manager`, then paste a line of `samples.log` into `/var/ossec/bin/wazuh-logtest`: it
   should end in the rule named above the line.

## NexusBackup

**Settings → Forwarding → Syslog**: the manager's address, port 514, transport **TCP (unencrypted)**, format
**Wazuh**, app name `nexus` (or change `program_name` in the decoder). **Send test message** shows up in Wazuh as
rule 110101.

Wazuh's syslog listener has no TLS, so the records travel in clear text: use it on the management network only. To
keep TLS, run rsyslog on the manager with a TLS listener (`imtcp` with the `gtls` driver, RFC 5425 framing) that
writes to a file Wazuh reads (`<localfile>` with `log_format syslog`), and leave the transport on TLS with format
Wazuh. Switching an enabled sink from TLS to plain TCP is a weakening and needs approval.

## Levels

| Rule | Level | Records |
|---|---|---|
| 110121 | 14 | critical security alert raised (malware, scan or hash-hunt hit, anomaly, tenant lockdown, break glass, console unlock, ...) |
| 110111 | 12 | audit: console unlocked or root shell opened |
| 110122 | 12 | other critical alert raised (failed backup, damaged snapshot, failing disk, ...) |
| 110112 | 10 | audit: account locked after failed logins |
| 110114 | 8 | audit: snapshot deleted or released, retention of orphans, tenant deleted, disabled, locked down or impersonated |
| 110115 | 8 | audit: forwarding, alert or anomaly settings changed |
| 110123, 110131 | 7 | warning raised; job failed |
| 110113 | 5 | audit: failed login, re-authentication or activation |
| 110100, 110101, 110110, 110116, 110120 | 3 | any other record, test message, audit entry, login, alert acknowledged or resolved |
| 110130 | 2 | job finished |

Wazuh mails from level 12 by default (`email_alert_level`). Not lab-tested against a Wazuh manager yet (#139).
