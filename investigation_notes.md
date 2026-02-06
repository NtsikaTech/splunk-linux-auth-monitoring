Date: 2026-02-06
Alert: SSH Brute-Force Detection
Host: Ubuntu-SOC-VMM
Source: /var/log/auth.log
Sourcetype: linux_syslog

Summary:
Multiple failed SSH login attempts detected for user 'wronguser' from ::1 (localhost).

Analysis:
- Count: 18 failed attempts in last 24 hours
- Host targeted: Ubuntu-SOC-VMM
- User: wronguser (invalid account)
- Source IP: ::1

Conclusion:
- Repeated failures indicate brute-force testing, likely automated
- No successful logins yet, monitor for escalation
- Alert validated, documented, and ready for escalation if in production
