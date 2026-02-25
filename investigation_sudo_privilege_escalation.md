# Phase 4: Privilege Escalation Detection

## Objective
Detect sudo usage indicating potential privilege escalation.

## Log Source
/var/log/auth.log

## Detection Logic
Monitor for sudo command execution and identify:
- User performing action
- Command executed
- Frequency

## Analysis
Observed sudo execution by user:
- Command: /usr/bin/ls
- Command: /usr/sbin/useradd
- Command: /usr/bin/cat /etc/shadow

## Risk Assessment
Unauthorized or unusual sudo usage may indicate:
- Privilege escalation
- Persistence activity
- Post-compromise lateral movement

## Conclusion
Alert logic validated. Detection ready for SOC monitoring.
