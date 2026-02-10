# Linux Authentication Monitoring with Splunk

## Project Overview
This project demonstrates detection of SSH brute-force attempts on a Linux system using Splunk Enterprise. It simulates SOC analyst workflows: detection, alerting, investigation, and documentation.

## Data Source
- /var/log/auth.log
- Sourcetype: linux_syslog
- Host: Ubuntu-SOC-VMM

## Detection Logic
- Failed SSH login attempts counted per host/user/source
- Threshold: 5+ failed attempts triggers alert
- SPL Query: `spl_queries/failed_ssh_attempts.spl`

## Alerts
- Alert Name: SSH Brute-Force Detection
- Trigger: Count >= 5
- Action: Log alert and document

## Investigation
- Documented in `investigation_notes.md`
- Screenshots in `screenshots/` folder

## Skills Demonstrated
- Linux log analysis
- Splunk SPL queries
- Alert configuration
- SOC triage and incident documentation


## Phase 2: Successful Login After Multiple Failures

This detection identifies cases where multiple failed SSH login attempts are followed by a successful login from the same source. This simulates potential account compromise in a SOC environment.

**Detection Logic:**
- Logs monitored: `/var/log/auth.log`
- Event types: "Failed password" and "Accepted password"
- Grouped by host and source IP
- Threshold: 5+ failures followed by 1+ success
- SPL Query: `spl_queries/success_after_failures.spl`

**Investigation Notes:**
- Documented in `investigation_success_after_failures.md`
- Screenshots in `screenshots/success_after_failures.png`

**Skills Demonstrated:**
- Linux log analysis
- Splunk SPL query creation
- Alert logic understanding
- SOC incident investigation workflow
