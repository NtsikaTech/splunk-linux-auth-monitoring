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
