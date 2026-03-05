# Splunk SOC Lab: Linux Authentication Monitoring

## Overview
This project demonstrates hands-on SOC analyst skills using Splunk SIEM to monitor and detect suspicious authentication activity on a Linux system.

The lab simulates real-world attack scenarios such as brute-force attacks, successful compromise attempts, and credential spraying.

---

## Lab Environment
- Ubuntu Desktop (Log Source)
- Splunk Enterprise (SIEM)
- VirtualBox Lab Environment

---

## Data Source
- `/var/log/auth.log`
- Sourcetype: `linux_syslog`

---

# Phase 1: SSH Brute-Force Detection

## Objective
Detect multiple failed SSH login attempts indicating brute-force activity.

## SPL Query
index=* sourcetype=linux_syslog "Failed password"
| stats count by host, user, src
| sort - count


## Outcome
- Identified repeated failed login attempts
- Created alert for brute-force detection
- Simulated SOC alert triage

---

# Phase 2: Successful Login After Failures

## Objective
Detect successful login after multiple failed attempts (possible compromise).

## SPL Query
index=* ("Failed password" OR "Accepted password")
| rex "password for (?:invalid user )?(?<user>\S+) from (?<src>[\d.:]+)"
| eval outcome=if(match(_raw,"Accepted password"),"success","failure")
| stats count(eval(outcome="failure")) as failures
count(eval(outcome="success")) as successes
by host, src, user
| where failures>=5 AND successes>=1


## Outcome
- Detected successful login following multiple failures
- Simulated attacker gaining access
- Created alert for high-risk authentication pattern

---

# Phase 3: Multiple Users from Single Source (Credential Spraying)

## Objective
Detect a single source attempting multiple usernames.

## SPL Query
index=* sourcetype=linux_syslog "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src>[\d.:]+)"
| stats dc(user) as unique_users, count by src
| where unique_users >= 3
| sort - unique_users


## Outcome
- Identified credential spraying behavior
- Detected multiple username attempts from single source
- Simulated attacker reconnaissance activity

---

## Screenshots

### Failed Login Detection
![Failed Logins](screenshots/failed_logins.png)

### Success After Failures
![Success After Failures](screenshots/success_after_failures.png)

### Alert Configuration
![Alert](screenshots/alert.png)

---

## Skills Demonstrated
- SIEM configuration and log ingestion
- SPL (Search Processing Language)
- Detection engineering
- Security monitoring and alerting
- Incident investigation and documentation

---

## SOC Analyst Workflow Applied
1. Log ingestion
2. Detection creation
3. Alert configuration
4. Incident investigation
5. Documentation and reporting

---

## Conclusion
This project demonstrates practical SOC analyst capabilities, including detecting brute-force attacks, identifying compromised accounts, and recognizing credential spraying patterns using Splunk.



# Phase 4: Privilege Escalation Detection (sudo Monitoring)

## Objective
Detect post-compromise behavior by monitoring sudo command execution.

## SPL Query
index=* sourcetype=linux_syslog "sudo:"
| sort - count


## Outcome
- Identified users executing privileged commands
- Monitored sensitive actions (user creation, shadow file access)
- Simulated post-compromise escalation scenario

## Investigation Notes
See `investigation_sudo_privilege_escalation.md`


### Screenshot

![Privilege Escalation Detection](screenshots/sudo_privilege_escalation.png)


---

# Phase 5: Privilege Escalation Detection (sudo Monitoring)

## Objective
Detect privilege escalation attempts through sudo usage, including successful and failed authentication attempts.

## Data Source
- `/var/log/auth.log`
- Sourcetype: `linux_syslog`

---

## Detection 1: Successful sudo Command Execution

### SPL Query
index=* sourcetype=linux_syslog "sudo:" "COMMAND="
| rex "sudo:\s+(?<user>\S+)\s+:"
| stats count by host, user
| sort - count


### Purpose
Identifies users executing commands with elevated privileges.

---

## Detection 2: Failed sudo Authentication Attempts

### SPL Query
index=* sourcetype=linux_syslog "sudo:" "authentication failure"
| stats count by host


### Purpose
Detects failed privilege escalation attempts.

---

## Outcome
- Simulated privilege escalation in lab environment
- Verified log ingestion from auth.log
- Created detection queries for sudo monitoring
- Documented SOC investigation workflow

---

## Skills Demonstrated (Phase 5)
- Privilege escalation detection
- Log analysis for command execution
- Field extraction using rex
- Security event correlation
- SOC alert creation and validation

### Field Extraction Example
![Field Extraction](screenshots/extract_field.png)

### Successful sudo Detection
![Successful Sudo](screenshots/successful.png)

### Failed sudo Detection
![Failed Sudo](screenshots/failed.png)


# Phase 6: SOC Monitoring Dashboard

A centralized dashboard was built to visualize key Linux authentication and security events in Splunk:

- Failed SSH login attempts
- Successful SSH logins
- Success after multiple failures
- Credential spraying
- Privilege escalation (sudo)
- New user creation

### Dashboard Screenshot

![Dashboard Overview](screenshots/dashboard_overview.png)

### Outcome
- Created centralized visibility for SOC monitoring
- Monitored brute-force attacks, account compromise, credential spraying, sudo activity, and persistence
- Simulated real SOC operational workflow

