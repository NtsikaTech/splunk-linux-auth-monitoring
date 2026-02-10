# SSH Success After Multiple Failures Detection

**Alert Name:** SSH Success After Multiple Failures  
**Host:** Ubuntu-SOC-VMM  
**Log Source:** /var/log/auth.log  
**Sourcetype:** linux_syslog  

## Summary
Multiple failed SSH login attempts followed by a successful login were detected.  

## Analysis
- Failures observed from same source before login
- Successful authentication recorded afterward
- Behavior may indicate credential guessing or testing

## Conclusion
Potential account compromise scenario simulated in SOC lab environment.
Alert validated and documented.
