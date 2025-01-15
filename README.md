## Objective

Write a Python and Bash scripts to automate tasks such as analyzing logs, identifying malicious software, and resolving security issues. These scripts assist in identifying odd behavior. They check new user accounts, system logs for unsuccessful login attempts, look for warning indications, identify potential threats, and perform safety checks on important directories and logs. 

### Skills Learned

- Log analysis and parsing: Create scripts to read various log formats and identify odd activity.
- Malware Analysis: Use hashes to check email files and attachments for potentially dangerous content and compare them to lists of known threats.
- Incident Response: Check system logs for security issues and automate procedures to handle incidents like identifying and blocking malicious IP addresses or unsuccessful login attempts.
- System monitoring and security checks: Create scripts to keep an eye on system logs for hardware issues or errors and identify odd new user accounts.
- Automate threat detection: To filter and examine log files for frequent threats such as brute force logins and SQL injection.
- Critical Directory Monitoring: Automatically monitor system folders for file changes and identify anomalies.

### Tools Used

- Python: For writing scripts to parse logs, extract IoCs, and perform automated analysis on email files, attachments, and system logs.
- Bash: For automating tasks like parsing system logs, monitoring login attempts, and identifying suspicious activities.
- Didier Stevens Suite: Collection of Python-based utilities for analyzing and reverse-engineering malware and malicious files.
- grep and cut commands: Used in Bash for filtering specific log entries based on user-defined parameters.
- find and ls commands: Used in Bash to search for modified files in a critical directory and output relevant details.
- sha256: Used for hashing email attachments to verify their integrity and compare against known malicious hashes.

## Practical Exercises
- Python Script: Log Analysis and Parsing
<p align="center">
<img src="https://imgur.com/bqfRxsa.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/2iF8BhK.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/AIPQCv2.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>log_analyzer.py ; Python script that parses and analyzes logs (such as JSON, CSV, or Syslog) to identify common suspicious and malicious activities, and then extracts potential Indicators of Compromise (IoC) such as IP addresses, user agents, URLs, etc. It then saves the results in a report template (report.txt)..</b>
<br/>

- Python Script: Phishing Analysis
<p align="center">
<img src="https://imgur.com/nfIFIQG.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/3OijaXv.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/vMGt8bi.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>extract_attach_hash.py; Python script will automate the Python script (emldump.py) that is processing an email file (sample1.eml), extracting certain parts of it, and then working with the resulting file (quotation.iso) to calculate its hash (SHA256). The final findings will be saved to a .txt report.</b>
<br/>
 
<p align="center">
<img src="https://imgur.com/S3ZBVLa.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/y5ROmeb.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/xhOlTI8.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>analyze_suspicious_doc.py; Python script will automate the Python script (oledump.py) and filter out the PowerShell commands, web requests, downloads, and connections from (.xlsm or .docm) the macro code. The final findings will be saved to a .txt report.</b>
<br/>

- Bash Script: Log Analysis and Parsing
<p align="center">
<img src="https://imgur.com/9CXacLQ.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/gaxpcM7.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/rCTWSLj.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>check_web_server_log.sh; Bash script will analyze the web server access logs for common security threats, including SQL injections, XSS, DoS attempts, and more. The final findings will be saved to a .txt report.</b>
<br/>

- Bash Script: System Monitoring and Security Checks
<p align="center">
<img src="https://imgur.com/x3jCm6G.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/WMv0h3U.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/M5wgGti.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>analyze_failed_logins.sh; Bash script that analyzes authentication logs to identify failed login attempts, including SSH and local logins, and account lockouts. It generates a detailed report summarizing usernames, login methods, and associated IP addresses.</b>
<br/>

<p align="center">
<img src="https://imgur.com/sV5aWDC.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/UOHWcrI.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/DexWIFZ.png" height="40%" width="40%" alt="Device Specification"/>
<br/>
<b>block_ssh_brute_force.sh; Bash script that monitors SSH brute force attempts by analyzing the auth.log file, identifies suspicious IP addresses based on failed login attempts, and blocks them using iptables.</b>
<br/>

## Outcome

 - Automated Log Analysis: Wrote scripts that scan and examine logs in order to identify and report odd activity, such as unsuccessful login attempts, dubious URLs, or warning indications. 
 - Malware Detection: Wrote Python scripts to examine and hash email attachments in order to identify potentially dangerous content. 
 - Incident Response: Automated the process of identifying and resolving threats, such as IP blocking in brute force attacks. 
 - Security Monitoring: Automated monitoring scripts to keep track of important folder changes, unsuccessful login attempts, new accounts, and system errors. 
 - Effective Reporting: Generated reports by examining logs, odd behavior, and system problems in order to provide useful information.

## Acknowledgements

This project combines ideas and methods from various sources, such as the TryHackMe Boogeyman 1 room, TCM Security SOC 101 class, and my personal experience. Python scripts were used to automate the commands given during the lab exercises in order to increase scalability and efficiency. These resources provided the fundamental information and techniques, which were then modified in light of practical uses.

- [TryHackMe Boogeyman 1](https://tryhackme.com/r/room/boogeyman1)
- [TCM Security SOC 101](https://academy.tcm-sec.com/p/security-operations-soc-101)
- [Didier Stevens](https://github.com/DidierStevens/DidierStevensSuite)

## Disclaimer

The sole goals of the projects and activities here are for education and ethical cybersecurity research. All work was conducted in controlled environments, such as paid cloud spaces, private labs, and online cybersecurity education platforms. Online learning and cloud tasks adhered closely to all usage guidelines. Never use these projects for improper or unlawful purposes. It is always prohibited to break into any computer system or network. Any misuse of the provided information or code is not the responsibility of the author or authors. 
