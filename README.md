## Objective

Write Python and Bash scripts to automate tasks such as Analyzing Logs, Phishing Analysis, Security Monitoring, and Incident Response. These scripts will help identify odd behaviors, gather indicators of compromise, inspect authentication logs for unsuccessful local and SSH login attempts, and detect and block brute-force attacks.

### Skills Learned

- Log analysis and parsing: Create scripts to read various log formats and identify odd activity.
- Phishing Analysis: Use hashes to check email files and attachments for potentially dangerous content.
- Security Monitoring: Create scripts to keep an eye on authentication logs for local and SSH failed login attempts.
- Incident Response: Automate procedures to handle incidents like identifying and blocking malicious IP addresses.

### Tools Used

- Python: For writing scripts to parse logs, extract IoCs, and perform automated analysis on email files and attachments.
- Bash: For automating tasks like parsing system logs, monitoring login attempts, and identifying suspicious activities.
- Didier Stevens Suite: Collection of Python-based utilities for analyzing and reverse-engineering malware and malicious files.

## Practical Exercises
- Python Script: Log Analysis and Parsing
<p align="center">
<img src="https://imgur.com/bqfRxsa.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/2iF8BhK.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/AIPQCv2.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>log_analyzer.py ; Python script that parses and analyzes logs (such as JSON, CSV, or Syslog) to identify common suspicious and malicious activities, and then extracts potential Indicators of Compromise (IoC) such as IP addresses, user agents, URLs, etc. It then saves the results in a report template (report.txt)..</b>
<br/>

- Python Script: Phishing Analysis
<p align="center">
<img src="https://imgur.com/nfIFIQG.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/3OijaXv.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/vMGt8bi.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>extract_attach_hash.py; Python script will automate the Python script (emldump.py) that is processing an email file (sample1.eml), extracting certain parts of it, and then working with the resulting file (quotation.iso) to calculate its hash (SHA256). The final findings will be saved to a .txt report.</b>
<br/>
 
<p align="center">
<img src="https://imgur.com/S3ZBVLa.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/y5ROmeb.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/xhOlTI8.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>analyze_suspicious_doc.py; Python script will automate the Python script (oledump.py) and filter out the PowerShell commands, web requests, downloads, and connections from (.xlsm or .docm) the macro code. The final findings will be saved to a .txt report.</b>
<br/>

- Bash Script: Log Analysis and Parsing
<p align="center">
<img src="https://imgur.com/9CXacLQ.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/gaxpcM7.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/rCTWSLj.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>check_web_server_log.sh; Bash script will analyze the web server access logs for common security threats, including SQL injections, XSS, DoS attempts, and more. The final findings will be saved to a .txt report.</b>
<br/>

- Bash Script: Security Monitoring and Incident Response
<p align="center">
<img src="https://imgur.com/x3jCm6G.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/WMv0h3U.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/yyXD4BX.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>analyze_failed_logins.sh; Bash script that analyzes authentication logs to identify failed login attempts, including SSH and local logins, and account lockouts. It generates a detailed report summarizing usernames, login methods, and associated IP addresses.</b>
<br/>

<p align="center">
<img src="https://imgur.com/sV5aWDC.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/UOHWcrI.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<img src="https://imgur.com/DexWIFZ.png" height="90%" width="90%" alt="Device Specification"/>
<br/>
<b>block_ssh_brute_force.sh; Bash script that monitors SSH brute force attempts by analyzing the auth.log file, identifies suspicious IP addresses based on failed login attempts, and blocks them using iptables.</b>
<br/>

## Outcome

- Automated Log Analysis: Wrote scripts that scan and examine logs to identify and report odd activity, such as unsuccessful login attempts, shady URLs, or warning indications. 
- Malware Analysis: Wrote Python scripts to examine and hash email attachments to identify potentially dangerous content. 
- Incident Response: Automated the process of identifying and resolving threats, such as IP blocking in brute force attacks. 
- Security Monitoring: Automated monitoring scripts to keep track of unsuccessful local and SSH login attempts.
- Effective Reporting: Generated template reports based on the results of Incident Response and Security Monitoring activities to provide useful information.

## Acknowledgements

This project combines ideas and methods from various sources, such as the TryHackMe Boogeyman 1 room, TCM Security SOC 101 class, along with my own experience. Python scripts were used to automate the commands given during the lab exercises in order to increase scalability and efficiency. These resources provided the fundamental information and techniques, which were then modified in light of practical uses.

- [TryHackMe Boogeyman 1](https://tryhackme.com/r/room/boogeyman1)
- [TCM Security SOC 101](https://academy.tcm-sec.com/p/security-operations-soc-101)
- [Didier Stevens](https://github.com/DidierStevens/DidierStevensSuite)

## Disclaimer

The sole goals of the projects and activities here are for education and ethical cybersecurity research. All work was conducted in controlled environments, such as paid cloud spaces, private labs, and online cybersecurity education platforms. Online learning and cloud tasks adhered closely to all usage guidelines. Never use these projects for improper or unlawful purposes. It is always prohibited to break into any computer system or network. Any misuse of the provided information or code is not the responsibility of the author or authors. 
