## 📋 Overview

This repository contains a comprehensive Cyber Threat Intelligence (CTI) report on **AKIRA ransomware**, one of the most prolific and financially successful ransomware-as-a-service (RaaS) operations currently active. AKIRA emerged in March 2023 and has rapidly become a critical threat to organizations globally, with over **$244 million USD** in confirmed ransom proceeds and **350+ victims** as of September 2025.

This report provides detailed analysis of AKIRA's tactics, techniques, and procedures (TTPs), mapped to the MITRE ATT&CK framework, along with comprehensive indicators of compromise (IOCs), exploited vulnerabilities, and actionable mitigation strategies.

---

## 🎯 Key Statistics

| Metric | Value |
|--------|-------|
| **Total Ransom Proceeds** | $244M+ USD |
| **Confirmed Victims** | 350+ organizations |
| **First Observed** | March 2023 |
| **Current Status** | Active |
| **Primary Targets** | Small-to-medium businesses (59% of victims) |
| **Geographic Focus** | United States (80% of victims) |
| **Most Targeted Sector** | Manufacturing |

---

## 📊 Report Contents

### 1. **Executive Summary**
- Overview of AKIRA ransomware operation
- Key statistics and financial impact
- Suspected origins and connections to Conti syndicate
- Operation model and motivation

### 2. **Threat Actor Profile**
- Origin and political affiliation
- Victim selection criteria and targeting patterns
- Typical cybercrime activities
- Double extortion methodology

### 3. **Tactics, Techniques & Procedures (TTPs)**

Complete MITRE ATT&CK mapping including:

- ⚡ Initial Access (T1190, T1078, T1566)
- 🔓 Execution (T1059.001, T1059.003)
- 🔐 Persistence (T1136.002, T1219)
- ⬆️ Privilege Escalation (T1003.001, T1558.003)
- 🚫 Defense Evasion (T1562.001, T1070)
- 🔎 Discovery (T1082, T1016, T1087)
- ↔️ Lateral Movement (T1021.001, T1021.002)
- 📦 Collection (T1560, T1005)
- 📤 Exfiltration (T1048, T1537, T1572)
- 💥 Impact (T1486, T1490, T1489, T1657)

### 4. **Tools & Utilities**

Comprehensive documentation of 40+ tools used across all attack phases:

- Remote access tools (AnyDesk, RustDesk, MobaXterm)
- Credential harvesting (Mimikatz, LaZagne, DonPAPI)
- Discovery tools (AdFind, Advanced IP Scanner, SharpHound)
- Exfiltration tools (Rclone, FileZilla, WinSCP)
- Defense evasion tools (PowerTool, POORTRY, STONESTOP)

### 5. **Exploited Vulnerabilities (CVEs)**

Detailed analysis of 7+ actively exploited CVEs:

- **CVE-2020-3259** - Cisco ASA/FTD (CVSS 9.8 - Critical)
- **CVE-2023-20269** - Cisco ASA/FTD (CVSS 9.8 - Critical)
- **CVE-2024-40766** - SonicWall SonicOS (CVSS 9.3 - Critical)
- **CVE-2024-40711** - Veeam Backup & Replication (CVSS 9.8 - Critical)
- **CVE-2023-27532** - Veeam Backup & Replication (CVSS 7.5 - High)
- **CVE-2024-37085** - Cisco ASA/FTD (CVSS 8.6 - High)
- **CVE-2023-28252** - Windows CLFS Driver (CVSS 7.8 - High)

### 6. **Indicators of Compromise (IOCs)**

- File hashes (SHA-256) for ransomware variants
- File extensions (`.akira`, `.powerranges`, `.akiranew`, `.aki`)
- Ransom note filenames
- Registry modifications
- Network indicators
- Common commands and scripts
- Behavioral indicators

### 7. **Mitigation & Prevention**

Comprehensive security recommendations:

- 🔒 Critical security controls (patching, MFA, backups)
- 🔐 Access control and account management
- 🌐 Network segmentation strategies
- 👁️ Detection and monitoring guidance
- 🚫 Prevention and hardening measures
- 📋 Incident response preparation
- 👥 Security awareness training
- 🔍 Threat hunting activities

---

## 🚀 Usage

### Viewing the Report

**1. Download the HTML file:**
```bash
git clone https://github.com/yourusername/akira-ransomware-cti.git
cd akira-ransomware-cti
```

**2. Open in browser:**

- Simply open `CTI_AKIRA.html` in any modern web browser
- No server or additional dependencies required
- Best viewed in Chrome, Firefox, or Edge

### For Security Teams

- **Threat Hunting:** Use the IOCs section to search your environment for signs of compromise
- **Detection Engineering:** Implement detection rules based on the TTPs section
- **Incident Response:** Reference the mitigation section during active incidents
- **Security Awareness:** Share relevant sections with stakeholders and end users
- **Vulnerability Management:** Prioritize patching based on the CVEs section

---

## 🎨 Report Features

- **Interactive HTML Design:** Modern, dark-themed interface with retro aesthetics
- **Complete MITRE ATT&CK Mapping:** All techniques mapped to ATT&CK v18
- **Searchable Content:** Use browser search (Ctrl+F) to find specific information
- **Print-Friendly:** Can be printed or saved as PDF for offline reference
- **Visual Statistics:** Key metrics displayed in easy-to-read stat cards
- **Color-Coded Sections:** Different sections clearly distinguished for quick navigation

---

## ⚠️ Disclaimer

This report is provided for **informational and defensive security purposes only**. The information contained herein should be used to:

- Improve organizational security posture
- Conduct threat hunting activities
- Develop detection and prevention capabilities
- Support incident response efforts

**Important Notes:**

- IOCs should be vetted before implementing blocking actions
- Some tools mentioned are legitimate software used maliciously
- Organizations should conduct their own risk assessments
- This report does not constitute legal or compliance advice
- Do not attempt to use this information for offensive purposes

## 📚 Sources & References

### Primary Intelligence Sources

**Ransomware.live - IOC Database**  
https://www.ransomware.live/ioc

**Ransomware.live - TTPs Database**  
https://www.ransomware.live/ttps

**CISA StopRansomware Newsroom**  
https://www.cisa.gov/stopransomware/newsroom

**MITRE ATT&CK Framework**  
https://attack.mitre.org/

**VirusTotal**  
https://www.virustotal.com/gui/home/upload

---

### AKIRA Ransomware Threat Actor Intelligence

**Ransomware.live - AKIRA Group Profile**  
https://www.ransomware.live/group/akira

**AKIRA Tor Leak Site** ⚠️ *(Caution: Dark Web)*  
`akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad.onion`

**AKIRA TTPs GitHub Repository**  
https://github.com/crocodyli/ThreatActors-TTPs/blob/main/Akira/Readme.md

---

### Victim Statistics & Targeting

**AKIRA Group Statistics**  
https://www.ransomware.live/groupstats/akira

**AKIRA Victim Geographical Map**  
https://www.ransomware.live/map?q=akira&year=full

**Primary Target Sectors:** Business Services and Technology

---

### Tactics, Techniques & Procedures (TTPs)

**AKIRA TTPs - Main Documentation**  
https://github.com/crocodyli/ThreatActors-TTPs/blob/main/Akira/Readme.md

**AKIRA TTPs - Repository Root**  
https://github.com/crocodyli/ThreatActors-TTPs/tree/main/Akira

**AKIRA TTP Detailed Analysis**  
https://github.com/crocodyli/ThreatActors-TTPs/blob/main/Akira/Akira-TTP.md

**AKIRA Exploited CVEs**  
https://github.com/crocodyli/ThreatActors-TTPs/blob/main/Akira/CVEs-Akira.md

**AKIRA Tools & Utilities**  
https://github.com/crocodyli/ThreatActors-TTPs/blob/main/Akira/Tools-Akira.md

**CISA Advisory - #StopRansomware: Akira Ransomware (AA24-109A)**  
https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a

**MITRE ATT&CK - AKIRA Group (G1024)**  
https://attack.mitre.org/groups/G1024/

**MITRE ATT&CK - AKIRA Software (S1129)**  
https://attack.mitre.org/software/S1129/

**Trellix Research - AKIRA Ransomware Analysis**  
https://www.trellix.com/blogs/research/akira-ransomware/

**S-RM Inform - Ransomware in Focus: Meet Akira**  
https://www.s-rminform.com/latest-thinking/ransomware-in-focus-meet-akira

---

### Detection & Mitigation Techniques

**YARA Rule for AKIRA Detection**  
https://www.ransomware.live/yara/Akira/Akira.yar

---

### Additional Security Resources

**FBI Internet Crime Complaint Center (IC3)**  
https://www.ic3.gov/

**CISA Known Exploited Vulnerabilities Catalog**  
https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**No More Ransom Project**  
https://www.nomoreransom.org/

**NIST Cybersecurity Framework**  
https://www.nist.gov/cyberframework

**CIS Controls**  
https://www.cisecurity.org/controls

---

**⚠️ Security Notice:** The Tor onion link provided leads to the threat actor's dark web infrastructure. Access only through proper security protocols and for legitimate research/investigation purposes. Never engage with ransomware operators directly.
