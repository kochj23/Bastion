# Bastion

> **AI-Powered Penetration Testing Platform for macOS**
> Enterprise-grade network security assessment with intelligent exploit orchestration

![Platform](https://img.shields.io/badge/platform-macOS%2013.0%2B-blue)
![Swift](https://img.shields.io/badge/Swift-5.9-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-1.0.0-brightgreen)

---

## ⚠️ LEGAL NOTICE - WHITE HAT TOOL ONLY

**Bastion is a penetration testing tool for AUTHORIZED USE ONLY.**

Unauthorized network scanning and exploitation is **ILLEGAL** in most jurisdictions and may violate:
- Computer Fraud and Abuse Act (CFAA) - USA (penalties: $250,000 + 20 years)
- Computer Misuse Act - UK
- Similar cybersecurity laws worldwide

**BY USING BASTION, YOU CONFIRM:**
- ✓ You own or have explicit written permission to test the target network
- ✓ You will use this tool for defensive security purposes only
- ✓ You understand that unauthorized access is a criminal offense

**INTENDED FOR:**
- Testing YOUR home/office network security
- Authorized penetration testing engagements
- Security research in lab environments
- Red team exercises with signed contracts

---

## 🎯 What is Bastion?

Bastion is an **AI-powered penetration testing platform** that helps you find and fix security vulnerabilities in your local network BEFORE attackers do.

### The Problem:
- You don't know what's vulnerable on your network
- CVE databases are overwhelming (200,000+ vulnerabilities)
- Manual penetration testing requires expert knowledge
- Commercial tools cost $5,000-50,000/year

### The Solution:
**Bastion** combines:
- 🤖 **AI Intelligence** - AI orchestrates attacks and prioritizes vulnerabilities
- 🎯 **Automated Exploitation** - Executes proof-of-concept attacks
- 📊 **Full CVE Database** - 200,000+ vulnerabilities indexed locally
- 🛡️ **Smart Remediation** - AI generates fix instructions
- 💎 **Premium UI** - Glassmorphic multi-window dashboards
- 🔒 **100% Local** - No cloud, complete privacy

---

## ✨ Premium Features

### 🤖 AI-Powered Attack Orchestration
**What Makes This Enterprise-Grade:**
- AI analyzes all discovered services and CVEs
- Prioritizes attacks by: severity, exploitability, impact
- Generates custom payloads for each target
- Predicts success probability for each exploit
- Recommends multi-stage attack chains
- Natural language security insights

**AI Backends Supported:**
- **Ollama** - Fast GPU-accelerated analysis
- **TinyLLM** by Jason Cox - Lightweight Docker deployment
- **MLX Toolkit** - Apple Silicon optimized

**Example:**
```
🤖 AI Analysis:
"Device 192.168.1.10 is your highest-risk target. It's running OpenSSH 7.4
with 3 critical CVEs (including remote code execution). Default credentials
are likely (Raspberry Pi fingerprint detected). Attack order: 1) Test default
password 'raspberry' (90% success), 2) Exploit CVE-2021-41617 if needed.
Expected time to compromise: Under 60 seconds."
```

---

### 🌐 Advanced Network Discovery
- **Auto-Discovery** - Scans entire subnet automatically
- **Service Fingerprinting** - Identifies exact versions (OpenSSH 7.4p1, Apache 2.4.6)
- **OS Detection** - Detects Linux, macOS, Windows, IoT devices
- **Device Categorization** - Routers, servers, workstations, IoT, mobile
- **Network Topology** - Visual map of network structure
- **Port Scanning** - Full TCP/UDP scanning (1-65535)

---

### 🎯 Comprehensive Exploit Modules

#### 1. SSH Attack Module
- Brute force weak passwords (dictionary attack)
- Default credential testing (500+ combos)
- Known SSH CVE exploits (RCE, privilege escalation)
- Key-based authentication testing
- User enumeration

#### 2. Web Vulnerability Module
- SQL Injection testing (all major databases)
- XSS vulnerability detection (reflected, stored, DOM-based)
- Directory traversal (path injection)
- Insecure deserialization
- Default admin panels (WordPress, phpMyAdmin, etc.)
- API endpoint fuzzing
- Authentication bypass
- CSRF testing

#### 3. SMB/NFS Module
- Anonymous share enumeration
- Weak password testing
- EternalBlue (MS17-010) detection and exploit
- Share permission testing
- Sensitive file discovery

#### 4. Default Credentials Module
- **1,000+ default credentials** for routers, IoT, cameras, NAS
- Manufacturer-specific defaults (Netgear, TP-Link, Synology, QNAP)
- Service defaults (MongoDB, Redis, Elasticsearch)
- Common weak passwords

#### 5. CVE Exploit Module
- **200,000+ CVE database** (full NVD)
- Automatic exploit matching
- Proof-of-concept execution
- Safe exploitation (no system damage)

---

### 📊 Full CVE Database Integration

**National Vulnerability Database (NVD):**
- **200,000+ CVEs** from 2002-2025
- **Daily updates** - Automatic CVE feed refresh
- **Local storage** - No internet required after download
- **Fast querying** - SQLite indexing for instant results
- **Smart matching** - Fuzzy version matching (7.4p1 matches 7.4.*)
- **Exploit availability** - Links to Metasploit, ExploitDB

**CVE Matching Example:**
```
Service: OpenSSH 7.4p1
Query: SELECT * FROM cves WHERE service='openssh' AND version_affected(7.4)

Results (12 CVEs):
1. CVE-2021-41617 - CVSS 9.8 (CRITICAL) - Remote Code Execution
   Exploit: Available (Metasploit)
   AI: "High priority - RCE with public exploit"

2. CVE-2020-15778 - CVSS 7.8 (HIGH) - Command Injection
   Exploit: Proof-of-concept available
   AI: "Test after CVE-2021-41617"

3. CVE-2019-6111 - CVSS 5.9 (MEDIUM) - Man-in-the-Middle
   Exploit: Requires specific conditions
   AI: "Low priority - complex to exploit"
```

---

### 🎨 Premium Multi-Window UI

**Your Glassmorphic Theme Applied:**
- Dark navy blue background with animated blobs
- Ultra-translucent glass cards (25% white opacity)
- Thick white borders (2px) with dual shadows
- Smooth animations (0.6s easeInOut)
- Vibrant accent colors (cyan, purple, pink, orange)
- Heat-mapped severity (green → yellow → orange → red)

**7 Windows:**
1. **Main Dashboard** - Overview cards and network map
2. **Device List** - Sortable table of all discovered devices
3. **Attack Log** - Live terminal-style exploit output
4. **AI Insights** - Natural language security analysis
5. **Vulnerabilities** - Detailed CVE information
6. **Reports** - PDF report generation and export
7. **Settings** - Configuration and AI backend selection

**Each Window:**
- Floating glassmorphic design
- Resizable and movable
- Keyboard shortcuts (⌘1-⌘7)
- Real-time data synchronization

---

### 📄 Enterprise PDF Reports

**Professional Security Assessment Report:**

```
┌────────────────────────────────────────────────────┐
│ BASTION SECURITY ASSESSMENT                        │
│ Network: 192.168.1.0/24                           │
│ Assessment Date: January 17, 2025                  │
│ Generated by: Bastion v1.0.0                       │
│                                                     │
│ EXECUTIVE SUMMARY                                   │
│                                                     │
│ [AI-Generated Summary]                              │
│ Your network contains 3 critically vulnerable      │
│ devices requiring immediate remediation. The most  │
│ severe issue is a Raspberry Pi with default        │
│ credentials and unpatched OpenSSH...               │
│                                                     │
│ RISK SUMMARY                                        │
│ ├─ Critical: 3 vulnerabilities                    │
│ ├─ High: 5 vulnerabilities                        │
│ ├─ Medium: 8 vulnerabilities                      │
│ └─ Low: 12 vulnerabilities                        │
│                                                     │
│ NETWORK OVERVIEW                                    │
│ [Visual network map]                                │
│                                                     │
│ DETAILED FINDINGS                                   │
│                                                     │
│ Finding #1: Default Credentials (CRITICAL)         │
│ Device: 192.168.1.10 (Raspberry Pi)               │
│ Service: SSH (OpenSSH 7.4p1)                       │
│ Issue: Default password 'raspberry' accepted       │
│ Impact: Complete device compromise                  │
│ CVSS: 9.8                                          │
│ Proof: [Screenshot of successful login]            │
│ Remediation: Change password immediately           │
│   Command: ssh pi@192.168.1.10 && passwd          │
│                                                     │
│ [... 27 more detailed findings ...]                │
│                                                     │
│ AI REMEDIATION PLAN                                 │
│ Priority 1 Actions (Complete in 30 minutes):       │
│   1. Change Raspberry Pi password                   │
│   2. Patch OpenSSH on 3 devices                    │
│   3. Disable directory listing on web server        │
│                                                     │
│ [Full remediation timeline with commands]           │
│                                                     │
│ APPENDIX                                            │
│ - Complete CVE list                                 │
│ - Exploit proof-of-concepts                        │
│ - Network topology diagram                          │
│ - Technical scan data                               │
└────────────────────────────────────────────────────┘

60 pages, professional formatting, branded
```

---

## 💎 Advanced Security Features

### 1. **AI-Driven Exploit Selection** (Unique)
- AI reads CVEs and predicts which will work
- Learns from successful/failed exploits
- Generates custom payloads
- **No other tool has this**

### 2. **Natural Language Security** (Premium)
- AI explains vulnerabilities in plain English
- Executive summaries for non-technical stakeholders
- **Competitors:** Expensive consultants required

### 3. **Complete CVE Coverage** (Comprehensive)
- 200,000+ CVEs locally indexed
- Real-time matching
- **Competitors:** Partial databases or cloud-only

### 4. **Automated Remediation** (Time-Saving)
- AI generates exact fix commands
- Prioritized action plans
- Time estimates for each fix
- **Competitors:** Manual interpretation required

### 5. **Proof-of-Concept Execution** (Validation)
- Actually exploits vulnerabilities
- Provides evidence (not just theory)
- **Competitors:** Identify-only or manual exploitation

### 6. **Multi-Backend AI** (Flexible)
- Works offline (MLX/Ollama)
- Lightweight (TinyLLM)
- User choice
- **Competitors:** Cloud-only or no AI

### 7. **Enterprise Reporting** (Professional)
- Board-ready PDF reports
- Executive summaries
- Technical appendices
- **Competitors:** Basic HTML reports

### 8. **100% Privacy** (Security-Critical)
- All processing local
- No cloud uploads
- No telemetry
- **Competitors:** Cloud-based with data risks

---

## 🚀 Open Source Mission

**Bastion is 100% free and open source** under the MIT License.

**Why Open Source?**
- 🏠 **Home Network Security** - Everyone deserves to know if their network is vulnerable
- 🔒 **Privacy First** - No cloud, no telemetry, no data collection
- 🤝 **Community Driven** - Security through transparency
- 📚 **Educational** - Learn penetration testing techniques
- 🛡️ **Defensive Security** - Help people protect their networks before attackers exploit them

**Current Features:**
- ✅ AI-powered vulnerability analysis
- ✅ Comprehensive network discovery
- ✅ Multiple attack modules (SSH, web, SMB, default credentials)
- ✅ Full CVE database integration (200,000+ vulnerabilities)
- ✅ Glassmorphic multi-window UI
- ✅ Professional PDF report generation
- ✅ Attack chaining and ML predictions
- ✅ Complete audit logging

**Contributing:**
- Report bugs and security issues
- Contribute new exploit modules
- Improve AI analysis algorithms
- Add device fingerprints
- Enhance documentation

This tool exists to help you secure YOUR network. Use it responsibly.