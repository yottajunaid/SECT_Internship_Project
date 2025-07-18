# 🛡️ SECT Internship
#  Week 1: Passive Reconnaissance & Threat Modeling

## 🎯 Project Objective

To simulate an attacker's reconnaissance phase using **passive information gathering techniques** — without interacting directly with the target and evaluate what assets are exposed to the public internet.

**Target Website**: [http://tendermines.com](http://tendermines.com)

---

## 🔧 Reconnaissance Techniques Used

- 🔍 **WHOIS & DNS Lookups** (via [who.is](https://who.is) and [MXToolbox](https://mxtoolbox.com))
- 🌐 **BuiltWith Analysis** (to identify tech stack and hosting infra)
- 🕵️‍♂️ **Google Dorking** (to find exposed endpoints, documents, logins)
- 📡 **Subdomain Enumeration** (via DNSDumpster, crt.sh, VirusTotal)
- 🔐 **SSL/TLS Analysis** (or lack thereof)
- 🎭 **Website Social Engineering Audit**
- 👤 **Social Media Reconnaissance** (LinkedIn, GitHub, etc.)
- 🌑 **Dark Web Filtering** (IntelX leak validation)
  

## 🕳️ Dark Web Leak Reference

- 🔗 [IntelX Leak – `tendermines.com.sql`](https://intelx.io/?did=4b5ea3eb-4e18-4877-a11b-442d42ebc6a1)
- 📥 [Sample leaked DB snapshot (Google Drive)](https://drive.google.com/file/d/15R_AjnB5f9CBipvXqDzH0I1NGrdl8sL1/view?usp=sharing)

---

## 📁 Included Files

- `Week_1/reconnaissance_sect.pdf` – Full PDF report with:
  - Screenshots of tools
  - Threat modeling table
  - Risk assessment matrix
  - Recommendations

---

This project demonstrates the importance of **passive reconnaissance** in understanding an organization’s public exposure. Through ethical OSINT and threat modeling, we can simulate how attackers gather intelligence and propose defensive actions before real exploitation happens.

---
# Week 2: Web Vulnerability Analysis

**Target**: http://tendermines.com

### 🧪 Key Activities:
- **XSS Testing**: Injected common payloads in URL parameters, search bar, and contact form. 
- **SQL Injection (Error-Based)**: Entered payloads like `' OR 'x'='x` in login form.
- **SSL/TLS Verification**: Site served over HTTP without HTTPS, HSTS, or secure cookies.
- **Email Security**: Missing SPF, DKIM, and DMARC DNS records — vulnerable to email spoofing.
- **Info Disclosure**: SQL error outputs revealed internal server paths and database structure.
- **Admin/Login Page Indexing**: `/login` page publicly accessible and potentially indexed; lacked protections.
- **Security Headers**: `X-Frame-Options` present, but CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy were missing.

### ✅ Risk Assessment – Summary Table:
| # | Issue                          | Risk Level |
|---|-------------------------------|------------|
| 1 | SQL Injection (Error-Based)   | High       |
| 2 | Leaked Sensitive Info         | High       |
| 3 | Missing HTTPS/TLS             | High       |
| 4 | Missing Email Auth (SPF/DKIM/DMARC) | High |
| 5 | Admin Page Indexed            | Medium     |
| 6 | Missing Security Headers      | Medium     |
| 7 | No XSS Found                  | N/A        |

---

## 📁 Included Files

- `Week_2/vulnerabilityreport_sect` – Full PDF report with:
  - Screenshots of tools
  - Threat modeling table
  - Risk assessment matrix
  - Recommendations

---

## ✒️ Author

**Junaid Quadri**  
`SECT Cybersecurity Intern – July 2025`

---

## 🔖 Tags

`cybersecurity` `osint` `reconnaissance` `sect-internship` `darkweb` `social-engineering` `bugbounty` `tls` `dns-security`

