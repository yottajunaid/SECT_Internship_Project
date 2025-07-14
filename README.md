# 🛡️ SECT Internship – Week 1: Passive Reconnaissance & Threat Modeling

This repository contains my **Week 1 submission** for the **SECT Internship Program**, where the focus was on performing **passive reconnaissance** on a real-world target and building a **threat model** based on observed risks.

---

## 🎯 Project Objective

To simulate an attacker's reconnaissance phase using **passive information gathering techniques** — without interacting directly with the target — and evaluate what assets are exposed to the public internet.

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

## 🔐 Conclusion

This project demonstrates the importance of **passive reconnaissance** in understanding an organization’s public exposure. Through ethical OSINT and threat modeling, we can simulate how attackers gather intelligence and propose defensive actions before real exploitation happens.

---

## ✒️ Author

**Junaid**  
`SECT Cybersecurity Intern – July 2025`

---

## 🔖 Tags

`cybersecurity` `osint` `reconnaissance` `sect-internship` `darkweb` `social-engineering` `bugbounty` `tls` `dns-security`

