# WebSecScan
Automated Web Security Misconfiguration Assessment Tool



##Overview

WebSecScan is a Python-based command-line tool designed to detect common web application security misconfigurations in a safe and automated manner.

The tool focuses on configuration-level security weaknesses rather than intrusive exploitation techniques. It performs structured security checks and generates clear findings with severity ratings, CVSS scores, and remediation guidance.

WebSecScan is suitable for:

- Students learning web security

- Developers performing basic security checks

- Small-scale security assessments

- Educational and research purposes

  

##Purpose of the Tool

WebSecScan helps users:

+ Identify common web security misconfigurations
+ Understand security risks through severity ratings and CVSS scoring
+ Receive remediation recommendations
+ Generate structured security reports

The tool emphasizes **automation**, **clarity**, and **modular design**.



##Features

✔ Scanning for Misconfiguration in Web Application

✔ Severity Rating & CVSS Scoring

✔ Generating Scanning Result with Simple Guidance 

✔ HTML Report Generation

✔ Optional PDF & JSON Export

✔ Optional Email Report Delivery



##What WebSecScan Detects?

WebSecScan checks for:

- Missing or misconfigured security headers

- Unsafe or unnecessary HTTP methods

- Exposed server version information

- Insecure cookie attributes (e.g., missing Secure/HttpOnly flags)

- CORS policy misconfigurations

- Publicly accessible sensitive directories or files

- Potential path traversal behavior

- Weak SSL/TLS configurations

- Lack of HTTPS enforcement

> [!NOTE]
> The tool uses **non-intrusive techniques** and does not **modify** target systems.



##Output & Results Screenshots

**CLI Scanning Result**


Reports are generated in:

🌐 HTML (interactive view)

📄 PDF (optional)

📑 JSON (machine-readable format)
