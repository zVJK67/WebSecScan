# WebSecScan  
**Automated Web Security Misconfiguration Assessment Tool**

---

## 📌 Overview

WebSecScan is a Python-based command-line tool designed to detect common web application security misconfigurations in a safe and automated manner.

Unlike intrusive penetration testing tools, WebSecScan focuses on **configuration-level weaknesses** using non-destructive techniques. It generates structured findings with severity ratings, CVSS scoring, and remediation guidance.

This tool is designed primarily for:

- 🎓 Students learning web security  
- 👨‍💻 Developers performing basic security checks  
- 🔍 Small-scale security assessments  
- 📚 Educational and research purposes  

---

## 🎯 Purpose

WebSecScan helps users:

- Identify common web security misconfigurations  
- Understand security risks using severity levels and CVSS scoring  
- Receive remediation recommendations  
- Generate structured security reports  

> The tool emphasizes **automation**, **clarity**, and **modular design**.

---

## 🚀 Features

- ✔ Detection of common web misconfigurations  
- ✔ Severity rating & CVSS scoring  
- ✔ Structured and readable output  
- ✔ HTML report generation  
- ✔ Optional PDF & JSON export  
- ✔ Optional email report delivery  

---

## 🔎 What WebSecScan Detects

WebSecScan performs checks for:

- Missing or misconfigured security headers  
- Unsafe or unnecessary HTTP methods  
- Exposed server version information  
- Insecure cookie attributes (Secure / HttpOnly flags)  
- CORS misconfiguration  
- Publicly accessible sensitive directories or files  
- Potential path traversal behavior  
- Weak SSL/TLS configurations  
- Lack of HTTPS enforcement  

> ⚠️ **Note**  
> WebSecScan uses **non-intrusive techniques** and does **not modify** target systems.

---

## ⚙️ Installation 

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/zVJK67/WebSecScan.git
cd WebSecScan
```


### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🖥️ Usage
WebSecScan supports both **Interactive Mode** and **Non-Interactive Mode**.

### 1️⃣ Interactive Mode

Run:
```bash
websecscan
```

You will be prompted to:
- Enter the target URL
- Enable or disable verbose mode
- Specify path traversal test runs
- Choose report export options

This mode is recommended for **beginners** or **manual testing**.


<img src="https://github.com/user-attachments/assets/1267680e-5bdc-4166-bb14-9592115316ee" width="600"/>

---

### 2️⃣ Non-Interactive Mode

Run:
```bash
websecscan [-u URL] [-v] [--path-tests PATH_TESTS]
```

<img src="https://github.com/user-attachments/assets/8f2fd4a8-421a-476e-b26c-c80e8df6d74f" width="600"/>

---

**Available Arguments**

<img src="https://github.com/user-attachments/assets/47723140-cc55-4295-8b13-64b26e55b489" width="1000"/>

---

## 📊 Output & Result 
After scanning, WebSecScan provides:
- Module-based scan results
- Risk Rating (Low / Medium / High)
- CVSS Score
- Detailed Findings
- Remediation Recommendations
- Execution time per module
- Summary table of detected issues


Reports are generated in:
- 🌐 HTML (clear and human-readable)
- 📄 PDF (easy to share and document)
- 📑 JSON (machine-readable format)


## Screenshots

### 🧾 CLI Scanning Result

<img src="https://github.com/user-attachments/assets/08d2954c-def5-4fb5-b8d0-cfbe006f542c" width="600"/>

---

### 🔍 Verbose Output

<img src="https://github.com/user-attachments/assets/7eed1e5f-f8a4-41e7-b55d-f1bef1fd2296" width="600"/>

---

### 📋 Summary Table

<img src="https://github.com/user-attachments/assets/4e041a5e-d3cc-4f47-a559-a5776131325e" width="600"/>

---

## 📁 Report Formats

### 🌐 HTML Report

<img src="https://github.com/user-attachments/assets/ecf4b3f0-3d98-4d14-bc5c-b5cb44e5c1c3" width="600"/>

<img src="https://github.com/user-attachments/assets/e49c01cb-7167-46de-a9aa-f8ae35d682d3" width="600"/>

---

### 📄 PDF Report

<img src="https://github.com/user-attachments/assets/1df3cc90-9fb9-4167-9e7f-865e6070387b" width="600"/>

---

### 🧾 JSON Report

<img src="https://github.com/user-attachments/assets/83a30df6-dbab-4afe-9320-f8fe05ab2c05" width="600"/>

---


> [!WARNING]
> ### Disclaimer
> WebSecScan is intended solely for educational use and authorized security assessments.  
> Unauthorized scanning or testing of systems without explicit permission is strictly prohibited.
>
> The author shall not be held liable for any misuse, damages, or legal consequences arising from the use of this tool.
