# NetSentry – Packet Sniffer & Sensitive Data Detector

NetSentry is a simple yet powerful packet inspection tool designed to detect **sensitive information leakage** inside network traffic.  
It is built for **learning**, **cybersecurity demonstrations**, and **understanding how unencrypted HTTP traffic can expose private data**.

---

## 🚀 Project Overview

This project contains two main components:

### 1️ Vulnerable Test Server
A custom HTTP server that **intentionally sends data over unencrypted traffic**.  
Users can submit fake sensitive details like emails, passwords, SSNs, credit card numbers, etc.

- Runs on `http://localhost:8080`
- Perfect for testing packet capture tools

---

### 2️ NetSentry Packet Sniffer
A packet-capture script that listens on the **loopback interface (`lo`)**, detects sensitive information, and generates alerts.

🔍 **What it can detect**
- Passwords
- API Keys
- SSNs
- Phone numbers
- Credit card numbers
- Sensitive keywords

 **Where alerts are stored**
- All findings go into: **`alerts.txt`**
- Alerts are categorized: **High / Medium / Low Severity**

---

## ? Why This Matters

Sending private data over plaintext HTTP is **extremely unsafe** .  
This project demonstrates how **attackers can easily capture and expose**:

> 🔑 Login passwords, 💳 card details, 🔐 API keys… right from network traffic!

A great learning tool for **cybersecurity students** and **ethical hackers**.


