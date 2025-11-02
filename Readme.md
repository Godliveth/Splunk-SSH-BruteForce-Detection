# 🔐 Day 24 – Splunk Basics: Investigating SSH Brute Force Attack (JSON-based Linux Auth Log Analysis)

### 🎯 Objective
As a SOC Trainee, the goal of this lab was to use **Splunk** to detect and investigate a simulated **SSH brute-force attack** by analyzing JSON-formatted Linux authentication logs.  
This project demonstrates how to extract and analyze failed login attempts, identify suspicious IPs, and understand brute-force attack patterns — a critical skill for any SOC or Threat Analyst.

---

## 🧰 Lab Setup

| Component | Details |
|------------|----------|
| **SIEM Tool** | Splunk Enterprise (Windows host) |
| **Dataset** | `linux_auth_logs.json` (JSON-formatted Linux Auth logs) |
| **Source Type** | `_json` (manually parsed using `spath`) |
| **Index** | `ssh_index` |
| **Operating System** | Windows 10 Host |

📥 **Download Dataset**:  
[🔗 Download linux_auth_logs.json](./linux_auth_logs.json)

---

## 🧪 Investigation Steps

### **1️⃣ Question 1: Which user has attempted the most number of SSH brute-force attacks?**

**SPL Query:**

spl

    index=ssh_json_index  "Failed password"
    | rex "Failed password for (invalid user )?(?<user>\w+)"
    | stats count by user
    | sort - count

🧠 Analyst Insight:
This query identifies users with the most failed SSH logins, helping spot brute-force targets or compromised accounts.
In real-world SOC monitoring, repeated failures followed by success from the same IP can indicate password spraying or brute-force attempts.

---

2️⃣ Question 2: What is the IP address of the user “thor”?

SPL Query:

    index=ssh_json_index
    | spath
    | search user="thor"
    | stats values(source_ip) as "Attacker_IP"


🧠 Analyst Insight:
By isolating user “thor” and extracting IP addresses via spath, we identified all IPs that attempted SSH logins with that username.
This is a key step in incident correlation — mapping user activity to external threat sources.


---

3️⃣ Question 3: How many times did user “thor” fail to login?

SPL Query:

    index=ssh_json_index  "Failed password" user="thor"
    | stats count as "Failed Attempts"


🧠 Analyst Insight:
This identifies the total failed login count for a specific user.
High frequency of failed attempts on a single account is a strong indicator of brute-force behavior, prompting further investigation into the source IP.


----

| Question | Observation                                  | Key Insight                                |
| -------- | -------------------------------------------- | ------------------------------------------ |
| Q1       | Multiple users experienced failed SSH logins | Indicates broad password-guessing activity |
| Q2       | User “thor” targeted from IP `98.110.184.71` | Potential attacker or automated bot        |
| Q3       | Thor had multiple failed login attempts      | Confirms brute-force pattern               |

---

## 📸 Screenshots Folder

All analysis screenshots from the Splunk investigation are available below 👇  

[🔗 View Screenshots Folder](./screenshots)


---

📊 Dashboard 

All three searches can be combined into a Splunk dashboard for continuous monitoring.
This demonstrates understanding of real-time security visualization in a SOC setting.

📸 Dashboard Screenshot:

[![View Dashboard](./images/Dashboard.png)](./images)

---

📂 Project Repository Structure
📁 Splunk-SSH-BruteForce-Detection
│
├── 📄 README.md
├── 📂 screenshots
│   ├── Q1_Top_Attempted_Users.png
│   ├── Q2_Thor_IP.png
│   ├── Q3_Thor_Failed_Attempts.png
│
├── 📂 images
│   └── Dashboard.png
│
└── 📄 linux_auth_logs.json

--- 

🧠 SOC Trainee Reflection

This project helped me understand how to analyze authentication logs, parse JSON data using Splunk’s spath command, and build SPL queries to detect brute-force login attempts.
I also practiced differentiating between failed and successful authentications — a key skill for detecting account compromise in real SOC environments.

---



Author

Godliveth Madu        
SOC Analyst Trainee 
