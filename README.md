# ☁️ Cloud Threat Hunting on AWS  

## 🔹 Overview  
This project simulates **AWS CloudTrail logs** to detect malicious activity in the cloud. Attackers often target cloud environments for **persistence and privilege escalation**. This lab demonstrates how to analyze CloudTrail logs to detect:  

- **IAM Persistence** (new access keys, backdoor user creation)  
- **Privilege Escalation** (attaching `AdministratorAccess` policies)  
- **Suspicious Login Activity** (logins from impossible geo locations)  

The goal is to show **real-world SOC analyst cloud detection skills** using Splunk queries, Sigma rules, and MITRE ATT&CK mapping.  

---

## 🔹 Dataset  
Dataset: `datasets/cloudtrail_logs.json`  

The log entries include:  
- **Normal Events**:  
  - S3 bucket access  
  - DynamoDB queries  
  - Regular console logins from India  

- **Suspicious/Malicious Events**:  
  - `CreateUser` → Attacker creates a new backdoor account  
  - `CreateAccessKey` → Persistence with long-term credentials  
  - `AttachUserPolicy` → Escalates privileges to `AdministratorAccess`  
  - `ConsoleLogin` → Logins from Russia & China while normal logins are from India  

---

## 🔹 Detection Logic  

### 📌 SPL (Splunk Queries)  

**1. Detect creation of suspicious access keys**  
```spl
index=cloudtrail
| search eventName=CreateAccessKey
| stats count by userIdentity.arn, sourceIPAddress, eventTime
```

**2. Detect privilege escalation (Admin policy attached)**  
```spl
index=cloudtrail
| search eventName=AttachUserPolicy policyArn=arn:aws:iam::aws:policy/AdministratorAccess
| table eventTime, userIdentity.arn, requestParameters.userName
```

**3. Detect suspicious login locations**  
```spl
index=cloudtrail
| search eventName=ConsoleLogin responseElements.ConsoleLogin="Success"
| iplocation sourceIPAddress
| stats values(sourceIPAddress) by userIdentity.userName
| where mvcount(sourceIPAddress) > 1
```

---

## 🔹 Sigma Rules  

### 🛡️ IAM Persistence (CreateAccessKey)  
```yaml
title: AWS IAM Access Key Creation (Possible Persistence)
id: 456e7890-e12b-34d5-a678-426614174111
status: experimental
description: Detects new AWS IAM access key creation which may indicate persistence
author: Tirthraj Sisodiya
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: "CreateAccessKey"
  condition: selection
fields:
  - eventTime
  - userIdentity.userName
  - sourceIPAddress
falsepositives:
  - Legitimate key creation by admin
level: high
```

### 🛡️ Privilege Escalation (AttachUserPolicy)  
```yaml
title: AWS IAM Privilege Escalation (Admin Policy Attached)
id: 789e1234-e56b-78c9-a123-426614174222
status: experimental
description: Detects when a user attaches AdministratorAccess policy to themselves or another account
author: Tirthraj Sisodiya
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: "AttachUserPolicy"
    requestParameters.policyArn: "arn:aws:iam::aws:policy/AdministratorAccess"
  condition: selection
fields:
  - eventTime
  - userIdentity.userName
  - sourceIPAddress
falsepositives:
  - Legitimate policy changes by cloud admins
level: critical
```

---

## 🔹 MITRE ATT&CK Mapping  

| Technique | ID | Description |  
|-----------|----|-------------|  
| Account Manipulation | T1098 | Persistence using IAM backdoor accounts/keys |  
| Valid Accounts | T1078 | Use of stolen or backdoor AWS credentials |  
| Cloud Trail Tampering | T1070.004 | Disabling/deleting CloudTrail logs |  
| Data from Cloud Storage | T1530 | Access to sensitive S3 buckets |  

---

## 🔹 Skills Demonstrated  
- Threat hunting in **CloudTrail logs**  
- Writing **Splunk SPL queries**  
- Creating **Sigma rules** for cloud detections  
- Mapping cloud attacks to **MITRE ATT&CK**  
- Simulating both **normal and malicious AWS activity**  

---

⚡ **Author:** Tirthraj Sisodiya  
🔗 LinkedIn: [linkedin.com/in/tirthraj-cybersecurity](https://linkedin.com/in/tirthraj-cybersecurity)  
