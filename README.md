# ☁️ Secure Cloud Infrastructure on AWS

> **Internee.pk Cybersecurity Internship — Task #2**

## 📌 Objective

Ensure Internee.pk's AWS cloud environment follows industry-standard security measures by auditing IAM configurations, applying least-privilege policies, enabling WAF for traffic filtering, and setting up multi-region backups for data redundancy.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        INTERNEE.PK AWS ENVIRONMENT              │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │                   SECURITY LAYER                     │      │
│   │                                                      │      │
│   │   ┌─────────────┐        ┌──────────────────────┐   │      │
│   │   │  AWS WAF    │        │   AWS CloudTrail     │   │      │
│   │   │  (Traffic   │        │   (Audit Logging)    │   │      │
│   │   │  Filtering) │        └──────────────────────┘   │      │
│   │   └──────┬──────┘                                   │      │
│   │          │               ┌──────────────────────┐   │      │
│   │          │               │   AWS Config         │   │      │
│   │          │               │   (Compliance Rules) │   │      │
│   │          │               └──────────────────────┘   │      │
│   └──────────┼───────────────────────────────────────── ┘      │
│              │                                                   │
│   ┌──────────▼───────────────────────────────────────────┐      │
│   │                  APPLICATION LAYER                   │      │
│   │                                                      │      │
│   │         ┌─────────────────────────────┐              │      │
│   │         │   Application Load Balancer │              │      │
│   │         └──────────────┬──────────────┘              │      │
│   │                        │                             │      │
│   │         ┌──────────────▼──────────────┐              │      │
│   │         │     EC2 / ECS / Lambda      │              │      │
│   │         └──────────────┬──────────────┘              │      │
│   │                        │                             │      │
│   │         ┌──────────────▼──────────────┐              │      │
│   │         │   RDS (Private Subnet)      │              │      │
│   │         └─────────────────────────────┘              │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │                   IAM LAYER                          │      │
│   │   Roles · Policies · MFA · Least Privilege           │      │
│   └──────────────────────────────────────────────────────┘      │
│                                                                  │
│   ┌──────────────────────────────────────────────────────┐      │
│   │               BACKUP & REDUNDANCY                    │      │
│   │   Primary: us-east-1   →   Replica: ap-south-1       │      │
│   │   S3 Cross-Region Replication · RDS Automated Backups│      │
│   └──────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔧 Components Implemented

| Component | AWS Service | Purpose |
|-----------|-------------|---------|
| Identity & Access Management | AWS IAM | Least-privilege roles and policies |
| Traffic Filtering | AWS WAF v2 | Block malicious web traffic |
| Audit Logging | AWS CloudTrail | Track all API calls |
| Compliance Monitoring | AWS Config | Detect misconfigured resources |
| Threat Detection | Amazon GuardDuty | ML-based anomaly detection |
| Primary Backups | AWS Backup | Automated backup schedules |
| Data Redundancy | S3 Cross-Region Replication | Multi-region data copies |
| Secrets Management | AWS Secrets Manager | Secure credential storage |

---

## 📁 Repository Structure

```
secure-cloud-infrastructure/
│
├── README.md
│
├── iam-policies/
│   ├── admin-policy.json              # Scoped admin policy (not root)
│   ├── developer-policy.json          # Developer least-privilege policy
│   ├── readonly-audit-policy.json     # Read-only auditor policy
│   └── mfa-enforcement-policy.json    # Force MFA for all users
│
├── waf-rules/
│   ├── waf-web-acl.json               # Core WAF Web ACL configuration
│   └── ip-blocklist.json              # IP reputation blocklist rule
│
├── backup-config/
│   ├── backup-plan.json               # AWS Backup plan (daily/weekly)
│   └── s3-replication-config.json     # S3 cross-region replication
│
├── audit-scripts/
│   ├── cloud-security-audit.py        # Automated security audit script
│   └── cloudtrail-analyzer.py        # CloudTrail log analyzer
│
└── docs/
    ├── setup-guide.md                 # Step-by-step implementation guide
    └── compliance-checklist.md        # CIS AWS Benchmark checklist
```

---

## 🔐 IAM Security

### Principles Applied
- **Least Privilege** — every role has only the permissions it needs
- **MFA Enforcement** — all human users must use MFA
- **No Root Usage** — root account locked down, MFA enabled, no access keys
- **Role-Based Access** — services use IAM roles, never access keys

### Roles Created

| Role | Purpose | Key Permissions |
|------|---------|-----------------|
| `internee-admin` | Senior admins only | Scoped admin, no IAM delete |
| `internee-developer` | Dev team | EC2, S3, Lambda read/write |
| `internee-auditor` | Security team | Read-only across all services |
| `internee-backup` | Backup service | S3, RDS, DynamoDB backup only |

---

## 🛡️ WAF Configuration

The AWS WAF Web ACL includes the following rule groups:

| Rule | Action | Description |
|------|--------|-------------|
| AWS Core Rule Set | Block | OWASP Top 10 protection |
| SQL Injection Protection | Block | Detects SQLi patterns in requests |
| XSS Protection | Block | Cross-site scripting prevention |
| Rate Limiting | Block | Max 2000 req/5min per IP |
| IP Reputation List | Block | Known malicious IP addresses |
| Bad Bot Protection | Block | Blocks known scrapers/scanners |
| Geo Restriction | Count | Flags traffic from high-risk regions |

---

## 🔁 Multi-Region Backup Strategy

| Data Type | Primary Region | Replica Region | Frequency | Retention |
|-----------|---------------|----------------|-----------|-----------|
| S3 Buckets | us-east-1 | ap-south-1 | Real-time replication | 90 days |
| RDS Databases | us-east-1 | ap-south-1 | Daily snapshots | 30 days |
| EC2 Volumes | us-east-1 | ap-south-1 | Daily AMI backups | 14 days |
| DynamoDB | us-east-1 | ap-south-1 | Continuous PITR | 35 days |

---

## 📊 Security Audit Results

Running `audit-scripts/cloud-security-audit.py` checks for:

| Check | Status | Severity |
|-------|--------|----------|
| Root account MFA enabled | ✅ Pass | Critical |
| No root access keys exist | ✅ Pass | Critical |
| CloudTrail enabled all regions | ✅ Pass | High |
| S3 buckets not public | ✅ Pass | High |
| WAF attached to ALB | ✅ Pass | High |
| GuardDuty enabled | ✅ Pass | Medium |
| Password policy enforced | ✅ Pass | Medium |
| Unused IAM credentials rotated | ✅ Pass | Medium |
| VPC Flow Logs enabled | ✅ Pass | Medium |
| Default security groups unused | ✅ Pass | Low |

---

## 🧠 Key Learnings

- **IAM is the backbone of AWS security** — misconfigured permissions are the #1 cause of cloud breaches
- **Least privilege is harder than it sounds** — requires careful mapping of what each role actually needs
- **WAF managed rule groups** save enormous time vs writing rules from scratch
- **Multi-region backups** protect against both data loss and regional outages
- **CloudTrail + AWS Config** together give full visibility into who changed what and when
- **GuardDuty** uses ML to detect threats that rule-based systems miss (e.g., credential exfiltration, unusual API calls)

---

## 📚 References

- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS WAF Documentation](https://docs.aws.amazon.com/waf/)
- [AWS Open Data Registry](https://registry.opendata.aws/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

---

## 👤 Author

**Cybersecurity Intern @ Internee.pk**
Task #2 — Secure Cloud Infrastructure
