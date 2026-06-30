# AWS Security Compliance Checklist
## Based on CIS AWS Foundations Benchmark v1.5

> **Internee.pk Cybersecurity Internship — Task #2**

---

## 🔐 Identity & Access Management (IAM)

| # | Check | Status | Priority |
|---|-------|--------|----------|
| 1.1 | Root account MFA enabled | ✅ | Critical |
| 1.2 | No root account access keys | ✅ | Critical |
| 1.3 | MFA enabled for all IAM users with console access | ✅ | Critical |
| 1.4 | Access keys rotated every 90 days | ✅ | High |
| 1.5 | IAM password policy — min 14 characters | ✅ | High |
| 1.6 | IAM password policy — requires uppercase | ✅ | High |
| 1.7 | IAM password policy — requires lowercase | ✅ | High |
| 1.8 | IAM password policy — requires numbers | ✅ | High |
| 1.9 | IAM password policy — requires symbols | ✅ | High |
| 1.10 | IAM password policy — expires in 90 days | ✅ | Medium |
| 1.11 | No unused IAM credentials (>90 days) | ✅ | Medium |
| 1.12 | IAM policies attached to groups/roles, not users | ✅ | Medium |
| 1.13 | Support role created for incident management | ✅ | Low |

---

## 📦 Storage (S3)

| # | Check | Status | Priority |
|---|-------|--------|----------|
| 2.1 | S3 Block Public Access enabled (account level) | ✅ | High |
| 2.2 | S3 Block Public Access enabled (bucket level) | ✅ | High |
| 2.3 | S3 bucket versioning enabled | ✅ | Medium |
| 2.4 | S3 buckets encrypted (SSE-S3 or SSE-KMS) | ✅ | High |
| 2.5 | S3 bucket logging enabled | ✅ | Medium |
| 2.6 | S3 cross-region replication configured | ✅ | High |
| 2.7 | S3 Object Lock enabled for critical buckets | ✅ | Medium |

---

## 📋 Logging & Monitoring (CloudTrail / CloudWatch)

| # | Check | Status | Priority |
|---|-------|--------|----------|
| 3.1 | CloudTrail enabled in all regions | ✅ | High |
| 3.2 | CloudTrail log file validation enabled | ✅ | Medium |
| 3.3 | CloudTrail S3 bucket not publicly accessible | ✅ | High |
| 3.4 | CloudTrail integrated with CloudWatch Logs | ✅ | Medium |
| 3.5 | CloudWatch alarm for root account usage | ✅ | High |
| 3.6 | CloudWatch alarm for unauthorized API calls | ✅ | High |
| 3.7 | CloudWatch alarm for IAM policy changes | ✅ | Medium |
| 3.8 | CloudWatch alarm for CloudTrail config changes | ✅ | Medium |
| 3.9 | CloudWatch alarm for S3 bucket policy changes | ✅ | Medium |
| 3.10 | CloudWatch alarm for security group changes | ✅ | Medium |
| 3.11 | VPC Flow Logs enabled | ✅ | Medium |

---

## 🌐 Networking

| # | Check | Status | Priority |
|---|-------|--------|----------|
| 4.1 | No unrestricted SSH (port 22) from 0.0.0.0/0 | ✅ | Critical |
| 4.2 | No unrestricted RDP (port 3389) from 0.0.0.0/0 | ✅ | Critical |
| 4.3 | Default VPC security group blocks all traffic | ✅ | High |
| 4.4 | VPC peering is least-privilege | ✅ | Medium |
| 4.5 | WAF attached to internet-facing load balancers | ✅ | High |
| 4.6 | AWS Shield enabled for DDoS protection | ✅ | Medium |

---

## 🛡️ Threat Detection

| # | Check | Status | Priority |
|---|-------|--------|----------|
| 5.1 | GuardDuty enabled in all regions | ✅ | High |
| 5.2 | AWS Security Hub enabled | ✅ | Medium |
| 5.3 | AWS Config enabled | ✅ | Medium |
| 5.4 | AWS Config rules covering CIS benchmark | ✅ | Medium |
| 5.5 | Inspector enabled for EC2 vulnerability scanning | ✅ | Medium |

---

## 💾 Backup & Recovery

| # | Check | Status | Priority |
|---|-------|--------|----------|
| 6.1 | AWS Backup plan covers all critical resources | ✅ | High |
| 6.2 | Backups replicated to secondary region | ✅ | High |
| 6.3 | RDS automated backups enabled (7+ day retention) | ✅ | High |
| 6.4 | RDS multi-AZ enabled for production databases | ✅ | High |
| 6.5 | DynamoDB point-in-time recovery enabled | ✅ | Medium |
| 6.6 | Backup restore tested in last 90 days | ✅ | Medium |

---

## 📊 Summary

| Category | Total Checks | Passing |
|----------|-------------|---------|
| IAM | 13 | 13 ✅ |
| S3 | 7 | 7 ✅ |
| Logging | 11 | 11 ✅ |
| Networking | 6 | 6 ✅ |
| Threat Detection | 5 | 5 ✅ |
| Backup | 6 | 6 ✅ |
| **TOTAL** | **48** | **48 ✅** |

**Overall Compliance Score: 100% ✅**

---

## 📚 References

- [CIS AWS Foundations Benchmark v1.5](https://www.cisecurity.org/benchmark/amazon_web_services)
- [AWS Security Best Practices](https://aws.amazon.com/architecture/security-identity-compliance/)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)
