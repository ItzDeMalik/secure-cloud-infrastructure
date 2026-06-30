#!/usr/bin/env python3
"""
AWS Cloud Security Audit Script
Internee.pk Cybersecurity Internship - Task #2

Audits AWS account against CIS AWS Foundations Benchmark.
Checks IAM, S3, CloudTrail, GuardDuty, WAF, and more.

Usage:
    pip install boto3
    aws configure   # set your credentials
    python3 cloud-security-audit.py
"""

import boto3
import json
from datetime import datetime, timezone

# ==================== CONFIGURATION ====================
REGIONS = ["us-east-1", "ap-south-1"]
REPORT_FILE = f"security-audit-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"

# Color codes for terminal output
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

results = []


def check(name, passed, severity, detail=""):
    """Record a check result and print it."""
    status = f"{GREEN}✅ PASS{RESET}" if passed else f"{RED}❌ FAIL{RESET}"
    sev_color = RED if severity == "CRITICAL" else YELLOW if severity == "HIGH" else RESET
    print(f"  {status}  [{sev_color}{severity}{RESET}]  {name}")
    if detail and not passed:
        print(f"         → {detail}")
    results.append({
        "check": name,
        "passed": passed,
        "severity": severity,
        "detail": detail
    })


# ==================== IAM CHECKS ====================
def audit_iam():
    print(f"\n{BOLD}[ IAM CHECKS ]{RESET}")
    iam = boto3.client("iam")

    # Check 1: Root MFA enabled
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        check(
            "Root account MFA enabled",
            summary.get("AccountMFAEnabled", 0) == 1,
            "CRITICAL",
            "Enable MFA on root account immediately"
        )
    except Exception as e:
        check("Root account MFA enabled", False, "CRITICAL", str(e))

    # Check 2: No root access keys
    try:
        check(
            "No root access keys exist",
            summary.get("AccountAccessKeysPresent", 0) == 0,
            "CRITICAL",
            "Delete root access keys — use IAM roles instead"
        )
    except Exception as e:
        check("No root access keys exist", False, "CRITICAL", str(e))

    # Check 3: Password policy
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        strong = (
            policy.get("MinimumPasswordLength", 0) >= 14 and
            policy.get("RequireUppercaseCharacters", False) and
            policy.get("RequireLowercaseCharacters", False) and
            policy.get("RequireNumbers", False) and
            policy.get("RequireSymbols", False) and
            policy.get("MaxPasswordAge", 999) <= 90
        )
        check(
            "Strong password policy enforced",
            strong,
            "HIGH",
            "Min 14 chars, uppercase, lowercase, numbers, symbols, max 90 days"
        )
    except iam.exceptions.NoSuchEntityException:
        check("Strong password policy enforced", False, "HIGH", "No password policy set")

    # Check 4: Users with unused credentials (>90 days)
    try:
        iam.generate_credential_report()
        import time; time.sleep(2)
        report = iam.get_credential_report()["Content"].decode("utf-8")
        lines = report.strip().split("\n")
        stale_users = []
        now = datetime.now(timezone.utc)
        for line in lines[1:]:
            parts = line.split(",")
            user = parts[0]
            last_used = parts[10]  # password_last_used
            if last_used not in ("N/A", "no_information", "not_supported", ""):
                try:
                    last_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                    days_inactive = (now - last_dt).days
                    if days_inactive > 90:
                        stale_users.append(f"{user} ({days_inactive} days)")
                except Exception:
                    pass
        check(
            "No IAM users inactive >90 days",
            len(stale_users) == 0,
            "MEDIUM",
            f"Stale users: {', '.join(stale_users)}" if stale_users else ""
        )
    except Exception as e:
        check("No IAM users inactive >90 days", False, "MEDIUM", str(e))


# ==================== S3 CHECKS ====================
def audit_s3():
    print(f"\n{BOLD}[ S3 CHECKS ]{RESET}")
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets()["Buckets"]
        public_buckets = []
        unversioned_buckets = []
        unencrypted_buckets = []

        for bucket in buckets:
            name = bucket["Name"]

            # Check public access block
            try:
                pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                is_public_blocked = all([
                    pab.get("BlockPublicAcls", False),
                    pab.get("IgnorePublicAcls", False),
                    pab.get("BlockPublicPolicy", False),
                    pab.get("RestrictPublicBuckets", False)
                ])
                if not is_public_blocked:
                    public_buckets.append(name)
            except Exception:
                public_buckets.append(name)

            # Check versioning
            try:
                versioning = s3.get_bucket_versioning(Bucket=name)
                if versioning.get("Status") != "Enabled":
                    unversioned_buckets.append(name)
            except Exception:
                unversioned_buckets.append(name)

            # Check encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
            except s3.exceptions.ClientError:
                unencrypted_buckets.append(name)

        check(
            "All S3 buckets block public access",
            len(public_buckets) == 0,
            "HIGH",
            f"Public buckets: {', '.join(public_buckets)}"
        )
        check(
            "All S3 buckets have versioning enabled",
            len(unversioned_buckets) == 0,
            "MEDIUM",
            f"Unversioned: {', '.join(unversioned_buckets)}"
        )
        check(
            "All S3 buckets are encrypted",
            len(unencrypted_buckets) == 0,
            "HIGH",
            f"Unencrypted: {', '.join(unencrypted_buckets)}"
        )

    except Exception as e:
        check("S3 bucket audit", False, "HIGH", str(e))


# ==================== CLOUDTRAIL CHECKS ====================
def audit_cloudtrail():
    print(f"\n{BOLD}[ CLOUDTRAIL CHECKS ]{RESET}")
    ct = boto3.client("cloudtrail", region_name="us-east-1")

    try:
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
        multi_region_trails = [t for t in trails if t.get("IsMultiRegionTrail")]
        check(
            "CloudTrail enabled in all regions",
            len(multi_region_trails) > 0,
            "HIGH",
            "Create a multi-region trail to capture all API calls"
        )

        # Check log validation
        for trail in multi_region_trails:
            check(
                f"CloudTrail log validation enabled ({trail['Name']})",
                trail.get("LogFileValidationEnabled", False),
                "MEDIUM",
                "Enable log file validation to detect tampering"
            )
    except Exception as e:
        check("CloudTrail audit", False, "HIGH", str(e))


# ==================== GUARDDUTY CHECKS ====================
def audit_guardduty():
    print(f"\n{BOLD}[ GUARDDUTY CHECKS ]{RESET}")
    for region in REGIONS:
        gd = boto3.client("guardduty", region_name=region)
        try:
            detectors = gd.list_detectors()["DetectorIds"]
            enabled = False
            if detectors:
                detector = gd.get_detector(DetectorId=detectors[0])
                enabled = detector.get("Status") == "ENABLED"
            check(
                f"GuardDuty enabled ({region})",
                enabled,
                "HIGH",
                f"Enable GuardDuty in {region} for threat detection"
            )
        except Exception as e:
            check(f"GuardDuty enabled ({region})", False, "HIGH", str(e))


# ==================== WAF CHECKS ====================
def audit_waf():
    print(f"\n{BOLD}[ WAF CHECKS ]{RESET}")
    waf = boto3.client("wafv2", region_name="us-east-1")
    try:
        acls = waf.list_web_acls(Scope="REGIONAL")["WebACLs"]
        check(
            "WAF Web ACL exists",
            len(acls) > 0,
            "HIGH",
            "Deploy WAF Web ACL and attach to ALB/API Gateway"
        )
    except Exception as e:
        check("WAF Web ACL exists", False, "HIGH", str(e))


# ==================== REPORT ====================
def generate_report():
    passed = sum(1 for r in results if r["passed"])
    failed = sum(1 for r in results if not r["passed"])
    total = len(results)
    score = int((passed / total) * 100) if total else 0

    critical_fails = [r for r in results if not r["passed"] and r["severity"] == "CRITICAL"]
    high_fails = [r for r in results if not r["passed"] and r["severity"] == "HIGH"]

    print(f"""
{BOLD}╔══════════════════════════════════════════════════════════════╗
║              AWS SECURITY AUDIT REPORT                       ║
╠══════════════════════════════════════════════════════════════╣
║  Score        : {score}% ({passed}/{total} checks passed){'':25}║
║  Critical Fails: {len(critical_fails):<44}║
║  High Fails   : {len(high_fails):<44}║
║  Report saved : {REPORT_FILE:<44}║
╚══════════════════════════════════════════════════════════════╝{RESET}""")

    with open(REPORT_FILE, "w") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "score": score,
            "passed": passed,
            "failed": failed,
            "total": total,
            "results": results
        }, f, indent=2)


# ==================== MAIN ====================
if __name__ == "__main__":
    print(f"{BOLD}🔍 AWS Cloud Security Audit — Internee.pk{RESET}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    audit_iam()
    audit_s3()
    audit_cloudtrail()
    audit_guardduty()
    audit_waf()
    generate_report()
