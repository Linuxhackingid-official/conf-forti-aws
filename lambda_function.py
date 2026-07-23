"""
AWS Lambda: Convert Syslog (key=value) events to ASFF and import into AWS Security Hub.

Supported input triggers (auto-detected):
  1. CloudWatch Logs subscription filter (gzip+base64 "awslogs" payload)
  2. Direct/manual test invocation:
        { "logs": ["itime=... epid=... ...", "itime=... ..."] }
     or { "log": "itime=... epid=... ..." }
  3. Kinesis Data Stream / Firehose records containing raw syslog text
     (each record's base64-decoded "data" is treated as one syslog line)

The syslog format handled looks like:

  itime=2026-07-23 20:47:53 epid=3 euid=3 data_parsername=FortiGate Log Parser
  data_sourceid=FGTAWSIUIGDJMGF5 ... event_message=Admin logout successful(...)
  ... net_wlan={\"sn\":\"1784814162\"}

It is a space-separated list of key=value pairs where values themselves may
contain spaces/parentheses/braces and are NOT quoted. We parse it by locating
every `word=` token and treating everything up to the *next* `word=` token as
the value of the previous key (see `parse_syslog_kv`).

Required IAM permission for the Lambda execution role:
  - securityhub:BatchImportFindings

Environment variables (optional, with sensible defaults):
  - AWS_ACCOUNT_ID   : overrides the account id used in ARNs (defaults to caller identity via context)
  - AWS_REGION       : uses the Lambda's own region (Lambda sets this automatically)
  - PRODUCT_NAME     : free-text label used in GeneratorId, default "FortiGate-Syslog"
  - COMPANY_NAME     : ASFF CompanyName field, default "CustomIngest"
"""

import base64
import gzip
import io
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone

import boto3

securityhub = boto3.client("securityhub")

REGION = os.environ.get("AWS_REGION", boto3.session.Session().region_name)
PRODUCT_NAME = os.environ.get("PRODUCT_NAME", "FortiGate-Syslog")
COMPANY_NAME = os.environ.get("COMPANY_NAME", "CustomIngest")

# Security Hub BatchImportFindings hard limit per call
MAX_FINDINGS_PER_BATCH = 100

# --------------------------------------------------------------------------
# Severity mapping: FortiGate/syslog severity -> ASFF Severity Label/Normalized
# --------------------------------------------------------------------------
SEVERITY_MAP = {
    "emergency":     ("CRITICAL", 95),
    "alert":         ("CRITICAL", 90),
    "critical":      ("HIGH", 80),
    "error":         ("HIGH", 70),
    "warning":       ("MEDIUM", 50),
    "notification":  ("LOW", 30),
    "notice":        ("LOW", 30),
    "information":   ("INFORMATIONAL", 10),
    "informational": ("INFORMATIONAL", 10),
    "debug":         ("INFORMATIONAL", 1),
}

# --------------------------------------------------------------------------
# Finding "Types" mapping: event_subtype/event_action -> ASFF Types taxonomy
# (https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-type-taxonomy.html)
# --------------------------------------------------------------------------
TYPES_MAP = {
    ("system", "login"):  ["TTPs/Initial Access/T1078-Valid Accounts"],
    ("system", "logout"): ["Unusual Behaviors/User/Authentication"],
    ("vpn", None):        ["Unusual Behaviors/Network Flow"],
    ("traffic", None):    ["Unusual Behaviors/Network Flow"],
    ("utm", None):        ["TTPs/Command and Control"],
}
DEFAULT_TYPES = ["Unusual Behaviors/Application"]

# Key must start at the beginning of the string or right after whitespace
# (negative lookbehind for a non-space char), so we don't false-match mid
# token (e.g. only capturing "sn=" out of "net_wlan.sn="). Keys may contain
# word chars and dots (e.g. "net_wlan.sn").
KV_PATTERN = re.compile(r"(?<!\S)([\w.]+)=")


def parse_syslog_kv(line: str) -> dict:
    """
    Parse a space-delimited key=value syslog line where values are not
    quoted and may themselves contain spaces. Works by finding every
    `key=` token (anchored to start-of-token) and slicing the text between
    consecutive tokens.
    """
    line = line.strip()
    matches = list(KV_PATTERN.finditer(line))
    result = {}
    for i, m in enumerate(matches):
        key = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(line)
        value = line[start:end].strip()
        # keep first occurrence if a key repeats
        if key not in result:
            result[key] = value
    return result


def to_iso8601(epoch_value: str) -> str:
    """Best-effort conversion of an epoch (possibly fractional) string to
    ASFF's required RFC3339/ISO8601 UTC timestamp. Falls back to now()."""
    try:
        epoch_float = float(str(epoch_value).split(".")[0])
        return datetime.fromtimestamp(epoch_float, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    except (ValueError, TypeError):
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_severity(fields: dict):
    raw = (fields.get("event_severity") or "").strip().lower()
    label, normalized = SEVERITY_MAP.get(raw, ("INFORMATIONAL", 10))
    return {"Label": label, "Normalized": normalized, "Original": raw or "unknown"}


def get_types(fields: dict):
    subtype = (fields.get("event_subtype") or "").strip().lower()
    action = (fields.get("event_action") or "").strip().lower()
    return (
        TYPES_MAP.get((subtype, action))
        or TYPES_MAP.get((subtype, None))
        or DEFAULT_TYPES
    )


def safe_generator_id(fields: dict) -> str:
    parser = fields.get("data_parsername", "unknown-parser")
    source = fields.get("data_sourcename", "unknown-source")
    generator = f"{PRODUCT_NAME}/{parser}/{source}"
    return re.sub(r"\s+", "-", generator)[:128]


def build_finding(fields: dict, account_id: str) -> dict:
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    created_at = to_iso8601(fields.get("event_creation_time") or fields.get("itime"))
    finding_id = fields.get("event_uuid") or fields.get("event_id") or str(uuid.uuid4())
    src_ip = fields.get("src_ip")
    dst_ip = fields.get("dst_ip")

    title = fields.get("event_name") or fields.get("event_action") or "Syslog event"
    description = (fields.get("event_message") or title)[:1024]

    resource_id = (
        fields.get("data_sourceid")
        or fields.get("data_sourcename")
        or dst_ip
        or "unknown-resource"
    )

    finding = {
        "SchemaVersion": "2018-10-08",
        "Id": f"{finding_id}-{fields.get('data_sourceid', 'na')}",
        "ProductArn": f"arn:aws:securityhub:{REGION}:{account_id}:product/{account_id}/default",
        "GeneratorId": safe_generator_id(fields),
        "AwsAccountId": account_id,
        "Types": get_types(fields),
        "CreatedAt": created_at,
        "UpdatedAt": now_iso,
        "Severity": get_severity(fields),
        "Title": title[:256],
        "Description": description,
        "SourceUrl": fields.get("logon_ui") if fields.get("logon_ui", "").startswith("http") else None,
        "ProductFields": {
            "CompanyName": COMPANY_NAME,
            "ProductName": PRODUCT_NAME,
            "data_sourcetype": fields.get("data_sourcetype", ""),
            "data_sourcevdom": fields.get("data_sourcevdom", ""),
        },
        "Resources": [
            {
                "Type": "Other",
                "Id": str(resource_id),
                "Region": REGION,
                "Details": {
                    "Other": {
                        k: str(v)
                        for k, v in fields.items()
                        if k not in ("event_message",)
                    }
                },
            }
        ],
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
    }

    # Optional Network object (only include if we actually have IPs)
    if src_ip or dst_ip:
        network = {}
        if src_ip:
            network["SourceIpV4"] = src_ip
        if dst_ip:
            network["DestinationIpV4"] = dst_ip
        if fields.get("http_method"):
            network["Protocol"] = fields.get("http_method")
        finding["Network"] = network

    # Drop keys with None values (ASFF rejects nulls)
    return {k: v for k, v in finding.items() if v is not None}


def chunked(iterable, size):
    for i in range(0, len(iterable), size):
        yield iterable[i : i + size]


def import_findings(findings: list):
    results = []
    for batch in chunked(findings, MAX_FINDINGS_PER_BATCH):
        resp = securityhub.batch_import_findings(Findings=batch)
        results.append(resp)
        if resp.get("FailedCount", 0):
            print(f"BatchImportFindings had failures: {json.dumps(resp.get('FailedFindings', []))}")
    return results


def extract_raw_lines(event) -> list:
    """Normalize the various possible trigger payloads into a list of raw
    syslog text lines."""
    lines = []

    # 1. CloudWatch Logs subscription filter payload
    if "awslogs" in event:
        compressed = base64.b64decode(event["awslogs"]["data"])
        payload = json.loads(gzip.GzipFile(fileobj=io.BytesIO(compressed)).read())
        for log_event in payload.get("logEvents", []):
            lines.append(log_event["message"])
        return lines

    # 2. Kinesis / Firehose records
    if "Records" in event and event["Records"] and "kinesis" in event["Records"][0]:
        for record in event["Records"]:
            data = base64.b64decode(record["kinesis"]["data"]).decode("utf-8", "ignore")
            lines.append(data)
        return lines

    # 3. Manual/test invocation
    if "logs" in event:
        lines.extend(event["logs"])
    if "log" in event:
        lines.append(event["log"])

    return lines


def lambda_handler(event, context):
    account_id = os.environ.get("AWS_ACCOUNT_ID") or (
        context.invoked_function_arn.split(":")[4] if context else "000000000000"
    )

    raw_lines = extract_raw_lines(event)
    if not raw_lines:
        print("No syslog lines found in event payload.")
        return {"statusCode": 200, "body": "No records to process"}

    findings = []
    for line in raw_lines:
        if not line or not line.strip():
            continue
        try:
            fields = parse_syslog_kv(line)
            if not fields:
                continue
            findings.append(build_finding(fields, account_id))
        except Exception as exc:  # noqa: BLE001
            print(f"Failed to parse/convert line: {line!r} error={exc}")

    if not findings:
        print("No findings built from input.")
        return {"statusCode": 200, "body": "No findings generated"}

    results = import_findings(findings)
    total_success = sum(r.get("SuccessCount", 0) for r in results)
    total_failed = sum(r.get("FailedCount", 0) for r in results)

    print(f"Imported {total_success} findings, {total_failed} failed, out of {len(findings)} parsed.")
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "parsed": len(findings),
                "success": total_success,
                "failed": total_failed,
            }
        ),
    }


# --------------------------------------------------------------------------
# Local test harness: `python lambda_function.py`
# --------------------------------------------------------------------------
if __name__ == "__main__":
    sample = (
        'itime=2026-07-23 20:47:53 epid=3 euid=3 data_parsername=FortiGate Log Parser '
        'data_sourceid=FGTAWSIUIGDJMGF5 data_sourcename=FGTAWSIUIGDJMGF5 root data_sourcetype=FortiGate '
        'data_timestamp=1784789268 dst_ip=10.0.3.59 event_action=logout event_id=32003 '
        'event_message=Admin logout successful(Administrator admin timed out on https(103.3.220.195)) '
        'event_ref=timeout event_severity=information event_subtype=system event_type=event '
        'host_owner=admin http_method=https net_sessionduration=306 src_ip=103.3.220.195 '
        'user_id=admin user_name=admin dstepid=3 dsteuid=3 event_creation_time=1784814468.324275530 '
        'event_resource_id=1784814162 event_status=success event_uuid=0100032003 data_sourcevdom=root '
        'event_name=Admin logout successful logon_ui=https(103.3.220.195) net_wlan.sn=1784814162 '
        'net_wlan={\\"sn\\":\\"1784814162\\"}'
    )
    parsed = parse_syslog_kv(sample)
    print("Parsed fields:")
    print(json.dumps(parsed, indent=2))
    finding = build_finding(parsed, account_id="123456789012")
    print("\nASFF finding:")
    print(json.dumps(finding, indent=2))
