"""
lambda_syslog_to_asff.py
========================
Single-file AWS Lambda function:
  FortiGate Syslog (key=value) → ASFF → AWS Security Hub

Supported event sources:
  - CloudWatch Logs subscription filter
  - Kinesis Data Streams
  - SQS / SNS
  - Direct Lambda invocation  {"syslog": "..."}  or  {"syslog": ["...", "..."]}

Environment Variables:
  SECURITY_HUB_REGION   AWS region of Security Hub        (default: us-east-1)
  AWS_ACCOUNT_ID        AWS account ID (auto-resolved if blank)
  PRODUCT_ARN_SUFFIX    Custom product suffix              (default: syslog-fortigate)
  FINDING_BATCH_SIZE    Max findings per API call          (default: 100)
  LOG_LEVEL             Python log level                   (default: INFO)
"""

# ─────────────────────────────────────────────────────────────────────────────
# Imports
# ─────────────────────────────────────────────────────────────────────────────
import base64
import gzip
import hashlib
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError

# ─────────────────────────────────────────────────────────────────────────────
# Logging & Config
# ─────────────────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
logger = logging.getLogger(__name__)

REGION             = os.environ.get("SECURITY_HUB_REGION",
                     os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
PRODUCT_ARN_SUFFIX = os.environ.get("PRODUCT_ARN_SUFFIX", "syslog-fortigate")
BATCH_SIZE         = int(os.environ.get("FINDING_BATCH_SIZE", "100"))

_ACCOUNT_ID: Optional[str] = None

securityhub = boto3.client("securityhub", region_name=REGION)
sts_client  = boto3.client("sts")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — SYSLOG PARSER
# ═════════════════════════════════════════════════════════════════════════════

# Matches:  key="quoted value"   or   key=unquoted_value
_TOKEN_RE = re.compile(
    r"""
    (?P<key>[A-Za-z_][A-Za-z0-9_.]*?)   # field name
    =                                     # separator
    (?:
        "(?P<qval>(?:[^"\\]|\\.)*)"       # double-quoted value
      |
        (?P<uval>[^\s"=]*)                # unquoted value (no spaces)
    )
    """,
    re.VERBOSE,
)

_DT_FORMATS = [
    "%Y-%m-%d %H:%M:%S",   # itime=2026-07-23 20:47:53
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%SZ",
]


def _parse_timestamp(raw: str) -> Optional[datetime]:
    """Try multiple formats; return UTC datetime or None."""
    for fmt in _DT_FORMATS:
        try:
            return datetime.strptime(raw.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    except (ValueError, OverflowError, TypeError):
        return None


def _try_parse_json(s: str) -> Any:
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return s


def parse_syslog_line(line: str) -> Optional[dict]:
    """
    Parse a FortiGate syslog key=value line into a Python dict.

    Special handling:
      - itime=2026-07-23 20:47:53   (date+time split across two tokens)
      - net_wlan={\"sn\":\"123\"}   (backslash-escaped embedded JSON)
      - Quoted strings with spaces
    Returns None if line is empty or has no parseable fields.
    """
    if not line or not line.strip():
        return None

    result: dict[str, Any] = {
        "_raw":       line,
        "_parsed_at": datetime.now(tz=timezone.utc),
    }

    # ── Tokenise ──────────────────────────────────────────────────────────────
    pairs: list[tuple[str, str, int, int]] = []
    for m in _TOKEN_RE.finditer(line):
        key = m.group("key")
        val = m.group("qval") if m.group("qval") is not None else m.group("uval")
        pairs.append((key, val, m.start(), m.end()))

    if not pairs:
        logger.debug("No key=value pairs found: %.120s", line)
        return None

    # ── Stitch itime date + time (two tokens) ─────────────────────────────────
    cleaned: list[tuple[str, str]] = []
    skip_next = False
    for idx, (key, val, _s, _e) in enumerate(pairs):
        if skip_next:
            skip_next = False
            continue
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", val) and idx + 1 < len(pairs):
            nk, nv, _, _ = pairs[idx + 1]
            if re.fullmatch(r"\d{2}:\d{2}:\d{2}", nk) and nv == "":
                val = f"{val} {nk}"
                skip_next = True
            elif re.fullmatch(r"\d{2}:\d{2}:\d{2}", nv):
                val = f"{val} {nv}"
                skip_next = True
        cleaned.append((key, val))

    # ── Build dict ────────────────────────────────────────────────────────────
    for key, val in cleaned:
        unescaped = val.replace('\\"', '"').replace("\\'", "'")
        if unescaped.startswith(("{", "[")):
            result[key] = _try_parse_json(unescaped)
        else:
            result[key] = unescaped

    # ── Parse timestamps ──────────────────────────────────────────────────────
    for ts_key in ("itime", "data_timestamp", "event_creation_time"):
        raw_ts = result.get(ts_key)
        if raw_ts:
            dt = _parse_timestamp(str(raw_ts))
            if dt:
                result[f"_{ts_key}_dt"] = dt

    # Primary event time (most precise wins)
    result["_event_time"] = (
        result.get("_event_creation_time_dt")
        or result.get("_data_timestamp_dt")
        or result.get("_itime_dt")
        or datetime.now(tz=timezone.utc)
    )
    return result


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — ASFF MAPPER
# ═════════════════════════════════════════════════════════════════════════════

# ── Severity ──────────────────────────────────────────────────────────────────
_SEVERITY_MAP: dict[str, tuple[str, int]] = {
    "emergency":    ("CRITICAL",      100),
    "alert":        ("CRITICAL",       90),
    "critical":     ("CRITICAL",       90),
    "error":        ("HIGH",           70),
    "warning":      ("MEDIUM",         50),
    "notification": ("LOW",            30),
    "information":  ("INFORMATIONAL",  10),
    "debug":        ("INFORMATIONAL",   0),
    # RFC-5424 numeric
    "0": ("CRITICAL",      100),
    "1": ("CRITICAL",       90),
    "2": ("CRITICAL",       90),
    "3": ("HIGH",           70),
    "4": ("MEDIUM",         50),
    "5": ("LOW",            30),
    "6": ("INFORMATIONAL",  10),
    "7": ("INFORMATIONAL",   0),
}

def _map_severity(raw: Optional[str]) -> tuple[str, int]:
    if raw is None:
        return ("INFORMATIONAL", 0)
    return _SEVERITY_MAP.get(str(raw).lower(), ("INFORMATIONAL", 0))


# ── ASFF Types (MITRE ATT&CK aligned) ────────────────────────────────────────
_TYPE_MAP: dict[str, str] = {
    "event/system/login":   "TTPs/Initial Access/Valid Accounts",
    "event/system/logout":  "TTPs/Defense Evasion/Account Manipulation",
    "event/system/admin":   "TTPs/Privilege Escalation/Valid Accounts",
    "event/vpn":            "TTPs/Initial Access/External Remote Services",
    "event/ha":             "Software and Configuration Checks/Infrastructure Configuration",
    "traffic/local":        "TTPs/Command and Control/Application Layer Protocol",
    "traffic/forward":      "Software and Configuration Checks/Network Reachability",
    "utm/virus":            "TTPs/Execution/Malware",
    "utm/webfilter":        "Software and Configuration Checks/Industry and Regulatory Standards",
    "utm/ips":              "TTPs/Lateral Movement/Exploitation of Remote Services",
    "utm/anomaly":          "TTPs/Discovery/Network Service Discovery",
    "utm/emailfilter":      "TTPs/Initial Access/Phishing",
    "utm/dlp":              "Software and Configuration Checks/Data Protection",
}
_DEFAULT_TYPE = "Software and Configuration Checks/Security Monitoring/Syslog Event"

def _map_type(parsed: dict) -> list[str]:
    et  = str(parsed.get("event_type",    "")).lower()
    est = str(parsed.get("event_subtype", "")).lower()
    ea  = str(parsed.get("event_action",  "")).lower()
    for key, val in _TYPE_MAP.items():
        if f"{et}/{est}/{ea}".startswith(key) or f"{et}/{est}".startswith(key):
            return [val]
    return [_DEFAULT_TYPE]


# ── Finding ID (deterministic / idempotent) ────────────────────────────────────
def _finding_id(parsed: dict, account_id: str, region: str) -> str:
    event_uuid = parsed.get("event_uuid", "")
    if event_uuid:
        try:
            uid = str(uuid.UUID(str(event_uuid)))
        except ValueError:
            uid = str(event_uuid)
        return f"arn:aws:securityhub:{region}:{account_id}:finding/{uid}"

    seed = "|".join([
        str(parsed.get("event_id", "")),
        str(parsed.get("data_sourceid", "")),
        str(parsed.get("event_creation_time", parsed.get("itime", ""))),
        str(parsed.get("event_message", "")),
    ])
    h = hashlib.sha256(seed.encode()).hexdigest()
    return f"arn:aws:securityhub:{region}:{account_id}:finding/{h}"


# ── Fields already mapped (excluded from UserDefinedFields) ──────────────────
_SKIP = frozenset({
    "itime", "data_timestamp", "event_creation_time", "src_ip", "dst_ip",
    "event_severity", "event_message", "event_name", "event_type",
    "event_subtype", "event_action", "event_uuid", "event_id",
    "user_name", "user_id", "data_sourcename", "data_sourceid",
    "data_sourcetype", "data_sourcevdom", "host_owner", "event_status",
    "http_method", "net_sessionduration", "logon_ui", "event_ref",
    "_raw", "_parsed_at", "_event_time",
    "_itime_dt", "_data_timestamp_dt", "_event_creation_time_dt",
})


def build_asff_finding(parsed: dict, account_id: str, product_arn: str, region: str) -> dict:
    """Convert parsed FortiGate dict → ASFF finding dict."""

    event_time: datetime = parsed["_event_time"]
    iso_time = event_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    sev_label, sev_norm = _map_severity(parsed.get("event_severity"))

    title       = str(parsed.get("event_name") or
                      parsed.get("event_message", "Unknown Security Event"))[:256]
    description = str(parsed.get("event_message") or
                      parsed.get("event_name", "No description available"))[:1024]

    # ── Resources ─────────────────────────────────────────────────────────────
    src_name  = parsed.get("data_sourcename") or parsed.get("data_sourceid", "unknown-device")
    src_type  = parsed.get("data_sourcetype", "Other")
    resources = [
        {
            "Type":      "AwsEc2Instance" if src_type == "FortiGate" else "Other",
            "Id":        f"arn:aws:securityhub:::device/{src_name}",
            "Partition": "aws",
            "Region":    region,
            "Tags": {
                "SourceType": str(src_type),
                "SourceName": str(src_name),
                "SourceVdom": str(parsed.get("data_sourcevdom", "root")),
                "HostOwner":  str(parsed.get("host_owner", "")),
            },
        }
    ]
    user_name = parsed.get("user_name") or parsed.get("user_id")
    if user_name:
        resources.append({
            "Type":      "AwsIamUser",
            "Id":        f"arn:aws:iam::{account_id}:user/{user_name}",
            "Partition": "aws",
            "Tags": {
                "Username": str(user_name),
                "LoginUI":  str(parsed.get("logon_ui", "")),
            },
        })

    # ── Network ───────────────────────────────────────────────────────────────
    network: dict[str, str] = {}
    if parsed.get("src_ip"):
        network["SourceIpV4"] = parsed["src_ip"]
    if parsed.get("dst_ip"):
        network["DestinationIpV4"] = parsed["dst_ip"]
    protocol = parsed.get("http_method") or parsed.get("event_ref")
    if protocol:
        network["Protocol"] = str(protocol).upper()

    # ── Compliance / Workflow ─────────────────────────────────────────────────
    status = str(parsed.get("event_status", "")).lower()
    compliance_status = {"success": "PASSED", "failed": "FAILED", "error": "FAILED"}.get(status)
    workflow_status   = "RESOLVED" if status == "success" else "NEW"

    # ── UserDefinedFields (all remaining fields) ──────────────────────────────
    udf: dict[str, str] = {
        k: json.dumps(v) if isinstance(v, dict) else str(v)
        for k, v in parsed.items()
        if k not in _SKIP and not k.startswith("_")
    }

    # ── Core ASFF finding ──────────────────────────────────────────────────────
    finding: dict[str, Any] = {
        "SchemaVersion": "2018-10-08",
        "Id":            _finding_id(parsed, account_id, region),
        "ProductArn":    product_arn,
        "GeneratorId":   f"{src_type}/{parsed.get('data_parsername', 'SyslogParser')}",
        "AwsAccountId":  account_id,
        "Types":         _map_type(parsed),
        "CreatedAt":     iso_time,
        "UpdatedAt":     iso_time,
        "Severity": {
            "Label":      sev_label,
            "Normalized": sev_norm,
            "Original":   str(parsed.get("event_severity", "information")),
        },
        "Title":       title,
        "Description": description,
        "Resources":   resources,
        "Workflow":    {"Status": workflow_status},
        "RecordState": "ACTIVE",
        "ProductFields": {
            "ProviderName":    str(parsed.get("data_parsername", "FortiGate Log Parser")),
            "SourceId":        str(parsed.get("data_sourceid", "")),
            "SourceName":      str(parsed.get("data_sourcename", "")),
            "SourceType":      str(src_type),
            "EventType":       str(parsed.get("event_type", "")),
            "EventSubtype":    str(parsed.get("event_subtype", "")),
            "EventAction":     str(parsed.get("event_action", "")),
            "EventStatus":     str(parsed.get("event_status", "")),
            "SessionDuration": str(parsed.get("net_sessionduration", "")),
        },
        "FindingProviderFields": {
            "Severity": {"Label": sev_label, "Original": str(parsed.get("event_severity", ""))},
            "Types":    _map_type(parsed),
        },
    }

    if network:
        finding["Network"] = network
    if compliance_status:
        finding["Compliance"] = {"Status": compliance_status}
    if udf:
        finding["UserDefinedFields"] = udf

    # Note: session info
    notes = []
    if parsed.get("net_sessionduration"):
        notes.append(f"Session: {parsed['net_sessionduration']}s")
    if parsed.get("logon_ui"):
        notes.append(f"UI: {parsed['logon_ui']}")
    if notes:
        finding["Note"] = {
            "Text":      " | ".join(notes),
            "UpdatedBy": "lambda-syslog-asff",
            "UpdatedAt": iso_time,
        }

    logger.debug("Built ASFF finding: %s", finding["Id"])
    return finding


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — EVENT EXTRACTION
# ═════════════════════════════════════════════════════════════════════════════

def extract_syslog_lines(event: dict) -> list[str]:
    """Extract raw syslog strings from any supported Lambda event source."""
    lines: list[str] = []

    # CloudWatch Logs subscription filter
    if "awslogs" in event:
        compressed = base64.b64decode(event["awslogs"]["data"])
        payload    = json.loads(gzip.decompress(compressed))
        for log_event in payload.get("logEvents", []):
            lines.append(log_event.get("message", ""))
        logger.info("Source: CloudWatch Logs — %d events", len(lines))
        return lines

    # Kinesis / SQS / SNS Records
    if "Records" in event:
        for record in event["Records"]:
            source = record.get("eventSource", "")

            if source == "aws:kinesis":
                raw = base64.b64decode(record["kinesis"]["data"]).decode("utf-8")
                lines.extend(l.strip() for l in raw.splitlines() if l.strip())

            elif source == "aws:sqs":
                body = record.get("body", "")
                try:
                    msg = json.loads(body)
                    body = msg.get("Message", body)   # unwrap SNS→SQS
                except json.JSONDecodeError:
                    pass
                lines.extend(l.strip() for l in body.splitlines() if l.strip())

            elif source == "aws:sns":
                msg = record.get("Sns", {}).get("Message", "")
                lines.extend(l.strip() for l in msg.splitlines() if l.strip())

        logger.info("Source: Records (%s) — %d lines",
                    event["Records"][0].get("eventSource", "?"), len(lines))
        return lines

    # Direct invocation
    if "syslog" in event:
        payload = event["syslog"]
        lines = [str(l) for l in payload if str(l).strip()] if isinstance(payload, list) \
                else [str(payload)]
        logger.info("Source: Direct invocation — %d lines", len(lines))
        return lines

    # Raw body
    if "body" in event:
        lines.extend(l.strip() for l in str(event["body"]).splitlines() if l.strip())
        return lines

    logger.warning("Unknown event structure, keys: %s", list(event.keys()))
    return [json.dumps(event)]


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — LAMBDA HANDLER
# ═════════════════════════════════════════════════════════════════════════════

def _get_account_id() -> str:
    global _ACCOUNT_ID
    if _ACCOUNT_ID is None:
        _ACCOUNT_ID = os.environ.get(
            "AWS_ACCOUNT_ID",
            sts_client.get_caller_identity()["Account"]
        )
    return _ACCOUNT_ID


def _send_to_security_hub(findings: list[dict]) -> dict:
    """Send findings in batches; return import summary."""
    summary = {"imported": 0, "failed": 0, "errors": []}
    for i in range(0, len(findings), BATCH_SIZE):
        batch = findings[i : i + BATCH_SIZE]
        try:
            resp = securityhub.batch_import_findings(Findings=batch)
            summary["imported"] += resp.get("SuccessCount", 0)
            failed = resp.get("FailedCount", 0)
            summary["failed"] += failed
            if failed:
                summary["errors"].extend(resp.get("FailedFindings", []))
                logger.warning("Batch %d: %d failed", i // BATCH_SIZE, failed)
            else:
                logger.info("Batch %d: %d imported", i // BATCH_SIZE, len(batch))
        except ClientError as exc:
            logger.error("BatchImportFindings error: %s", exc)
            summary["failed"] += len(batch)
            summary["errors"].append(str(exc))
    return summary


def lambda_handler(event: dict, context: Any) -> dict:
    """AWS Lambda entry point."""
    logger.info("Invoked. Event keys: %s", list(event.keys()))

    account_id  = _get_account_id()
    product_arn = (
        f"arn:aws:securityhub:{REGION}:{account_id}:"
        f"product/{account_id}/{PRODUCT_ARN_SUFFIX}"
    )

    # 1. Extract raw syslog lines
    syslog_lines = extract_syslog_lines(event)
    if not syslog_lines:
        return {"statusCode": 200, "body": "No syslog lines to process."}

    # 2. Parse + map to ASFF
    findings: list[dict] = []
    parse_errors = 0
    for raw_line in syslog_lines:
        try:
            parsed = parse_syslog_line(raw_line)
            if parsed is None:
                parse_errors += 1
                continue
            findings.append(build_asff_finding(parsed, account_id, product_arn, REGION))
        except Exception as exc:        # noqa: BLE001
            logger.error("Error on line: %s | %.200s", exc, raw_line)
            parse_errors += 1

    logger.info("Built %d findings (%d parse errors)", len(findings), parse_errors)

    if not findings:
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "No valid findings.", "parse_errors": parse_errors}),
        }

    # 3. Send to Security Hub
    summary = _send_to_security_hub(findings)
    summary["parse_errors"] = parse_errors
    summary["total_lines"]  = len(syslog_lines)
    logger.info("Done: %s", summary)

    return {
        "statusCode": 200 if summary["failed"] == 0 else 207,
        "body": json.dumps(summary),
    }
