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
  PRODUCT_ARN_SUFFIX    Custom product suffix              (default: default)
  FINDING_BATCH_SIZE    Max findings per API call          (default: 100)
  LOG_LEVEL             Python log level                   (default: INFO)

Changelog:
  v1.3  Fix Network.Protocol → only TCP/UDP/ICMP/ICMPv6 allowed
        Fix Resources[].Id  → sanitize spaces/special chars
        Fix UserDefinedFields → max 50 keys, key≤128 chars, value≤1024 chars
        Fix GeneratorId     → max 512 chars, no control chars
        Add detailed FailedFindings error logging
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
PRODUCT_ARN_SUFFIX = os.environ.get("PRODUCT_ARN_SUFFIX", "default")
BATCH_SIZE         = int(os.environ.get("FINDING_BATCH_SIZE", "100"))

_ACCOUNT_ID: Optional[str] = None

securityhub = boto3.client("securityhub", region_name=REGION)
sts_client  = boto3.client("sts")


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 1 — SYSLOG PARSER
# ═════════════════════════════════════════════════════════════════════════════

# Finds every  key=  that starts at beginning-of-string or after whitespace.
# This ensures we don't match  key=  patterns that are INSIDE values
# (e.g. inside a JSON string or a URL like https://x.com?q=1).
_KEY_POS_RE = re.compile(r'(?:(?<=\s)|^)([A-Za-z_][A-Za-z0-9_.]*?)=')

_DT_FORMATS = [
    "%Y-%m-%d %H:%M:%S",   # itime=2026-07-23 22:22:03
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
    Parse a FortiGate syslog key=value line into a structured dict.

    Strategy: locate ALL  key=  positions first, then slice the raw line
    between consecutive key positions.  This correctly handles:

      - Multi-word unquoted values:
          event_name=Admin logout successful logon_ui=...
          → event_name = "Admin logout successful"   ✅

      - Values containing spaces (device names, messages):
          data_sourcename=FGT-AWS root data_sourcetype=...
          → data_sourcename = "FGT-AWS root"          ✅

      - Date+time values:
          itime=2026-07-23 22:22:03 epid=...
          → itime = "2026-07-23 22:22:03"             ✅

      - Quoted values (standard):
          event_message="Admin logout successful(...)"
          → event_message = "Admin logout successful(...)" ✅

      - Embedded JSON (backslash-escaped by FortiGate):
          net_wlan={\"sn\":\"1784819455\"}
          → net_wlan = {"sn": "1784819455"}           ✅

    Returns None if line is blank or has no parseable fields.
    """
    if not line or not line.strip():
        return None

    result: dict[str, Any] = {
        "_raw":       line,
        "_parsed_at": datetime.now(tz=timezone.utc),
    }

    # ── Find all key= positions ────────────────────────────────────────────────
    key_matches = list(_KEY_POS_RE.finditer(line))
    if not key_matches:
        logger.debug("No key=value pairs found: %.120s", line)
        return None

    # ── Slice values between consecutive key positions ─────────────────────────
    for i, m in enumerate(key_matches):
        key       = m.group(1)
        val_start = m.end()                       # character right after '='
        val_end   = key_matches[i + 1].start() if i + 1 < len(key_matches) else len(line)

        raw_val = line[val_start:val_end].strip()

        # ── Handle quoted value ───────────────────────────────────────────────
        if raw_val.startswith('"'):
            inner = raw_val[1:]
            # Find the closing un-escaped quote
            end_q = -1
            j = 0
            while j < len(inner):
                if inner[j] == '\\':
                    j += 2          # skip escaped char
                    continue
                if inner[j] == '"':
                    end_q = j
                    break
                j += 1
            raw_val = inner[:end_q] if end_q >= 0 else inner
            # Unescape \" inside
            raw_val = raw_val.replace('\\"', '"').replace("\\'", "'")

        # ── Handle embedded JSON (FortiGate backslash-escapes JSON values) ────
        elif raw_val.startswith(("{", "[")):
            unescaped = raw_val.replace('\\"', '"')
            raw_val = _try_parse_json(unescaped)

        result[key] = raw_val

    # ── Parse timestamps ───────────────────────────────────────────────────────
    for ts_key in ("itime", "data_timestamp", "event_creation_time"):
        raw_ts = result.get(ts_key)
        if raw_ts:
            dt = _parse_timestamp(str(raw_ts))
            if dt:
                result[f"_{ts_key}_dt"] = dt

    # Primary event time — most precise field wins
    result["_event_time"] = (
        result.get("_event_creation_time_dt")
        or result.get("_data_timestamp_dt")
        or result.get("_itime_dt")
        or datetime.now(tz=timezone.utc)
    )
    return result


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 2 — ASFF FIELD VALIDATORS / SANITIZERS
# ═════════════════════════════════════════════════════════════════════════════

# ASFF Network.Protocol only accepts these values (case-insensitive input → uppercase)
_VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "ICMPv6"}

# Application-layer → transport layer mapping
_PROTO_MAP = {
    "HTTP":    "TCP",
    "HTTPS":   "TCP",
    "FTP":     "TCP",
    "SSH":     "TCP",
    "TELNET":  "TCP",
    "SMTP":    "TCP",
    "DNS":     "UDP",
    "DHCP":    "UDP",
    "SNMP":    "UDP",
    "SYSLOG":  "UDP",
    "TFTP":    "UDP",
    "NTP":     "UDP",
    "IPsec":   "UDP",
    "IPSEC":   "UDP",
    "GRE":     "TCP",
    "TIMEOUT": "TCP",  # FortiGate event_ref value
}


def _sanitize_protocol(raw: str) -> Optional[str]:
    """
    Map any protocol string to a valid ASFF Network.Protocol value.
    Returns None if no mapping found (field will be omitted).
    """
    upper = str(raw).strip().upper()
    if upper in _VALID_PROTOCOLS:
        return upper
    mapped = _PROTO_MAP.get(upper)
    if mapped:
        return mapped
    # If it ends up not matching anything, omit rather than send invalid value
    logger.debug("Unmapped protocol '%s' — omitting Network.Protocol", raw)
    return None


def _sanitize_resource_id(raw_id: str) -> str:
    """
    ASFF Resource.Id must not contain spaces or control characters.
    Replace spaces with hyphens; strip leading/trailing whitespace.
    Max length: 512 chars.
    """
    clean = re.sub(r"\s+", "-", str(raw_id).strip())
    # Remove any remaining non-printable characters
    clean = re.sub(r"[^\x20-\x7E]", "", clean)
    return clean[:512]


def _sanitize_generator_id(raw: str) -> str:
    """GeneratorId: max 512 chars, printable ASCII only."""
    clean = re.sub(r"[^\x20-\x7E]", "", str(raw).strip())
    return clean[:512] or "FortiGate/SyslogParser"


def _sanitize_udf(raw_dict: dict[str, str]) -> dict[str, str]:
    """
    ASFF UserDefinedFields constraints:
      - Max 50 key-value pairs
      - Key:   max 128 chars, alphanumeric + underscore + dot
      - Value: max 1024 chars, string only
    """
    out: dict[str, str] = {}
    for k, v in raw_dict.items():
        # Sanitize key: keep only allowed chars
        clean_k = re.sub(r"[^A-Za-z0-9_.]", "_", str(k))[:128]
        if not clean_k:
            continue
        # Truncate value
        clean_v = str(v)[:1024]
        out[clean_k] = clean_v
        if len(out) >= 50:
            logger.debug("UserDefinedFields capped at 50 entries")
            break
    return out


def _sanitize_product_fields(raw_dict: dict[str, str]) -> dict[str, str]:
    """ProductFields: key max 128 chars, value max 2048 chars."""
    return {
        str(k)[:128]: str(v)[:2048]
        for k, v in raw_dict.items()
    }


def _sanitize_tags(raw_dict: dict[str, str]) -> dict[str, str]:
    """Resource Tags: key max 128, value max 256, max 50 tags."""
    out: dict[str, str] = {}
    for k, v in raw_dict.items():
        out[str(k)[:128]] = str(v)[:256]
        if len(out) >= 50:
            break
    return out


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 3 — ASFF MAPPER
# ═════════════════════════════════════════════════════════════════════════════

# ── Severity ──────────────────────────────────────────────────────────────────
_SEVERITY_MAP: dict[str, tuple[str, int]] = {
    # Based on FortiGate Event Type (type / event_type)
    "utm":          ("HIGH",           70),
    "anomaly":      ("MEDIUM",         50),
    "event":        ("INFORMATIONAL",  10),
    "traffic":      ("INFORMATIONAL",   0),
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


# ── Finding ID (randomized per event) ─────────────────────────────────────────
def _finding_id(parsed: dict, account_id: str, region: str) -> str:
    uid = str(uuid.uuid4())
    return f"arn:aws:securityhub:{region}:{account_id}:finding/{uid}"


# ── Fields already mapped (excluded from UserDefinedFields) ──────────────────
_SKIP = frozenset({
    # FortiAnalyzer normalized names
    "itime", "data_timestamp", "event_creation_time", "src_ip", "dst_ip",
    "event_severity", "event_message", "event_name", "event_type",
    "event_subtype", "event_action", "event_uuid", "event_id",
    "user_name", "user_id", "data_sourcename", "data_sourceid",
    "data_sourcetype", "data_sourcevdom", "host_owner", "event_status",
    "http_method", "net_sessionduration", "logon_ui", "event_ref",
    "data_parsername",
    # Raw FortiGate field names
    "msg", "devname", "devid", "type", "subtype", "action",
    "srcip", "dstip", "srcname", "dstname", "user", "ui",
    "severity", "level", "logid", "sessionid", "duration",
    "proto", "service", "status", "reason", "logdesc",
    # Internal parser fields
    "_raw", "_parsed_at", "_event_time",
    "_itime_dt", "_data_timestamp_dt", "_event_creation_time_dt",
})


def _get(parsed: dict, *keys: str, default: str = "") -> str:
    """
    Try multiple field name aliases in order; return first non-empty value.
    Handles both FortiAnalyzer normalized names and raw FortiGate names.

    Example:
        _get(parsed, "event_message", "msg", "logdesc", default="No description")
    """
    for k in keys:
        v = parsed.get(k)
        if v is not None and str(v).strip():
            return str(v).strip()
    return default


def build_asff_finding(parsed: dict, account_id: str, product_arn: str, region: str) -> dict:
    """Convert parsed FortiGate dict → ASFF finding dict (validated)."""

    # ── DIAGNOSTIC LOGGING ────────────────────────────────────────────────────
    # Log the raw syslog line (first 500 chars)
    raw_line = str(parsed.get("_raw", ""))
    logger.info("RAW SYSLOG (first 500): %.500s", raw_line)

    # Log ALL parsed field names + value snippets (first 80 chars each)
    field_dump = {
        k: str(v)[:80]
        for k, v in parsed.items()
        if not k.startswith("_")
    }
    logger.info("PARSED FIELDS: %s", json.dumps(field_dump, default=str))

    event_time: datetime = parsed["_event_time"]
    iso_time = event_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    # ── Severity — use EventType (type / event_type) ──────────────────────────
    event_type_val = _get(parsed, "event_type", "type")
    sev_label, sev_norm = _map_severity(event_type_val or None)

    # ── Title — try all common fields, ultimate fallback = raw syslog line ───
    title = _get(
        parsed,
        "event_name",    # FortiAnalyzer
        "event_message", # FortiAnalyzer
        "msg",           # Raw FortiGate
        "logdesc",       # Raw FortiGate
        "reason",        # Raw FortiGate
    )
    if not title:
        # Ultimate fallback: use the raw syslog line itself (first 256 chars)
        title = f"FortiGate: {raw_line[:240]}" if raw_line else "FortiGate Security Event"
    title = title[:256]

    # ── Description — try all common fields, fallback = raw syslog line ──────
    description = _get(
        parsed,
        "event_message", # FortiAnalyzer
        "msg",           # Raw FortiGate
        "logdesc",       # Raw FortiGate
        "event_name",    # FortiAnalyzer fallback
    )
    if not description:
        description = raw_line[:1024] if raw_line else "No description available"
    description = description[:1024]

    # Log final title and description
    logger.info("TITLE: %s", title)
    logger.info("DESCRIPTION (first 200): %.200s", description)

    # ── Resources — try all device name / type field variants ────────────────
    src_name = _sanitize_resource_id(
        _get(parsed,
             "data_sourcename",  # FortiAnalyzer
             "data_sourceid",    # FortiAnalyzer
             "devname",          # Raw FortiGate
             "devid",            # Raw FortiGate
             "srcname",          # Raw FortiGate
             default="unknown-device")
    )
    src_type = _get(parsed, "data_sourcetype", default="FortiGate")

    resources = [
        {
            "Type":      "AwsEc2Instance" if src_type == "FortiGate" else "Other",
            "Id":        f"arn:aws:securityhub:::device/{src_name}",
            "Partition": "aws",
            "Region":    region,
            "Tags": _sanitize_tags({
                "SourceType": str(src_type),
                "SourceName": str(src_name),
                "SourceVdom": str(parsed.get("data_sourcevdom", "root")),
                "HostOwner":  str(parsed.get("host_owner", "")),
            }),
        }
    ]

    user_name = _get(parsed,
                     "user_name",  # FortiAnalyzer
                     "user_id",    # FortiAnalyzer
                     "user",       # Raw FortiGate
                     "unauthuser", # Raw FortiGate
                     default="")
    if user_name:
        resources.append({
            "Type":      "AwsIamUser",
            "Id":        f"arn:aws:iam::{account_id}:user/{_sanitize_resource_id(user_name)}",
            "Partition": "aws",
            "Tags": _sanitize_tags({
                "Username": user_name,
                "LoginUI":  _get(parsed, "logon_ui", "ui"),
            }),
        })

    # ── Network — try FortiAnalyzer & raw FortiGate field names ─────────────
    # NOTE: Network.Protocol only accepts TCP / UDP / ICMP / ICMPv6
    network: dict[str, Any] = {}
    src_ip = _get(parsed, "src_ip", "srcip")
    dst_ip = _get(parsed, "dst_ip", "dstip")
    if src_ip:
        network["SourceIpV4"] = src_ip
    if dst_ip:
        network["DestinationIpV4"] = dst_ip

    raw_proto = _get(parsed, "http_method", "proto", "service", "event_ref")
    if raw_proto:
        valid_proto = _sanitize_protocol(raw_proto)
        if valid_proto:
            network["Protocol"] = valid_proto

    # ── Compliance / Workflow ─────────────────────────────────────────────────
    status = _get(parsed, "event_status", "status", "reason").lower()
    compliance_status = {"success": "PASSED", "failed": "FAILED", "error": "FAILED"}.get(status)
    workflow_status   = "RESOLVED" if status == "success" else "NEW"

    # ── UserDefinedFields (all remaining fields, sanitized) ───────────────────
    raw_udf: dict[str, str] = {
        k: json.dumps(v) if isinstance(v, dict) else str(v)
        for k, v in parsed.items()
        if k not in _SKIP and not k.startswith("_")
    }
    udf = _sanitize_udf(raw_udf)

    # ── GeneratorId (sanitized) ───────────────────────────────────────────────
    generator_id = _sanitize_generator_id(
        f"{src_type}/{_get(parsed, 'data_parsername', default='SyslogParser')}"
    )

    # ── Core ASFF finding ─────────────────────────────────────────────────────
    finding: dict[str, Any] = {
        "SchemaVersion": "2018-10-08",
        "Id":            _finding_id(parsed, account_id, region),
        "ProductArn":    product_arn,
        "GeneratorId":   generator_id,
        "AwsAccountId":  account_id,
        "Types":         _map_type(parsed),
        "CreatedAt":     iso_time,
        "UpdatedAt":     iso_time,
        "Severity": {
            "Label":      sev_label,
            "Normalized": sev_norm,
            "Original":   str(parsed.get("event_severity") or "information"),
        },
        "Title":       title,
        "Description": description,
        "Resources":   resources,
        "Workflow":    {"Status": workflow_status},
        "RecordState": "ACTIVE",
        "ProductFields": _sanitize_product_fields({
            "ProviderName":    _get(parsed, "data_parsername",    default="FortiGate Log Parser"),
            "SourceId":        _get(parsed, "data_sourceid",      "devid"),
            "SourceName":      _get(parsed, "data_sourcename",    "devname"),
            "SourceType":      src_type,
            "EventType":       _get(parsed, "event_type",         "type"),
            "EventSubtype":    _get(parsed, "event_subtype",      "subtype"),
            "EventAction":     _get(parsed, "event_action",       "action"),
            "EventStatus":     _get(parsed, "event_status",       "status"),
            "SessionDuration": _get(parsed, "net_sessionduration", "duration"),
        }),
        "FindingProviderFields": {
            "Severity": {
                "Label":    sev_label,
                "Original": str(parsed.get("event_severity") or "information"),
            },
            "Types": _map_type(parsed),
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
    dur = _get(parsed, "net_sessionduration", "duration")
    if dur:
        notes.append(f"Session: {dur}s")
    login_ui = _get(parsed, "logon_ui", "ui")
    if login_ui:
        notes.append(f"UI: {login_ui[:200]}")
    if notes:
        finding["Note"] = {
            "Text":      " | ".join(notes)[:512],
            "UpdatedBy": "lambda-syslog-asff",
            "UpdatedAt": iso_time,
        }

    logger.debug("Built ASFF finding: %s", finding["Id"])
    return finding


# ═════════════════════════════════════════════════════════════════════════════
# SECTION 4 — EVENT EXTRACTION
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
                    event["Records"][0].get("eventSource", "?") if event.get("Records") else "?",
                    len(lines))
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
# SECTION 5 — LAMBDA HANDLER
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
    """Send findings in batches; log each individual failure reason."""
    summary: dict[str, Any] = {"imported": 0, "failed": 0, "errors": []}

    for i in range(0, len(findings), BATCH_SIZE):
        batch = findings[i : i + BATCH_SIZE]
        try:
            resp   = securityhub.batch_import_findings(Findings=batch)
            imported = resp.get("SuccessCount", 0)
            failed   = resp.get("FailedCount",  0)
            summary["imported"] += imported
            summary["failed"]   += failed

            if failed:
                # ── Log each failure with its ErrorCode + ErrorMessage ────────
                for ff in resp.get("FailedFindings", []):
                    err_info = {
                        "FindingId":    ff.get("Id", "unknown"),
                        "ErrorCode":    ff.get("ErrorCode", ""),
                        "ErrorMessage": ff.get("ErrorMessage", ""),
                    }
                    logger.error(
                        "FAILED finding | id=%s | code=%s | msg=%s",
                        err_info["FindingId"],
                        err_info["ErrorCode"],
                        err_info["ErrorMessage"],
                    )
                    summary["errors"].append(err_info)

                logger.warning(
                    "Batch %d: %d imported, %d failed",
                    i // BATCH_SIZE, imported, failed
                )
            else:
                logger.info("Batch %d: %d imported ✓", i // BATCH_SIZE, imported)

        except ClientError as exc:
            logger.error("BatchImportFindings ClientError: %s", exc)
            summary["failed"] += len(batch)
            summary["errors"].append({"ErrorMessage": str(exc)})

    return summary


def lambda_handler(event: dict, context: Any) -> dict:
    """AWS Lambda entry point."""
    logger.info("Invoked. Event keys: %s", list(event.keys()))

    account_id  = _get_account_id()
    product_arn = (
        f"arn:aws:securityhub:{REGION}:{account_id}:"
        f"product/{account_id}/{PRODUCT_ARN_SUFFIX}"
    )
    logger.info("ProductArn: %s", product_arn)

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
            logger.error("Parse/map error: %s | line=%.200s", exc, raw_line)
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
    logger.info("Done: imported=%d failed=%d parse_errors=%d",
                summary["imported"], summary["failed"], parse_errors)

    return {
        "statusCode": 200 if summary["failed"] == 0 else 207,
        "body": json.dumps(summary, default=str),
    }
