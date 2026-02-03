# -*- coding: utf-8 -*-
"""export_automation_script_inventory.py

Maximo 7.6.1.3 Automation Script (Jython/Python) — MAS9 readiness evidence collector

What it does
- Inventories Automation Scripts and Launch Points
- Scans script source text for patterns that commonly cause issues in MAS9/containerised runtimes
- Outputs a JSON report (to file or to log)

How to use
- Create an Automation Script in Maximo (Python language)
- Paste this file
- Configure OUTPUT_MODE and OUTPUT_PATH

Notes
- Read-only from DB perspective
- Uses MBO APIs; requires permissions to read AUTOSCRIPT and SCRIPTLAUNCHPOINT
"""

from psdi.server import MXServer
from java.util import Date
from java.text import SimpleDateFormat
import re

# ------------------- Configuration -------------------
OUTPUT_MODE = "LOG"   # "LOG" or "FILE"
OUTPUT_PATH = "/tmp/mas9_automation_script_inventory.json"  # used when OUTPUT_MODE == "FILE"
MAX_SAMPLE_HITS = 25

# Patterns that are frequently problematic in MAS9 (heuristics)
RISK_PATTERNS = [
    # OS/process execution
    ("runtime_exec", re.compile(r"Runtime\\.getRuntime\\(\\)\\.exec\\(", re.I)),
    ("processbuilder", re.compile(r"ProcessBuilder\\(", re.I)),

    # Threading / sleeps (pods + lifecycle)
    ("thread_sleep", re.compile(r"Thread\\.sleep\\(", re.I)),
    ("new_thread", re.compile(r"new\\s+Thread\\(", re.I)),

    # File system assumptions
    ("hardcoded_windows_path", re.compile(r"[A-Za-z]:\\\\", re.I)),
    ("hardcoded_unix_path", re.compile(r"/(opt|var|etc|home)/", re.I)),
    ("file_write", re.compile(r"\\b(open\\(|File(Output|Writer)?|FileOutputStream)\\b", re.I)),

    # Network calls without timeouts (common pitfall)
    ("urlopen", re.compile(r"urlopen\\(", re.I)),
    ("httpclient", re.compile(r"HttpURLConnection|requests\\.", re.I)),

    # Reflection/classloading
    ("class_forname", re.compile(r"Class\\.forName\\(", re.I)),

    # Hardcoded secrets
    ("password_literal", re.compile(r"password\\s*=\\s*['\"]", re.I)),

    # Direct SQL string construction (risk)
    ("sql_concat", re.compile(r"\\bSELECT\\b|\\bUPDATE\\b|\\bINSERT\\b|\\bDELETE\\b", re.I)),
]


def utc_now_iso():
    sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
    sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"))
    return sdf.format(Date())


def safe_str(x):
    try:
        return str(x)
    except:
        return ""


def scan_text(text):
    hits = []
    if not text:
        return {"hit_count": 0, "hits": []}

    for (name, pat) in RISK_PATTERNS:
        for m in pat.finditer(text):
            if len(hits) >= MAX_SAMPLE_HITS:
                break
            # capture a small snippet around match
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 60)
            snippet = text[start:end].replace("\n", " ")
            hits.append({"pattern": name, "snippet": snippet})

    return {"hit_count": len(hits), "hits": hits}


def main():
    mx = MXServer.getMXServer()

    # AUTOSCRIPT inventory
    ms_autoscript = mx.getMboSet("AUTOSCRIPT", mx.getSystemUserInfo())
    ms_launch = mx.getMboSet("SCRIPTLAUNCHPOINT", mx.getSystemUserInfo())

    total_scripts = ms_autoscript.count()
    total_launch = ms_launch.count()

    risky = {
        "runtime_exec": 0,
        "threading": 0,
        "filesystem": 0,
        "network": 0,
        "secrets": 0,
        "sql_strings": 0,
        "other": 0
    }

    sample_findings = []

    ms_autoscript.reset()
    mbo = ms_autoscript.moveFirst()
    while mbo:
        try:
            script_name = mbo.getString("AUTOSCRIPT")
            lang = mbo.getString("SCRIPTLANGUAGE")
            source = mbo.getString("SOURCE")

            scanned = scan_text(source)
            if scanned["hit_count"] > 0:
                # Categorise coarse-grained buckets
                for h in scanned["hits"]:
                    p = h["pattern"]
                    if p in ("runtime_exec", "processbuilder"):
                        risky["runtime_exec"] += 1
                    elif p in ("thread_sleep", "new_thread"):
                        risky["threading"] += 1
                    elif p in ("hardcoded_windows_path", "hardcoded_unix_path", "file_write"):
                        risky["filesystem"] += 1
                    elif p in ("urlopen", "httpclient"):
                        risky["network"] += 1
                    elif p in ("password_literal", ):
                        risky["secrets"] += 1
                    elif p in ("sql_concat", ):
                        risky["sql_strings"] += 1
                    else:
                        risky["other"] += 1

                if len(sample_findings) < MAX_SAMPLE_HITS:
                    sample_findings.append({
                        "autoscript": script_name,
                        "language": lang,
                        "scan": scanned
                    })

        except Exception as e:
            # ignore individual script failures
            pass

        mbo = ms_autoscript.moveNext()

    report = {
        "timestamp_utc": utc_now_iso(),
        "tool": {"name": "mas9_readiness_jython", "module": "automation_script_inventory"},
        "signals": {
            "autoscript_total": total_scripts,
            "launchpoint_total": total_launch,
            "risky_script_counts_by_bucket": risky,
            "sample_findings": sample_findings
        },
        "recommendations": [
            "Review scripts flagged in sample_findings; remediate filesystem assumptions, process execution, and threading.",
            "For network calls, enforce explicit timeouts and avoid hard-coded hostnames; use MAS service DNS names.",
            "Avoid hard-coded secrets; migrate to managed secrets/configuration.",
            "Prefer Maximo APIs over direct SQL; validate JDBC usage against MAS container constraints."
        ]
    }

    # Output
    import json
    payload = json.dumps(report, indent=2)

    if OUTPUT_MODE == "FILE":
        try:
            f = open(OUTPUT_PATH, "w")
            f.write(payload)
            f.close()
        except:
            # fall back to log
            service.log(payload)
    else:
        service.log(payload)


# Maximo script entrypoint
try:
    main()
finally:
    try:
        ms_autoscript.close()
    except:
        pass
    try:
        ms_launch.close()
    except:
        pass
