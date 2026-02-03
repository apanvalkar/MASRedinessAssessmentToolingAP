#
#"""
#export_automation_script_inventory.py

#Maximo 7.6.1.x Automation Script (Jython/Python) — MAS9 readiness evidence collector (DB-based)

#What it does
#- Inventories AUTOSCRIPT and SCRIPTLAUNCHPOINT from DB (read-only)
#- Scans script source for MAS9 risk patterns (static text heuristics)
#- Produces JSON output (LOG or FILE)

#Key MAS9 checks included (high value)
#- AS-01: MXServer.getMXServer() singleton usage
#- AS-02: Manual commit/rollback/save patterns (heuristic)
#- AS-03: Threading/sleep
#- AS-04: Filesystem assumptions
#- AS-05: Direct JDBC/SQL string usage (heuristic)
#- AS-06: Workflow manipulation patterns (heuristic)
#- AS-07: OS command execution
#- AS-08: Hard-coded secrets
#- AS-09: Unbounded getMboSet via MXServer (memory/DB risk in MAS9 pods)

#Notes
#- Uses MBO APIs; requires read permissions on AUTOSCRIPT and SCRIPTLAUNCHPOINT
#"""

from psdi.server import MXServer
from java.util import Date, TimeZone
from java.text import SimpleDateFormat
import re
import json

# ------------------- Configuration -------------------
OUTPUT_MODE = "LOG"   # "LOG" or "FILE"
OUTPUT_PATH = "/tmp/mas9_automation_script_inventory.json"  # used if OUTPUT_MODE == "FILE"
MAX_SAMPLE_FINDINGS = 50          # number of scripts to include with detailed findings
MAX_SNIPPETS_PER_SCRIPT = 12      # max snippets per script
CONTEXT_WINDOW = 80               # chars around match

# ------------------- Helpers -------------------
def utc_now_iso():
    sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
    sdf.setTimeZone(TimeZone.getTimeZone("UTC"))
    return sdf.format(Date())

def safe_get(mbo, attr):
    try:
        return mbo.getString(attr)
    except:
        return ""

def snippet_around(text, start, end, window):
    s = max(0, start - window)
    e = min(len(text), end + window)
    return text[s:e].replace("\n", " ").replace("\r", " ")

# ------------------- MAS9 Risk Checks -------------------
# Each entry:
# (check_id, pattern_name, regex, bucket, default_severity, description)
CHECKS = [
    # AS-01: MXServer singleton usage
    ("AS-01", "mxserver_singleton", re.compile(r"\bMXServer\s*\.\s*getMXServer\s*\(", re.I),
     "runtime_state", "AMBER",
     "Direct MXServer singleton usage (multi-pod/runtime state risk in MAS9)."),

    # AS-09: MXServer.getMXServer().getMboSet(...) (high risk when unbounded)
    ("AS-09", "mxserver_getmboset_chain",
     re.compile(r"\bMXServer\s*\.\s*getMXServer\s*\(\s*\)\s*\.\s*getMboSet\s*\(", re.I),
     "memory_db", "AMBER",
     "MXServer.getMXServer().getMboSet(...) usage; can be unbounded and memory-heavy in MAS9 pods."),

    # System user context (used as signal for AS-09 severity)
    ("SIG-01", "system_userinfo", re.compile(r"\bgetSystemUserInfo\s*\(", re.I),
     "signals", "INFO", "Uses system user context (amplifies unbounded fetch risk)."),

    # Filtering signals (reduce AS-09 severity if present)
    ("SIG-02", "set_where", re.compile(r"\bsetWhere\s*\(", re.I),
     "signals", "INFO", "Script applies setWhere() filter."),
    ("SIG-03", "set_qbe", re.compile(r"\bsetQbe\s*\(", re.I),
     "signals", "INFO", "Script applies setQbe() filter."),
    ("SIG-04", "set_maxrows", re.compile(r"\bsetMaxRows\s*\(", re.I),
     "signals", "INFO", "Script limits rows via setMaxRows()."),
    ("SIG-05", "reset_call", re.compile(r"\breset\s*\(", re.I),
     "signals", "INFO", "Script resets MboSet after filters."),
    ("SIG-06", "sqlformat", re.compile(r"\bSqlFormat\s*\(", re.I),
     "signals", "INFO", "Uses SqlFormat (often paired with setWhere)."),

    # Iteration / heavy operations signals
    ("SIG-07", "iteration", re.compile(r"\bmoveFirst\s*\(|\bmoveNext\s*\(", re.I),
     "signals", "INFO", "Iterates through MboSet (can be heavy when unbounded)."),
    ("SIG-08", "count_call", re.compile(r"\bcount\s*\(", re.I),
     "signals", "INFO", "Calls count() (can be expensive when unbounded)."),

    # OS / process execution
    ("AS-07", "runtime_exec", re.compile(r"Runtime\.getRuntime\(\)\.exec\(", re.I),
     "os_exec", "RED", "Executes OS process (not suitable in locked-down containers)."),
    ("AS-07", "processbuilder", re.compile(r"ProcessBuilder\(", re.I),
     "os_exec", "RED", "Executes OS process via ProcessBuilder."),

    # Threading / sleeps
    ("AS-03", "thread_sleep", re.compile(r"Thread\.sleep\(", re.I),
     "threading", "RED", "Thread sleep in automation script (pod lifecycle/retry risk)."),
    ("AS-03", "new_thread", re.compile(r"new\s+Thread\(", re.I),
     "threading", "RED", "Creates new Thread (not supported / unsafe in container runtime)."),

    # Filesystem assumptions / writes
    ("AS-04", "hardcoded_windows_path", re.compile(r"[A-Za-z]:\\", re.I),
     "filesystem", "AMBER", "Hardcoded Windows path in script."),
    ("AS-04", "hardcoded_unix_path", re.compile(r"/(opt|var|etc|home)/", re.I),
     "filesystem", "AMBER", "Hardcoded Unix path in script."),
    ("AS-04", "file_write", re.compile(r"\b(open\s*\(|File(Output|Writer)?|FileOutputStream)\b", re.I),
     "filesystem", "RED", "Potential file write/IO; pods are ephemeral unless using PVs."),

    # Network calls (heuristic)
    ("AS-10", "urlopen", re.compile(r"\burlopen\s*\(", re.I),
     "network", "AMBER", "Network call detected; ensure timeouts, DNS and retries are MAS-safe."),
    ("AS-10", "httpclient", re.compile(r"HttpURLConnection|requests\.", re.I),
     "network", "AMBER", "HTTP client usage detected; ensure timeouts/retry/idempotency."),

    # Secrets
    ("AS-08", "password_literal", re.compile(r"password\s*=\s*['\"]", re.I),
     "secrets", "RED", "Hard-coded password/secret pattern detected."),

    # SQL strings / direct JDBC heuristics
    ("AS-05", "sql_keywords", re.compile(r"\bSELECT\b|\bUPDATE\b|\bINSERT\b|\bDELETE\b", re.I),
     "sql", "AMBER", "SQL keywords found (may indicate direct SQL; validate usage)."),
    ("AS-05", "jdbc", re.compile(r"\bjava\.sql\.|\bPreparedStatement\b|\bcreateStatement\b", re.I),
     "sql", "RED", "Direct JDBC usage detected (connection pool & transactional risk)."),

    # Transaction boundary heuristics (strong MAS9 risk)
    ("AS-02", "manual_commit", re.compile(r"\bcommit\s*\(", re.I),
     "transactions", "RED", "Manual commit() detected; violates managed transaction boundaries."),
    ("AS-02", "manual_rollback", re.compile(r"\brollback\s*\(", re.I),
     "transactions", "RED", "Manual rollback() detected; violates managed transaction boundaries."),
    ("AS-02", "mbo_save", re.compile(r"\.save\s*\(", re.I),
     "transactions", "AMBER", "save() call detected; validate it is framework-safe and bounded."),

    # Workflow manipulation heuristics (adjustable)
    ("AS-06", "workflow_keywords", re.compile(r"\bWF\w+\b|\bworkflow\b", re.I),
     "workflow", "AMBER", "Workflow-related code detected; validate idempotency and retries."),
]

def scan_script(source_text):
    """
    Returns:
      signals: set of signal names hit
      findings: list of findings with checkId/pattern/snippet
    """
    if not source_text:
        return set(), []

    findings = []
    signals = set()

    # collect per pattern hits (with snippet limits)
    per_script_snip_count = 0

    for (check_id, pname, regex, bucket, severity, desc) in CHECKS:
        for m in regex.finditer(source_text):
            # treat SIG-* as signals only (not surfaced as findings by default)
            if check_id.startswith("SIG-"):
                signals.add(pname)
            else:
                if per_script_snip_count < MAX_SNIPPETS_PER_SCRIPT:
                    findings.append({
                        "checkId": check_id,
                        "pattern": pname,
                        "severity": severity,
                        "description": desc,
                        "snippet": snippet_around(source_text, m.start(), m.end(), CONTEXT_WINDOW)
                    })
                    per_script_snip_count += 1
            # only need one signal record per script
            if check_id.startswith("SIG-"):
                break

    return signals, findings

def derive_as09_severity(signals, findings):
    """
    Upgrade/downgrade severity for AS-09 based on local signals.
    Heuristic:
      RED if mxserver_getmboset_chain and (system_userinfo OR no filters) and (iteration OR count)
      AMBER if mxserver_getmboset_chain but filters exist
    """
    has_as09 = False
    for f in findings:
        if f["checkId"] == "AS-09":
            has_as09 = True
            break
    if not has_as09:
        return

    has_filter = ("set_where" in signals) or ("set_qbe" in signals) or ("set_maxrows" in signals) or ("sqlformat" in signals)
    has_heavy = ("iteration" in signals) or ("count_call" in signals)
    has_sys = ("system_userinfo" in signals)

    # Decide final severity for AS-09 findings
    final = "AMBER"
    rationale = "MXServer getMboSet chain detected; review for bounding filters."
    if (has_sys or (not has_filter)) and has_heavy:
        final = "RED"
        rationale = "MXServer.getMboSet appears unbounded (no filter) and is iterated/counted; high OOM/DB risk in MAS9 pods."
    elif has_filter:
        final = "AMBER"
        rationale = "MXServer.getMboSet detected but filters/maxRows appear present; verify correctness and reset ordering."

    # Apply to AS-09 findings
    for f in findings:
        if f["checkId"] == "AS-09":
            f["severity"] = final
            f["description"] = f["description"] + " " + rationale

def collect_launchpoints(ms_launch):
    """
    Build mapping: AUTOSCRIPT -> list of launch point descriptors
    """
    mapping = {}
    try:
        ms_launch.reset()
        lp = ms_launch.moveFirst()
        while lp:
            try:
                as_name = safe_get(lp, "AUTOSCRIPT")
                lp_name = safe_get(lp, "SCRIPTLAUNCHPOINT")
                lp_type = safe_get(lp, "LAUNCHPOINTTYPE")
                obj = safe_get(lp, "OBJECTNAME")
                attr = safe_get(lp, "ATTRIBUTENAME")
                event = safe_get(lp, "EVENTTYPE")
                desc = {
                    "launchpoint": lp_name,
                    "type": lp_type,
                    "object": obj,
                    "attribute": attr,
                    "event": event
                }
                if as_name:
                    mapping.setdefault(as_name, []).append(desc)
            except:
                pass
            lp = ms_launch.moveNext()
    except:
        pass
    return mapping

def main():
    ms_autoscript = None
    ms_launch = None

    try:
        mx = MXServer.getMXServer()
        ui = mx.getSystemUserInfo()

        ms_autoscript = mx.getMboSet("AUTOSCRIPT", ui)
        ms_launch = mx.getMboSet("SCRIPTLAUNCHPOINT", ui)

        total_scripts = ms_autoscript.count()
        total_launch = ms_launch.count()

        launch_map = collect_launchpoints(ms_launch)

        # Per-check counts (per script, dedup)
        check_counts = {}   # checkId -> count of scripts triggering it
        severity_counts = {"RED": 0, "AMBER": 0, "GREEN": 0}

        # Bucket counts (per script, dedup)
        buckets = {
            "runtime_state": 0,
            "memory_db": 0,
            "transactions": 0,
            "threading": 0,
            "filesystem": 0,
            "network": 0,
            "secrets": 0,
            "sql": 0,
            "workflow": 0,
            "os_exec": 0
        }

        detailed_findings = []
        scripts_with_findings = 0

        ms_autoscript.reset()
        s = ms_autoscript.moveFirst()

        while s:
            try:
                script_name = safe_get(s, "AUTOSCRIPT")
                lang = safe_get(s, "SCRIPTLANGUAGE")
                source = safe_get(s, "SOURCE")

                signals, findings = scan_script(source)
                derive_as09_severity(signals, findings)

                if findings:
                    # Deduplicate per script by checkId and by bucket
                    per_script_checks = set()
                    per_script_buckets = set()
                    worst = "GREEN"

                    for f in findings:
                        per_script_checks.add(f["checkId"])

                        # determine bucket for this finding (lookup from CHECKS)
                        # (simple map build on the fly)
                        for (cid, pname, regex, bucket, sev, desc) in CHECKS:
                            if cid == f["checkId"] and pname == f["pattern"]:
                                if bucket in buckets:
                                    per_script_buckets.add(bucket)
                                break

                        if f["severity"] == "RED":
                            worst = "RED"
                        elif f["severity"] == "AMBER" and worst != "RED":
                            worst = "AMBER"

                    # increment counts per script
                    for cid in per_script_checks:
                        check_counts[cid] = check_counts.get(cid, 0) + 1

                    for b in per_script_buckets:
                        buckets[b] = buckets.get(b, 0) + 1

                    severity_counts[worst] = severity_counts.get(worst, 0) + 1

                    # store details for a limited number of scripts
                    if scripts_with_findings < MAX_SAMPLE_FINDINGS:
                        detailed_findings.append({
                            "autoscript": script_name,
                            "language": lang,
                            "worstSeverity": worst,
                            "launchPoints": launch_map.get(script_name, []),
                            "signals": sorted(list(signals)),
                            "findings": findings
                        })
                        scripts_with_findings += 1

            except:
                # keep scanning
                pass

            s = ms_autoscript.moveNext()

        # Executive-ish recommendation text (high value for migration)
        recommendations = [
            "Prioritise remediation of RED findings first (OS exec, threading, unbounded MXServer getMboSet, JDBC, hard-coded secrets).",
            "For MXServer.getMboSet usage: ensure setWhere/setQbe + reset ordering, use setMaxRows where possible, and avoid system user unless required.",
            "Replace manual transaction controls (commit/rollback/save) with framework-safe patterns; validate idempotency under MAS9 retries.",
            "For filesystem access: move to managed PVs/config maps or redesign to avoid local writes in pods.",
            "For network calls: enforce timeouts, use MAS DNS/service endpoints, and design for retries without side effects."
        ]

        report = {
            "timestamp_utc": utc_now_iso(),
            "tool": {
                "name": "mas9_readiness_jython",
                "module": "automation_script_inventory_dbscan",
                "maximo_version_target": "7.6.1.x",
                "mas_target": "MAS 9"
            },
            "signals": {
                "autoscript_total": total_scripts,
                "launchpoint_total": total_launch,
                "scripts_with_findings_included": scripts_with_findings,
                "severity_counts_by_script": severity_counts,
                "check_counts_by_script": check_counts,
                "bucket_counts_by_script": buckets,
                "sample_findings": detailed_findings
            },
            "recommendations": recommendations
        }

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

    finally:
        try:
            if ms_autoscript:
                ms_autoscript.close()
        except:
            pass
        try:
            if ms_launch:
                ms_launch.close()
        except:
            pass

# Maximo script entrypoint
main()
