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
from java.util.regex import Pattern

from com.ibm.json.java import JSONObject, JSONArray

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

def _is_dict(x):
    try:
        return isinstance(x, dict)
    except:
        return False

def _is_list(x):
    try:
        return isinstance(x, list)
    except:
        return False

def to_ibm_json(val):
    """Convert Python primitives/dict/list into com.ibm.json.java JSONObject/JSONArray."""
    if _is_dict(val):
        o = JSONObject()
        for k, v in val.items():
            o.put(str(k), to_ibm_json(v))
        return o

    if _is_list(val):
        a = JSONArray()
        for v in val:
            a.add(to_ibm_json(v))
        return a

    return val

def serialize_ibm_json(obj):
    """Serialize IBM JSONObject/JSONArray to a JSON string."""
    try:
        return service.jsonToString(obj)
    except:
        try:
            return obj.serialize()
        except:
            return str(obj)

# ------------------- Java Regex helpers -------------------
def jflags(*flags):
    """Combine java.util.regex.Pattern flags."""
    f = 0
    for x in flags:
        f = f | x
    return f

def compile_pattern(expr, ignore_case=True):
    if ignore_case:
        return Pattern.compile(expr, jflags(Pattern.CASE_INSENSITIVE))
    return Pattern.compile(expr)

def find_matches(pattern, text):
    """
    Returns list of (start, end) offsets for all matches.
    Pattern is a compiled java.util.regex.Pattern.
    """
    out = []
    if not text:
        return out
    m = pattern.matcher(text)
    while m.find():
        out.append((m.start(), m.end()))
    return out

# ------------------- MAS9 Risk Checks -------------------
# Each entry:
# (check_id, pattern_name, java_pattern, bucket, default_severity, description)
CHECKS = [
    ("AS-01", "mxserver_singleton",
     compile_pattern(r"\bMXServer\s*\.\s*getMXServer\s*\("),
     "runtime_state", "AMBER",
     "Direct MXServer singleton usage (multi-pod/runtime state risk in MAS9)."),

    ("AS-09", "mxserver_getmboset_chain",
     compile_pattern(r"\bMXServer\s*\.\s*getMXServer\s*\(\s*\)\s*\.\s*getMboSet\s*\("),
     "memory_db", "AMBER",
     "MXServer.getMXServer().getMboSet(...) usage; can be unbounded and memory-heavy in MAS9 pods."),

    ("SIG-01", "system_userinfo",
     compile_pattern(r"\bgetSystemUserInfo\s*\("),
     "signals", "INFO",
     "Uses system user context (amplifies unbounded fetch risk)."),

    ("SIG-02", "set_where",
     compile_pattern(r"\bsetWhere\s*\("),
     "signals", "INFO",
     "Script applies setWhere() filter."),
    ("SIG-03", "set_qbe",
     compile_pattern(r"\bsetQbe\s*\("),
     "signals", "INFO",
     "Script applies setQbe() filter."),
    ("SIG-04", "set_maxrows",
     compile_pattern(r"\bsetMaxRows\s*\("),
     "signals", "INFO",
     "Script limits rows via setMaxRows()."),
    ("SIG-05", "reset_call",
     compile_pattern(r"\breset\s*\("),
     "signals", "INFO",
     "Script resets MboSet after filters."),
    ("SIG-06", "sqlformat",
     compile_pattern(r"\bSqlFormat\s*\("),
     "signals", "INFO",
     "Uses SqlFormat (often paired with setWhere)."),

    # Note: Java Pattern uses | fine; \b groups OK.
    ("SIG-07", "iteration",
     compile_pattern(r"\bmoveFirst\s*\(|\bmoveNext\s*\("),
     "signals", "INFO",
     "Iterates through MboSet (can be heavy when unbounded)."),
    ("SIG-08", "count_call",
     compile_pattern(r"\bcount\s*\("),
     "signals", "INFO",
     "Calls count() (can be expensive when unbounded)."),

    ("AS-07", "runtime_exec",
     compile_pattern(r"Runtime\.getRuntime\(\)\.exec\("),
     "os_exec", "RED",
     "Executes OS process (not suitable in locked-down containers)."),
    ("AS-07", "processbuilder",
     compile_pattern(r"ProcessBuilder\("),
     "os_exec", "RED",
     "Executes OS process via ProcessBuilder."),

    ("AS-03", "thread_sleep",
     compile_pattern(r"Thread\.sleep\("),
     "threading", "RED",
     "Thread sleep in automation script (pod lifecycle/retry risk)."),
    ("AS-03", "new_thread",
     compile_pattern(r"new\s+Thread\("),
     "threading", "RED",
     "Creates new Thread (not supported / unsafe in container runtime)."),

    ("AS-04", "hardcoded_windows_path",
     compile_pattern(r"[A-Za-z]:\\"),
     "filesystem", "AMBER",
     "Hardcoded Windows path in script."),
    ("AS-04", "hardcoded_unix_path",
     compile_pattern(r"/(opt|var|etc|home)/"),
     "filesystem", "AMBER",
     "Hardcoded Unix path in script."),
    ("AS-04", "file_write",
     compile_pattern(r"\b(open\s*\(|File(Output|Writer)?|FileOutputStream)\b"),
     "filesystem", "RED",
     "Potential file write/IO; pods are ephemeral unless using PVs."),

    ("AS-10", "urlopen",
     compile_pattern(r"\burlopen\s*\("),
     "network", "AMBER",
     "Network call detected; ensure timeouts, DNS and retries are MAS-safe."),
    ("AS-10", "httpclient",
     compile_pattern(r"HttpURLConnection|requests\."),
     "network", "AMBER",
     "HTTP client usage detected; ensure timeouts/retry/idempotency."),

    ("AS-08", "password_literal",
     compile_pattern(r"password\s*=\s*['\"]"),
     "secrets", "RED",
     "Hard-coded password/secret pattern detected."),

    ("AS-05", "sql_keywords",
     compile_pattern(r"\bSELECT\b|\bUPDATE\b|\bINSERT\b|\bDELETE\b"),
     "sql", "AMBER",
     "SQL keywords found (may indicate direct SQL; validate usage)."),
    ("AS-05", "jdbc",
     compile_pattern(r"\bjava\.sql\.|\bPreparedStatement\b|\bcreateStatement\b"),
     "sql", "RED",
     "Direct JDBC usage detected (connection pool & transactional risk)."),

    ("AS-02", "manual_commit",
     compile_pattern(r"\bcommit\s*\("),
     "transactions", "RED",
     "Manual commit() detected; violates managed transaction boundaries."),
    ("AS-02", "manual_rollback",
     compile_pattern(r"\brollback\s*\("),
     "transactions", "RED",
     "Manual rollback() detected; violates managed transaction boundaries."),
    ("AS-02", "mbo_save",
     compile_pattern(r"\.save\s*\("),
     "transactions", "AMBER",
     "save() call detected; validate it is framework-safe and bounded."),

    ("AS-06", "workflow_keywords",
     compile_pattern(r"\bWF\w+\b|\bworkflow\b"),
     "workflow", "AMBER",
     "Workflow-related code detected; validate idempotency and retries."),
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
    per_script_snip_count = 0

    for (check_id, pname, jpat, bucket, severity, desc) in CHECKS:
        matches = find_matches(jpat, source_text)

        if not matches:
            continue

        if check_id.startswith("SIG-"):
            # Only need to record once per script
            signals.add(pname)
            continue

        for (st, en) in matches:
            if per_script_snip_count >= MAX_SNIPPETS_PER_SCRIPT:
                break
            findings.append({
                "checkId": check_id,
                "pattern": pname,
                "severity": severity,
                "description": desc,
                "snippet": snippet_around(source_text, st, en, CONTEXT_WINDOW)
            })
            per_script_snip_count += 1

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
        if f.get("checkId") == "AS-09":
            has_as09 = True
            break
    if not has_as09:
        return

    has_filter = ("set_where" in signals) or ("set_qbe" in signals) or ("set_maxrows" in signals) or ("sqlformat" in signals)
    has_heavy = ("iteration" in signals) or ("count_call" in signals)
    has_sys = ("system_userinfo" in signals)

    final = "AMBER"
    rationale = "MXServer getMboSet chain detected; review for bounding filters."

    if (has_sys or (not has_filter)) and has_heavy:
        final = "RED"
        rationale = "MXServer.getMboSet appears unbounded (no filter) and is iterated/counted; high OOM/DB risk in MAS9 pods."
    elif has_filter:
        final = "AMBER"
        rationale = "MXServer.getMboSet detected but filters/maxRows appear present; verify correctness and reset ordering."

    for f in findings:
        if f.get("checkId") == "AS-09":
            f["severity"] = final
            f["description"] = f["description"] + " " + rationale

def collect_launchpoints(ms_launch):
    """Build mapping: AUTOSCRIPT -> list of launch point descriptors."""
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
        # Optional: prove this revision is running
        # service.log("MAS9_AUTOSCRIPT_INVENTORY java-regex build=2026-02-04")

        mx = MXServer.getMXServer()
        ui = mx.getSystemUserInfo()

        ms_autoscript = mx.getMboSet("AUTOSCRIPT", ui)
        ms_launch = mx.getMboSet("SCRIPTLAUNCHPOINT", ui)

        total_scripts = ms_autoscript.count()
        total_launch = ms_launch.count()

        launch_map = collect_launchpoints(ms_launch)

        check_counts = {}   # checkId -> count of scripts triggering it (per script, dedup)
        severity_counts = {"RED": 0, "AMBER": 0, "GREEN": 0}

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
                    per_script_checks = set()
                    per_script_buckets = set()
                    worst = "GREEN"

                    for f in findings:
                        per_script_checks.add(f.get("checkId"))

                        # Determine bucket for this finding
                        for (cid, pname, _jpat, bucket, _sev, _desc) in CHECKS:
                            if cid == f.get("checkId") and pname == f.get("pattern"):
                                if bucket in buckets:
                                    per_script_buckets.add(bucket)
                                break

                        if f.get("severity") == "RED":
                            worst = "RED"
                        elif f.get("severity") == "AMBER" and worst != "RED":
                            worst = "AMBER"

                    for cid in per_script_checks:
                        check_counts[cid] = check_counts.get(cid, 0) + 1

                    for b in per_script_buckets:
                        buckets[b] = buckets.get(b, 0) + 1

                    severity_counts[worst] = severity_counts.get(worst, 0) + 1

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
                pass

            s = ms_autoscript.moveNext()

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

        obj = to_ibm_json(report)
        payload = serialize_ibm_json(obj)

        if OUTPUT_MODE == "FILE":
            try:
                f = open(OUTPUT_PATH, "w")
                f.write(payload)
                f.close()
            except:
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
