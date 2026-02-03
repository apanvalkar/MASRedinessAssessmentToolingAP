# -*- coding: utf-8 -*-
"""export_cron_escalation_inventory.py

Maximo 7.6.1.3 Automation Script (Jython/Python) — MAS9 readiness evidence collector

What it does
- Inventories cron tasks and escalations (volume + complexity signals)
- Outputs JSON (log or file)

Why it matters for MAS9
- High cron/escalation volumes often map to operational tuning work in containerised runtimes
- Some cron tasks rely on local filesystem or external integrations (needs validation)
"""

from psdi.server import MXServer
from java.util import Date
from java.text import SimpleDateFormat

OUTPUT_MODE = "LOG"   # "LOG" or "FILE"
OUTPUT_PATH = "/tmp/mas9_cron_escalation_inventory.json"


def utc_now_iso():
    sdf = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
    sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"))
    return sdf.format(Date())


def main():
    mx = MXServer.getMXServer()

    ms_cron = mx.getMboSet("CRONTASKDEF", mx.getSystemUserInfo())
    ms_escl = mx.getMboSet("ESCALATION", mx.getSystemUserInfo())

    cron_total = ms_cron.count()
    escl_total = ms_escl.count()

    # sample the most relevant fields
    cron_samples = []
    ms_cron.reset()
    mbo = ms_cron.moveFirst()
    while mbo and len(cron_samples) < 50:
        cron_samples.append({
            "crontaskname": mbo.getString("CRONTASKNAME"),
            "class": mbo.getString("CLASSNAME"),
            "description": mbo.getString("DESCRIPTION")
        })
        mbo = ms_cron.moveNext()

    escl_samples = []
    ms_escl.reset()
    mbo = ms_escl.moveFirst()
    while mbo and len(escl_samples) < 50:
        escl_samples.append({
            "escalation": mbo.getString("ESCALATION"),
            "description": mbo.getString("DESCRIPTION"),
            "active": mbo.getBoolean("ACTIVE")
        })
        mbo = ms_escl.moveNext()

    report = {
        "timestamp_utc": utc_now_iso(),
        "tool": {"name": "mas9_readiness_jython", "module": "cron_escalation_inventory"},
        "signals": {
            "crontaskdef_total": cron_total,
            "escalation_total": escl_total,
            "cron_samples": cron_samples,
            "escalation_samples": escl_samples
        },
        "recommendations": [
            "Review cron tasks for local filesystem dependencies and external integrations; validate for containerised runtime.",
            "Validate schedules and concurrency assumptions; consider MAS scaling implications.",
            "High volumes may require tuning of resources, queues, and job scheduling in the MAS target environment."
        ]
    }

    import json
    payload = json.dumps(report, indent=2)

    if OUTPUT_MODE == "FILE":
        try:
            f = open(OUTPUT_PATH, "w")
            f.write(payload)
            f.close()
        except:
            service.log(payload)
    else:
        service.log(payload)

try:
    main()
finally:
    try:
        ms_cron.close()
    except:
        pass
    try:
        ms_escl.close()
    except:
        pass
