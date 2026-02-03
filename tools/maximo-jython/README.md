# Maximo Automation Script (Jython) checks for MAS9 readiness

This folder contains **optional** Jython scripts you can run **inside Maximo 7.6.1.3** (Automation Scripts) to collect *runtime evidence* and identify script patterns that tend to break or require remediation when moving to **MAS9**.

These scripts are **read-only** from a database perspective. They:
- query Maximo metadata using `MXServer` / MBO APIs
- scan automation script source text for risky patterns
- output results as **JSON** (either to a file path you choose, or to the Maximo log if file-write is not permitted)

> Why do this?
> SpotBugs covers **compiled Java**. These scripts cover **Jython automation scripts**, which are often a major migration risk area.

## How to run

### Option A — create an Automation Script (recommended)
1. Go to **System Configuration → Platform Configuration → Automation Scripts**.
2. Create a new script (Script Language: **Python**).
3. Paste the content of one of the `.py` files in this folder.
4. Run it:
   - Either bind to an action (e.g., via a button)
   - Or run via a temporary launch point (e.g., Object Launch Point on a safe object)

### Option B — run via Script Console (if enabled)
If your environment has a script console, you can execute these directly and capture output.

## Outputs
All scripts produce a JSON object with:
- `timestamp_utc`
- `environment` (server name, version hints)
- `signals` (counts, risky pattern hits)
- `recommendations`

You can feed the JSON into your readiness reporting pipeline (manual or automated).

## Scripts

- `export_automation_script_inventory.py`
  - counts scripts + launch points
  - identifies high-risk patterns in script source

- `export_cron_escalation_inventory.py`
  - inventories cron tasks and escalations (volume signals)

## Security / permissions
- File writing may be blocked in some Maximo environments.
- Each script supports **log-only mode** by setting `OUTPUT_MODE = "LOG"`.

## Disclaimer
These are **heuristic** signals. Always validate with solution architecture and IBM MAS Move / Migration Factory outputs.
