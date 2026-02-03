# Sample Outputs – MAS9 Source Readiness Assessment

This folder contains **example outputs** to help customers, architects, and delivery teams
understand what the MAS9 Readiness tool produces **before running it in their environment**.

These samples are **illustrative only** and do not represent real customer data.

---

## sample_output.json

This file demonstrates the **raw machine-readable output** produced by the tool.

### What it shows
- Input parameters (DB type, app server, OS)
- Overall RAG status (RED / AMBER / GREEN)
- Highest-risk category
- Per-category findings summary
- Counts of RED / AMBER / GREEN findings
- Recommended next actions

### How it is used
- Feeding dashboards or CI/CD pipelines
- Generating executive and technical reports
- Tracking readiness improvements over time

---

## sample_report.pdf

This file demonstrates a **human-readable executive report** generated from the JSON output.

### What it shows
- Overall readiness position
- Category-level risk summary
- Key findings at a glance
- Recommended next actions

### Intended audience
- CIOs and IT leadership
- Program sponsors
- Migration steering committees

---

## Relationship Between Outputs

```
Assessment Run
     |
     +--> JSON Output (sample_output.json)
              |
              +--> PDF / DOCX Executive Reports
              +--> Technical Remediation Worklists
              +--> Dashboards and Metrics
```

---

## Important Notes

- Sample outputs are **safe to commit to GitHub**
- Real assessment outputs may contain sensitive information and
  should be handled according to your organisation’s security policies
- The structure of these samples matches actual tool output

---

For full explanation of checks and interpretation of results,
refer to the master guide located in:

```
docs/MAS9_Readiness_Master_Guide_EXEC_TECH_COMPLETE.docx
```
