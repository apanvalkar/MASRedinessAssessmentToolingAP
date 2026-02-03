# MAS9 Source Readiness – Architecture

## Overview
The MAS9 Source Readiness tool is a **static and inventory-based assessment framework**
designed to evaluate IBM Maximo 7.6.1.x environments prior to migration to
IBM Maximo Application Suite (MAS) 9.

The tool intentionally avoids runtime dependency on MAS infrastructure and
can be executed safely against source code, configuration, and database metadata.

---

## High-Level Components

```
+---------------------+
| CLI (Picocli)       |
+----------+----------+
           |
           v
+----------+----------+
| Assessment Engine   |
| - Rule Registry     |
| - RAG Aggregator    |
+----------+----------+
           |
           v
+----------+----------+
| Check Modules       |
| - Automation (Jython)
| - Workflow (DB)     |
| - Java (SpotBugs)   |
+----------+----------+
           |
           v
+----------+----------+
| Outputs              |
| - JSON (machine)     |
| - PDF / DOCX (human) |
+---------------------+
```

---

## Design Principles

- **DB / OS / App Server agnostic**
- **Read-only by default**
- **Deterministic output**
- **Explainable results**
- **Migration-factory aligned**

---

## Extensibility

New checks can be added by:
- Implementing a new Check module
- Registering it with the Rule Registry
- Defining RAG contribution rules

No changes to reporting logic are required.
