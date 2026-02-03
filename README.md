
# MAS9 Source Readiness Assessment Tool

## Purpose

The MAS9 Source Readiness Assessment Tool evaluates whether an existing **IBM Maximo 7.6.1.x**
environment is technically ready to migrate to **IBM Maximo Application Suite (MAS) 9**.

MAS9 is a **platform transformation**, not a traditional upgrade. It introduces containerised
execution, horizontal scaling, automated restarts, stricter JVM behaviour, and modern security
constraints. Many Maximo environments are stable today because of long-running JVM assumptions
that do not hold true in MAS9.

This tool identifies **source-level and design-level risks** early, before migration timelines
and budgets are committed.

The tool is:
- Read-only
- Non-intrusive
- Safe to run against production (with read-only DB access)
- Independent of MAS infrastructure

---

## What the Tool Checks

### 1. Automation Scripts (Jython / Python)
Detects high-risk patterns including:
- MXServer singleton usage
- Manual commit / rollback / save
- Threading and sleep calls
- Filesystem access
- Direct JDBC usage
- Workflow engine manipulation
- OS command execution
- Hard-coded secrets and endpoints

---

### 2. Workflow Inventory & Complexity
Analyses workflow metadata from:
- WFPROCESS
- WFNODE
- WFROUTE
- WFASSIGNMENT
- WFACTION

Identifies:
- Workflow scale
- Routing and fan-out complexity
- Scripted workflow actions
- Compound workflow + automation risks

---

### 3. Java Customisations (Static Analysis)
Analyses compiled Java custom code for:
- Null safety issues
- Resource leaks
- Unsafe concurrency
- Static initialisation hazards
- Hard-coded file paths
- Weak cryptography
- Hard-coded secrets

---

## RAG Scoring Model

Each category produces an independent risk signal.

**Overall Readiness = Highest Risk Category**

| RAG | Meaning |
|----|-------|
| GREEN | Minimal remediation required |
| AMBER | Targeted remediation required |
| RED | Structural refactoring required before migration |

---

## How to Run the Tool

### Prerequisites
- Java 11+
- Network access to Maximo database
- Read-only DB credentials
- JDBC driver for your database

Supported databases:
- DB2
- Oracle
- SQL Server

---

### Step 1: Prepare the Environment

```bash
cd MAS9ReadinessAPVersion
```

Place your database JDBC driver in:

```
drivers/
```

---

### Step 2: Build the Tool

```bash
./mvnw clean package
```

---

### Step 3: Run the Assessment

```bash
java -jar target/mas9-readiness.jar --help
```

Example:

```bash
java -jar target/mas9-readiness.jar   --dbType db2   --dbHost db.company.local   --dbPort 50000   --dbName MAXDB   --dbSchema MAXIMO   --dbUser readonly_user   --dbPassword ******   --smpHome /opt/IBM/SMP   --appServer websphere   --os linux   --driversDir ./drivers   --outputDir ./out
```

---

## Outputs Produced

```
out/
├── assessment.json
├── executive-report.pdf
├── technical-report.pdf
├── evidence/
└── logs/
```

---

## Documentation

- docs/ – Master Executive + Technical Guide
- ARCHITECTURE.md – Tool design
- CONTRIBUTING.md – Contribution guide
- samples/ – Example outputs

---
