# MAS9 Source Readiness (Source-only)

Java CLI tool to assess IBM Maximo 7.6.x source environments against MAS9 source prerequisites.
Uses **picocli** for CLI UX and **Jackson** for structured JSON output.

## Build (no Maven install required)
On Linux/AIX/macOS:
```bash
./mvnw -DskipTests package
```

On Windows:
```bat
mvnw.cmd -DskipTests package
```

## Run (external JDBC driver)
Example DB2 on Linux/AIX:
```bash
java -cp "target/mas9-source-readiness-1.0.0.jar:drivers/db2jcc4.jar" \
  com.acme.mas.Mas9SourceReadinessApp \
  --jdbc-url "jdbc:db2://db2host:50000/MAXDB" \
  --user maxread \
  --password \
  --db-type AUTO \
  --expected-db-type DB2 \
  --schema MAXIMO \
  --out mas9_source_readiness.json
```

Place JDBC drivers under `drivers/` (do not commit).


## Added checks in v1.1.0
- SMP vs DB version alignment
- Custom Java footprint (heuristic)
- Presentation XML overrides (heuristic)
- Automation script footprint (DB)
- Integration artifacts signals (SMP)
\n\n## v1.2.0\n- Modular checks package\n- Heatmap + effort estimator\n- Data quality + integration signals\n- Optional data volume counts\n- Licensing hints\n- Security posture signals\n

## Static analysis template (FindBugs/SpotBugs)
A MAS9 migration-focused FindBugs/SpotBugs filter template is included under `tools/findbugs/`.

## Maximo Automation Script (Jython) checks
This repo includes optional Maximo **Automation Script** collectors under `tools/maximo-jython/` to inventory and risk-score **Jython/Python automation scripts**, cron tasks, and escalations for MAS9 migration readiness.


---

## Documentation

- `docs/` – Executive & Technical master guide
- `samples/` – Example outputs
- `ARCHITECTURE.md` – Tool design
- `CONTRIBUTING.md` – How to extend the tool
