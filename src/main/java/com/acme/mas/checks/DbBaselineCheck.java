package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.DbType;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.Finding;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.DbUtil;
import com.acme.mas.util.Dialect;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.util.*;

public final class DbBaselineCheck implements Check {

    private static final Set<String> ALLOWED_SOURCE_VERSIONS = Set.of("7.6.0.10", "7.6.1.2", "7.6.1.3");

    @Override public String id() { return "db-baseline"; }

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) throws Exception {
        Connection conn = ctx.connection;
        if (conn == null) {
            out.addFinding(Finding.err("DATABASE", "No DB connection available."));
            out.addBlock(new RiskBlock("Database baseline", Rag.RED, "DB connection failed; cannot assess database checks.", Map.of()));
            return;
        }

        DatabaseMetaData md = conn.getMetaData();
        out.putCheck("db_connection", Map.of(
                "ok", true,
                "dbms_name", md.getDatabaseProductName(),
                "dbms_version", md.getDatabaseProductVersion(),
                "driver_name", md.getDriverName(),
                "driver_version", md.getDriverVersion()
        ));

        DbType detected = DbUtil.detectDbType(conn);
        DbType effective = (ctx.requestedDbType == DbType.AUTO) ? detected : ctx.requestedDbType;
        ctx.effectiveDbType = effective;
        ctx.dialect = new Dialect(effective == DbType.UNKNOWN ? DbType.SQLSERVER : effective);

        out.putCheck("db_platform", Map.of("detected", detected.toString(), "effective", effective.toString()));

        if (effective == DbType.UNKNOWN) out.addFinding(Finding.warn("DATABASE", "DB type could not be detected; specify --db-type explicitly."));
        else out.addFinding(Finding.ok("DATABASE", "DB platform in use: " + effective));

        if (ctx.expectedDbType != null && ctx.expectedDbType != DbType.UNKNOWN) {
            if (effective != ctx.expectedDbType) {
                out.addFinding(Finding.err("DATABASE",
                        "DB platform mismatch: expected " + ctx.expectedDbType + ", detected " + effective +
                                ". DB platform changes are not supported in Manage upgrade."));
            } else {
                out.addFinding(Finding.ok("DATABASE", "DB platform matches expected: " + ctx.expectedDbType));
            }
        }

        String[] coreTables = {"MAXVARS", "MAXPROP", "MAXOBJECT", "MAXATTRIBUTE"};
        List<Map<String, Object>> readability = new ArrayList<>();
        for (String t : coreTables) {
            String tableQ = DbUtil.qualify(ctx.schema, t);
            try {
                DbUtil.execQuery(conn, ctx.dialect.selectOneFromTable(tableQ));
                readability.add(Map.of("table", t, "select_ok", true));
            } catch (Exception e) {
                readability.add(Map.of("table", t, "select_ok", false, "error", e.getMessage()));
            }
        }
        out.putCheck("db_core_table_readability", readability);

        boolean anyUnreadable = readability.stream().anyMatch(r -> Boolean.FALSE.equals(r.get("select_ok")));
        if (anyUnreadable) out.addFinding(Finding.err("DATABASE", "Cannot read core Maximo tables (permissions/schema).", readability));
        else out.addFinding(Finding.ok("DATABASE", "Core Maximo tables readable via provided connection."));

        List<Map<String, String>> hints = new ArrayList<>();
        String[] candidates = {"MAXIMO_VERSION", "VERSION", "PRODUCTVERSION", "APPVERSION", "SMPVERSION", "DBVERSION"};
        for (String k : candidates) {
            try {
                String v = DbUtil.scalarString(conn,
                        "SELECT value FROM " + DbUtil.qualify(ctx.schema, "MAXVARS") +
                                " WHERE UPPER(varname)=UPPER('" + k + "')");
                if (v != null && !v.isBlank()) hints.add(Map.of("varname", k, "value", v));
            } catch (Exception ignored) { }
        }
        out.putCheck("source_version_hints_db", hints);
        ctx.dbVersionBest = bestDbVersion(hints);
        out.putDerived("db_version_best", ctx.dbVersionBest);

        boolean allowedHit = hints.stream()
                .map(m -> m.getOrDefault("value", ""))
                .anyMatch(val -> ALLOWED_SOURCE_VERSIONS.stream().anyMatch(val::contains));

        if (!hints.isEmpty() && allowedHit) out.addFinding(Finding.ok("SOURCE_VERSION", "DB indicates allowed starting version (7.6.0.10 / 7.6.1.2 / 7.6.1.3)."));
        else if (!hints.isEmpty()) out.addFinding(Finding.warn("SOURCE_VERSION", "DB version hints did not clearly match allowed starting versions; verify patch level."));
        else out.addFinding(Finding.warn("SOURCE_VERSION", "Could not confirm source version from DB MAXVARS; verify patch level manually."));

        Rag rag = anyUnreadable ? Rag.RED : Rag.GREEN;
        out.addBlock(new RiskBlock("Database baseline", rag,
                anyUnreadable ? "DB connected but core Maximo tables were not readable." : "DB connected and core Maximo tables readable.",
                Map.of("core_table_readability", readability, "version_hints", hints)));
    }

    static String bestDbVersion(List<Map<String, String>> hints) {
        if (hints == null || hints.isEmpty()) return null;
        String[] prefer = {"MAXIMO_VERSION", "PRODUCTVERSION", "VERSION", "APPVERSION", "SMPVERSION", "DBVERSION"};
        for (String key : prefer) {
            for (Map<String, String> m : hints) {
                if (key.equalsIgnoreCase(m.getOrDefault("varname", ""))) {
                    String v = m.get("value");
                    if (v != null && !v.isBlank()) return v;
                }
            }
        }
        String v = hints.get(0).get("value");
        return (v == null || v.isBlank()) ? null : v;
    }
}
