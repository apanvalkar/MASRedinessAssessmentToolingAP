
/*
 * Copyright © 2026 Aniruddh Panvelkar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * Original Author: Aniruddh Panvelkar
 * Project: MAS Readiness Assessment Tool
 */

package com.acme.mas;

import com.acme.mas.checks.*;
import com.acme.mas.model.AssessmentResult;
import com.acme.mas.model.Enums.DbType;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.Finding;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.FsUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import picocli.CommandLine;

import java.net.InetAddress;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

@CommandLine.Command(
        name = "mas9-source-readiness",
        mixinStandardHelpOptions = true,
        version = "1.2.0",
        description = "MAS9 source-only readiness checker (Maximo 7.6.x assessed against MAS9 source prerequisites).",
        sortOptions = false
)
public class Mas9SourceReadinessApp implements java.util.concurrent.Callable<Integer> {

    @CommandLine.Option(names = "--jdbc-url", required = true, description = "JDBC URL to Maximo database.")
    private String jdbcUrl;

    @CommandLine.Option(names = "--user", required = true, description = "DB username (read-only recommended).")
    private String user;

    @CommandLine.Option(names = "--password", required = true, interactive = true, description = "DB password (interactive prompt recommended).")
    private String password;

    @CommandLine.Option(names = "--db-type", defaultValue = "AUTO", description = "DB type: ${COMPLETION-CANDIDATES}. Default: ${DEFAULT-VALUE}")
    private DbType dbType;

    @CommandLine.Option(names = "--expected-db-type", description = "Optional enforcement of DB platform continuity: ${COMPLETION-CANDIDATES}")
    private DbType expectedDbType;

    @CommandLine.Option(names = "--schema", description = "Optional schema/owner for Maximo tables (e.g., MAXIMO or dbo).")
    private String schema;

    @CommandLine.Option(names = "--smp-dir", description = "SMP root directory path (recommended for deeper checks).")
    private String smpDir;

    @CommandLine.Option(names = "--properties-file", description = "Path to maximo.properties (optional, for security signals).")
    private String propertiesFile;

    @CommandLine.Option(names = "--include-data-volume", defaultValue = "false", description = "Enable potentially expensive row-count checks. Default: ${DEFAULT-VALUE}")
    private boolean includeDataVolume;

    @CommandLine.Option(names = "--out", description = "Output JSON report path. Default: mas9_source_readiness_<timestamp>.json")
    private String out;

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Mas9SourceReadinessApp()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        String jdbcUrlRedacted = redactSecrets(jdbcUrl);

        AssessmentContext ctx = new AssessmentContext(
                jdbcUrlRedacted,
                user,
                dbType,
                expectedDbType,
                schema,
                smpDir,
                propertiesFile,
                includeDataVolume
        );

        AssessmentResultBuilder builder = new AssessmentResultBuilder();
        builder.putEvidence("smp_dir", FsUtil.fileStat(smpDir));
        builder.putEvidence("properties_file", FsUtil.fileStat(propertiesFile));

        Properties props = new Properties();
        props.setProperty("user", user);
        props.setProperty("password", password);

        try (Connection conn = DriverManager.getConnection(jdbcUrl, props)) {
            ctx.connection = conn;

            List<Check> checks = List.of(
                    new DbBaselineCheck(),
                    new UpgradePathValidationCheck(),
                    new SmpVersionAlignmentCheck(),
                    new SmpCustomisationCheck(),
                    new AutomationComplexityCheck(),
                    new IntegrationCompatibilitySignalsCheck(),
                    new DataQualitySignalsCheck(),
                    new DataVolumeCheck(),
                    new LicensingHintsCheck(),
                    new SecurityPostureSignalsCheck()
            );

            for (Check c : checks) {
                try { c.run(ctx, builder); }
                catch (Exception e) {
                    builder.addFinding(Finding.warn("CHECKS", "Check '" + c.id() + "' failed: " + e.getMessage(), Map.of("check", c.id())));
                }
            }

        } catch (Exception e) {
            builder.putCheck("db_connection", Map.of("ok", false, "error", e.getMessage()));
            builder.addFinding(Finding.err("DATABASE", "Cannot connect to Maximo DB via JDBC: " + e.getMessage()));
            // FS-only checks
            List<Check> checks = List.of(
                    new SmpVersionAlignmentCheck(),
                    new SmpCustomisationCheck(),
                    new SecurityPostureSignalsCheck()
            );
            for (Check c : checks) {
                try { c.run(ctx, builder); }
                catch (Exception ex) {
                    builder.addFinding(Finding.warn("CHECKS", "Check '" + c.id() + "' failed: " + ex.getMessage(), Map.of("check", c.id())));
                }
            }
        }

        AssessmentResult result = builder.build();

        Map<String, Rag> heatmap = deriveHeatmap(result.blocks());
        builder.putDerived("complexity_heatmap", stringifyHeatmap(heatmap));
        builder.putDerived("effort_estimate", ComplexityHeatmapAndEstimatorCheck.estimateEffort(heatmap));
        result = builder.build();

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("timestamp_utc", Instant.now().toString());
        report.put("tool", Map.of("name", "mas9_source_readiness", "mode", "source_only", "version", "java-1.2.0"));
        report.put("host", Map.of(
                "hostname", safeHostName(),
                "os", System.getProperty("os.name"),
                "java", System.getProperty("java.version")
        ));
        report.put("inputs", Map.of(
                "jdbc_url_redacted", ctx.jdbcUrlRedacted,
                "user", ctx.user,
                "db_type", String.valueOf(ctx.requestedDbType),
                "expected_db_type", ctx.expectedDbType == null ? null : String.valueOf(ctx.expectedDbType),
                "schema", ctx.schema,
                "smp_dir", ctx.smpDir,
                "properties_file", ctx.propertiesFile,
                "include_data_volume", ctx.includeDataVolume
        ));
        report.put("evidence", result.evidence());
        report.put("checks", result.checks());
        report.put("derived", result.derived());
        report.put("rag", Map.of("overall", result.overallRag().toString()));

        List<Map<String,Object>> blocksOut = new ArrayList<>();
        for (RiskBlock b : result.blocks()) {
            blocksOut.add(Map.of(
                    "name", b.name(),
                    "rag", b.rag().toString(),
                    "summary", b.summary(),
                    "evidence", b.evidence()
            ));
        }
        report.put("risk_blocks", blocksOut);

        List<Map<String,Object>> findingsOut = new ArrayList<>();
        for (Finding f : result.findings()) {
            Map<String,Object> o = new LinkedHashMap<>();
            o.put("severity", f.severity().toString());
            o.put("category", f.category());
            o.put("message", f.message());
            if (f.details() != null) o.put("details", f.details());
            findingsOut.add(o);
        }
        report.put("findings", findingsOut);

        String outPath = (out != null && !out.isBlank())
                ? out
                : "mas9_source_readiness_" + Instant.now().toString().replace(":", "").replace(".", "") + ".json";

        MAPPER.writeValue(Path.of(outPath).toFile(), report);

        System.out.println("\n=== MAS9 Source Readiness (Source-only) ===");
        System.out.println("Overall RAG: " + result.overallRag());
        System.out.println("Report: " + outPath + "\n");
        System.out.println("Heatmap: " + stringifyHeatmap(heatmap));
        System.out.println("Effort: " + result.derived().get("effort_estimate"));
        System.out.println();

        return (result.overallRag() == Rag.GREEN) ? 0 : (result.overallRag() == Rag.AMBER ? 1 : 2);
    }

    static Map<String, Rag> deriveHeatmap(List<RiskBlock> blocks) {
        Map<String, Rag> map = new LinkedHashMap<>();
        map.put("java", ragFor(blocks, "Custom Java footprint"));
        map.put("ui", ragFor(blocks, "Presentation XML overrides"));
        map.put("automation", ragFor(blocks, "Automation script footprint"));
        map.put("integration", ragFor(blocks, "Integration artifacts"));
        map.put("reports", Rag.AMBER); // placeholder until BIRT inventory module is added
        map.put("data_volume", ragFor(blocks, "Data volume signals"));
        map.put("security", ragFor(blocks, "Security posture signals"));
        map.put("hygiene", ragFor(blocks, "Environment hygiene signals"));
        return map;
    }

    static Rag ragFor(List<RiskBlock> blocks, String blockName) {
        for (RiskBlock b : blocks) {
            if (b.name().equalsIgnoreCase(blockName)) return b.rag();
        }
        return Rag.AMBER;
    }

    static Map<String,String> stringifyHeatmap(Map<String,Rag> heatmap) {
        Map<String,String> out = new LinkedHashMap<>();
        for (var e : heatmap.entrySet()) out.put(e.getKey(), e.getValue().toString());
        return out;
    }

    static String redactSecrets(String s) {
        if (s == null) return null;
        s = Pattern.compile("(password=)([^;]+)", Pattern.CASE_INSENSITIVE).matcher(s).replaceAll("$1***");
        s = Pattern.compile("(PWD=)([^;]+)", Pattern.CASE_INSENSITIVE).matcher(s).replaceAll("$1***");
        return s;
    }

    static String safeHostName() {
        try { return InetAddress.getLocalHost().getHostName(); }
        catch (Exception e) { return "unknown"; }
    }
}
