package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.FsUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public final class SmpCustomisationCheck implements Check {
    @Override public String id() { return "smp-customisation"; }

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) throws Exception {
        Path smp = ctx.smpPath();
        if (smp == null || !FsUtil.dirExists(smp)) {
            out.addBlock(new RiskBlock("SMP customisation", Rag.AMBER,
                    "SMP directory not provided or not accessible; SMP customisation checks skipped.",
                    Map.of("smp_dir", ctx.smpDir)));
            return;
        }

        out.addBlock(structureBlock(smp));
        out.addBlock(customJavaBlock(smp));
        out.addBlock(presentationXmlBlock(smp));
        out.addBlock(integrationBlock(smp));
        out.addBlock(hygieneBlock(smp));
    }

    private static RiskBlock structureBlock(Path smp) {
        List<String> required = List.of(
                "maximo",
                "maximo/applications",
                "maximo/applications/maximo",
                "maximo/applications/maximo/businessobjects",
                "maximo/applications/maximo/properties",
                "maximo/tools",
                "maximo/etc"
        );
        List<String> missing = new ArrayList<>();
        for (String r : required) {
            if (!Files.exists(smp.resolve(r))) missing.add(r);
        }
        Rag rag = missing.isEmpty() ? Rag.GREEN : (missing.size() <= 2 ? Rag.AMBER : Rag.RED);
        String summary = missing.isEmpty() ? "Core SMP folders detected." : "Missing expected SMP folders: " + String.join(", ", missing);
        return new RiskBlock("SMP structure completeness", rag, summary, Map.of("missing", missing, "checked", required));
    }

    private static RiskBlock hygieneBlock(Path smp) throws Exception {
        Path backup = smp.resolve("maximo/tools/backup");
        Path patch = smp.resolve("maximo/tools/patch");

        List<String> backupSample = new ArrayList<>();
        List<String> patchSample = new ArrayList<>();

        long backupFiles = FsUtil.countFilesByExt(backup, Set.of(".zip",".tar",".gz",".bak"), 10, backupSample);
        long patchFiles = FsUtil.countFilesByExt(patch, Set.of(".log",".txt",".jar",".zip"), 10, patchSample);

        Rag rag = (patchFiles > 0 || backupFiles > 0) ? Rag.AMBER : Rag.GREEN;
        String summary = (patchFiles > 0 || backupFiles > 0)
                ? "Hygiene signals detected (backup/patch artifacts). Review before migration tooling runs."
                : "No significant patch/backup residue detected under tools/.";

        Map<String,Object> ev = new LinkedHashMap<>();
        ev.put("backup_dir", backup.toString());
        ev.put("patch_dir", patch.toString());
        ev.put("backup_artifact_count", backupFiles);
        ev.put("patch_artifact_count", patchFiles);
        ev.put("backup_sample", backupSample);
        ev.put("patch_sample", patchSample);
        return new RiskBlock("Environment hygiene signals", rag, summary, ev);
    }

    private static RiskBlock customJavaBlock(Path smp) throws Exception {
        Path base = smp.resolve("maximo/applications/maximo/businessobjects/classes");
        if (!FsUtil.dirExists(base)) {
            return new RiskBlock("Custom Java footprint", Rag.AMBER,
                    "Classes directory not found (expected maximo/applications/maximo/businessobjects/classes).",
                    Map.of("expected_path", base.toString()));
        }

        long totalJava = 0, totalClass = 0, customJava = 0, customClass = 0, nonIbmJava = 0, nonIbmClass = 0;

        try (var stream = Files.walk(base)) {
            for (Path p : (Iterable<Path>) stream::iterator) {
                if (!Files.isRegularFile(p)) continue;
                String fn = p.getFileName().toString().toLowerCase(Locale.ROOT);
                boolean isJava = fn.endsWith(".java");
                boolean isClass = fn.endsWith(".class");
                if (!isJava && !isClass) continue;

                String rel = base.relativize(p).toString().replace('\\', '/').toLowerCase(Locale.ROOT);
                boolean underCustom = rel.startsWith("custom/") || rel.contains("/custom/");
                boolean isIbm = rel.startsWith("psdi/") || rel.startsWith("com/ibm/") || rel.contains("/psdi/") || rel.contains("/com/ibm/");

                if (isJava) totalJava++;
                if (isClass) totalClass++;
                if (underCustom) {
                    if (isJava) customJava++;
                    if (isClass) customClass++;
                }
                if (!isIbm) {
                    if (isJava) nonIbmJava++;
                    if (isClass) nonIbmClass++;
                }
            }
        }

        long footprint = Math.max(nonIbmJava + nonIbmClass, customJava + customClass);
        Rag rag = footprint >= 200 ? Rag.RED : (footprint >= 50 ? Rag.AMBER : Rag.GREEN);

        String summary = "Heuristic custom footprint=" + footprint +
                " (nonIbmJava=" + nonIbmJava + ", nonIbmClass=" + nonIbmClass +
                ", customJava=" + customJava + ", customClass=" + customClass + ").";

        Map<String,Object> ev = new LinkedHashMap<>();
        ev.put("classes_path", base.toString());
        ev.put("total_java", totalJava);
        ev.put("total_class", totalClass);
        ev.put("custom_java", customJava);
        ev.put("custom_class", customClass);
        ev.put("non_ibm_java", nonIbmJava);
        ev.put("non_ibm_class", nonIbmClass);
        ev.put("heuristic_custom_footprint", footprint);

        return new RiskBlock("Custom Java footprint", rag, summary, ev);
    }

    private static RiskBlock presentationXmlBlock(Path smp) throws Exception {
        Path dir = smp.resolve("maximo/applications/maximo/properties/product");
        if (!FsUtil.dirExists(dir)) {
            return new RiskBlock("Presentation XML overrides", Rag.AMBER,
                    "Presentation XML directory not found (expected maximo/applications/maximo/properties/product).",
                    Map.of("expected_path", dir.toString()));
        }

        List<String> sample = new ArrayList<>();
        long xmlCount = FsUtil.countFilesByExt(dir, Set.of(".xml"), 30, sample);

        Rag rag = xmlCount >= 200 ? Rag.RED : (xmlCount >= 50 ? Rag.AMBER : Rag.GREEN);
        String summary = "Found " + xmlCount + " XML files under product/ (override heuristic).";
        return new RiskBlock("Presentation XML overrides", rag, summary, Map.of("path", dir.toString(), "xml_count", xmlCount, "sample", sample));
    }

    private static RiskBlock integrationBlock(Path smp) throws Exception {
        Path integDir = smp.resolve("maximo/applications/maximo/integration");
        Path etcDir = smp.resolve("maximo/etc");

        List<String> sampleInteg = new ArrayList<>();
        List<String> sampleMx = new ArrayList<>();

        long integSignals = FsUtil.countFilesByExt(integDir, Set.of(".xml",".xsd",".properties",".jar",".java",".class"), 30, sampleInteg);
        long mxintegSignals = FsUtil.countFilesByPrefix(etcDir, "mxinteg", 30, sampleMx);

        long totalSignals = integSignals + mxintegSignals;
        Rag rag = totalSignals >= 200 ? Rag.RED : (totalSignals >= 50 ? Rag.AMBER : Rag.GREEN);
        String summary = "integration/* signals=" + integSignals + ", etc/mxinteg* signals=" + mxintegSignals + ".";

        return new RiskBlock("Integration artifacts", rag, summary, Map.of(
                "integration_dir", integDir.toString(),
                "etc_dir", etcDir.toString(),
                "integration_signals", integSignals,
                "mxinteg_signals", mxintegSignals,
                "sample_integration", sampleInteg,
                "sample_mxinteg", sampleMx
        ));
    }
}
