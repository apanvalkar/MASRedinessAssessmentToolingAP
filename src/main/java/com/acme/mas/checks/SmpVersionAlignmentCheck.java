package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.FsUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class SmpVersionAlignmentCheck implements Check {
    @Override public String id() { return "smp-version-alignment"; }

    private static final String[] SMP_VERSION_FILES = {
            "maximo/version.properties",
            "maximo/etc/version.properties",
            "maximo/applications/maximo/properties/version.properties"
    };

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) throws Exception {
        Path smp = ctx.smpPath();
        if (smp == null || !FsUtil.dirExists(smp)) {
            out.addBlock(new RiskBlock("SMP vs DB version alignment", Rag.AMBER,
                    "SMP directory not provided or not accessible; cannot validate SMP/DB version alignment.",
                    Map.of("smp_dir", ctx.smpDir)));
            return;
        }

        List<Map<String, Object>> found = new ArrayList<>();
        for (String rel : SMP_VERSION_FILES) {
            Path p = smp.resolve(rel);
            if (Files.exists(p) && Files.isRegularFile(p)) {
                String text = FsUtil.safeRead(p, 200_000);
                String v = extractVersion(text);
                found.add(Map.of("file", rel, "exists", true, "detected_version", v));
            } else {
                found.add(Map.of("file", rel, "exists", false));
            }
        }

        String smpVersion = null;
        for (Map<String, Object> f : found) {
            Object dv = f.get("detected_version");
            if (dv instanceof String s && s != null && !s.isBlank()) { smpVersion = s; break; }
        }

        String dbVersion = ctx.dbVersionBest;

        Map<String,Object> ev = new LinkedHashMap<>();
        ev.put("smp_files", found);
        ev.put("smp_version_best", smpVersion);
        ev.put("db_version_best", dbVersion);

        if (dbVersion == null && smpVersion == null) {
            out.addBlock(new RiskBlock("SMP vs DB version alignment", Rag.AMBER,
                    "Could not determine DB or SMP version from markers; confirm patch level manually.", ev));
            return;
        }
        if (dbVersion == null) {
            out.addBlock(new RiskBlock("SMP vs DB version alignment", Rag.AMBER,
                    "SMP version found (" + smpVersion + ") but DB version could not be determined; confirm patch level manually.", ev));
            return;
        }
        if (smpVersion == null) {
            out.addBlock(new RiskBlock("SMP vs DB version alignment", Rag.AMBER,
                    "DB version found (" + dbVersion + ") but SMP version marker not found; confirm SMP build matches DB.", ev));
            return;
        }

        boolean aligned = normalize(dbVersion).contains(normalize(smpVersion)) || normalize(smpVersion).contains(normalize(dbVersion));
        if (aligned) {
            out.addBlock(new RiskBlock("SMP vs DB version alignment", Rag.GREEN,
                    "SMP version (" + smpVersion + ") appears aligned with DB hints (" + dbVersion + ").", ev));
        } else {
            out.addBlock(new RiskBlock("SMP vs DB version alignment", Rag.RED,
                    "Potential mismatch: SMP version (" + smpVersion + ") differs from DB hints (" + dbVersion + "). Investigate patch/fixpack consistency.", ev));
        }
    }

    static String extractVersion(String text) {
        if (text == null) return null;
        Pattern p = Pattern.compile("(\d+\.\d+\.\d+\.\d+)");
        Matcher m = p.matcher(text);
        if (m.find()) return m.group(1);
        return null;
    }

    static String normalize(String s) { return s == null ? "" : s.trim().toLowerCase(Locale.ROOT); }
}
