package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.DbUtil;

import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class DataVolumeCheck implements Check {
    @Override public String id() { return "data-volume"; }

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) {
        if (!ctx.includeDataVolume) {
            out.addBlock(new RiskBlock("Data volume signals", Rag.AMBER,
                    "Data volume checks are disabled (use --include-data-volume to enable).", Map.of()));
            return;
        }

        Connection conn = ctx.connection;
        if (conn == null) {
            out.addBlock(new RiskBlock("Data volume signals", Rag.AMBER,
                    "DB connection not available; data volume not measured.", Map.of()));
            return;
        }

        String[] tables = {"WORKORDER", "ASSET", "LOCATIONS", "PERSON", "LABTRANS", "MATUSETRANS"};
        Map<String, Object> counts = new LinkedHashMap<>();
        long max = 0;
        for (String t : tables) {
            long c = asLong(DbUtil.safeCount(conn, ctx.dialect, ctx.schema, t));
            counts.put(t, c);
            if (c > max) max = c;
        }

        Rag rag = (max >= 50_000_000L) ? Rag.RED : (max >= 5_000_000L ? Rag.AMBER : Rag.GREEN);
        String summary = "Largest table count signal=" + max + " rows (heuristic).";

        out.putCheck("data_volume_counts", counts);
        out.addBlock(new RiskBlock("Data volume signals", rag, summary, counts));
    }

    static long asLong(Object o) {
        if (o == null) return -1;
        if (o instanceof Number n) return n.longValue();
        try { return Long.parseLong(o.toString()); } catch (Exception ignored) { return -1; }
    }
}
