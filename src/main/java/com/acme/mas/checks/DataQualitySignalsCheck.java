package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.DbUtil;

import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class DataQualitySignalsCheck implements Check {
    @Override public String id() { return "data-quality"; }

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) {
        Connection conn = ctx.connection;
        if (conn == null) {
            out.addBlock(new RiskBlock("Data quality signals", Rag.AMBER,
                    "DB connection not available; data quality signals not measured.", Map.of()));
            return;
        }

        Map<String,Object> ev = new LinkedHashMap<>();
        ev.put("workorder_missing_siteid", DbUtil.safeCountWhere(conn, ctx.dialect, ctx.schema, "WORKORDER", "SITEID IS NULL"));
        ev.put("asset_missing_siteid", DbUtil.safeCountWhere(conn, ctx.dialect, ctx.schema, "ASSET", "SITEID IS NULL"));
        ev.put("person_missing_personid", DbUtil.safeCountWhere(conn, ctx.dialect, ctx.schema, "PERSON", "PERSONID IS NULL"));

        long woNull = asLong(ev.get("workorder_missing_siteid"));
        long assetNull = asLong(ev.get("asset_missing_siteid"));

        Rag rag = Rag.GREEN;
        if ((woNull > 0 && woNull != -1) || (assetNull > 0 && assetNull != -1)) rag = Rag.AMBER;

        String summary = "Basic null/health signals collected (heuristic). Consider data remediation if counts are high.";
        out.putCheck("data_quality_signals", ev);
        out.addBlock(new RiskBlock("Data quality signals", rag, summary, ev));
    }

    static long asLong(Object o) {
        if (o == null) return -1;
        if (o instanceof Number n) return n.longValue();
        try { return Long.parseLong(o.toString()); } catch (Exception ignored) { return -1; }
    }
}
