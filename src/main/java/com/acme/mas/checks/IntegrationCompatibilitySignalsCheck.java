package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.DbUtil;

import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class IntegrationCompatibilitySignalsCheck implements Check {
    @Override public String id() { return "integration-signals"; }

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) {
        Connection conn = ctx.connection;
        if (conn == null) {
            out.addBlock(new RiskBlock("Integration compatibility signals", Rag.AMBER,
                    "DB connection not available; integration DB signals not measured.", Map.of()));
            return;
        }

        Map<String,Object> ev = new LinkedHashMap<>();
        ev.put("MAXENDPOINT_count", DbUtil.safeCount(conn, ctx.dialect, ctx.schema, "MAXENDPOINT"));
        ev.put("MAXIFACEINVOKE_count", DbUtil.safeCount(conn, ctx.dialect, ctx.schema, "MAXIFACEINVOKE"));
        ev.put("MAXINTERROR_count", DbUtil.safeCount(conn, ctx.dialect, ctx.schema, "MAXINTERROR"));

        long endpoints = asLong(ev.get("MAXENDPOINT_count"));
        Rag rag = (endpoints >= 200) ? Rag.RED : (endpoints >= 50 ? Rag.AMBER : Rag.GREEN);
        String summary = "Integration touchpoint signals (MAXENDPOINT=" + endpoints + " etc.). Review integrations during MAS migration.";

        out.putCheck("integration_db_signals", ev);
        out.addBlock(new RiskBlock("Integration compatibility signals", rag, summary, ev));
    }

    static long asLong(Object o) {
        if (o == null) return -1;
        if (o instanceof Number n) return n.longValue();
        try { return Long.parseLong(o.toString()); } catch (Exception ignored) { return -1; }
    }
}
