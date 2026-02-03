package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.DbUtil;

import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class LicensingHintsCheck implements Check {
    @Override public String id() { return "licensing-hints"; }

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) {
        Connection conn = ctx.connection;
        if (conn == null) {
            out.addBlock(new RiskBlock("Licensing & entitlement hints", Rag.AMBER,
                    "DB connection not available; licensing hints not derived.", Map.of()));
            return;
        }

        Map<String,Object> ev = new LinkedHashMap<>();
        long totalUsers = asLong(DbUtil.safeCount(conn, ctx.dialect, ctx.schema, "MAXUSER"));
        long activeUsers = asLong(DbUtil.safeCountWhere(conn, ctx.dialect, ctx.schema, "MAXUSER", "UPPER(STATUS)='ACTIVE'"));

        ev.put("maxuser_total", totalUsers);
        ev.put("maxuser_active_best_effort", activeUsers);

        Rag rag = (totalUsers >= 5000) ? Rag.AMBER : Rag.GREEN;
        String summary = "User inventory signal: total MAXUSER=" + totalUsers + ", active(best-effort)=" + activeUsers + ".";

        out.putCheck("licensing_hints", ev);
        out.addBlock(new RiskBlock("Licensing & entitlement hints", rag, summary, ev));
    }

    static long asLong(Object o) {
        if (o == null) return -1;
        if (o instanceof Number n) return n.longValue();
        try { return Long.parseLong(o.toString()); } catch (Exception ignored) { return -1; }
    }
}
