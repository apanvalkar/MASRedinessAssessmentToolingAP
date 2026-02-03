/*
 * Copyright © 2026 Aniruddh Panvelkar
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * Original Author: Aniruddh Panvelkar
 * Project: MAS Readiness Assessment Tool
 */

package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.DbUtil;

import java.sql.Connection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class AutomationComplexityCheck implements Check {
    @Override public String id() { return "automation"; }

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) {
        Connection conn = ctx.connection;
        if (conn == null) {
            out.addBlock(new RiskBlock("Automation script footprint", Rag.AMBER,
                    "DB connection not available; automation footprint not measured.", Map.of()));
            return;
        }

        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("AUTOSCRIPT", DbUtil.safeCount(conn, ctx.dialect, ctx.schema, "AUTOSCRIPT"));
        counts.put("SCRIPTLAUNCHPOINT", DbUtil.safeCount(conn, ctx.dialect, ctx.schema, "SCRIPTLAUNCHPOINT"));
        counts.put("CRONTASKDEF", DbUtil.safeCount(conn, ctx.dialect, ctx.schema, "CRONTASKDEF"));

        long autoscript = asLong(counts.get("AUTOSCRIPT"));
        long launch = asLong(counts.get("SCRIPTLAUNCHPOINT"));
        long footprint = safeAdd(autoscript, launch);

        Rag rag = (footprint >= 50) ? Rag.RED : (footprint >= 10 ? Rag.AMBER : Rag.GREEN);
        String summary = "AUTOSCRIPT=" + autoscript + ", SCRIPTLAUNCHPOINT=" + launch + ", CRONTASKDEF=" + asLong(counts.get("CRONTASKDEF")) + ".";

        out.putCheck("automation_counts_db", counts);
        out.addBlock(new RiskBlock("Automation script footprint", rag, summary, counts));
    }

    static long asLong(Object o) {
        if (o == null) return -1;
        if (o instanceof Number n) return n.longValue();
        try { return Long.parseLong(o.toString()); } catch (Exception ignored) { return -1; }
    }

    static long safeAdd(long a, long b) {
        if (a < 0 && b < 0) return -1;
        if (a < 0) return b;
        if (b < 0) return a;
        return a + b;
    }
}
