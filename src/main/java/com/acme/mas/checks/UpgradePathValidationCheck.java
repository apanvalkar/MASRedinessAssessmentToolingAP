package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.RiskBlock;

import java.util.Map;

public final class UpgradePathValidationCheck implements Check {
    @Override public String id() { return "upgrade-path"; }

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) {
        String v = ctx.dbVersionBest;
        Rag rag = Rag.AMBER;
        String summary = "Could not confirm Maximo source version; validate fix pack / patch level.";

        if (v != null) {
            if (v.contains("7.6.1.3") || v.contains("7.6.1.2") || v.contains("7.6.0.10")) {
                rag = Rag.GREEN;
                summary = "DB version hints indicate a commonly supported starting point (" + v + ").";
            } else {
                rag = Rag.AMBER;
                summary = "DB version hints found (" + v + "), but starting point must be confirmed against IBM supported upgrade sources.";
            }
        }

        out.addBlock(new RiskBlock("Upgrade path validation", rag, summary, Map.of("db_version_best", v)));
    }
}
