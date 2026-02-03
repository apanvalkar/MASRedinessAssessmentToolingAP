package com.acme.mas.checks;

import com.acme.mas.model.Enums.Rag;
import com.acme.mas.util.ScoreUtil;

import java.util.Map;

public final class ComplexityHeatmapAndEstimatorCheck {

    private ComplexityHeatmapAndEstimatorCheck() {}

    public static Map<String, Object> estimateEffort(Map<String, Rag> heatmap) {
        Rag worst = Rag.GREEN;
        for (Rag r : heatmap.values()) worst = ScoreUtil.worst(worst, r);

        String tshirt;
        String indicative;
        if (worst == Rag.GREEN) { tshirt = "S"; indicative = "Typically 4–8 weeks (depends on target build & testing)."; }
        else if (worst == Rag.AMBER) { tshirt = "M"; indicative = "Typically 2–4 months (remediation + migration + testing)."; }
        else { tshirt = "L/XL"; indicative = "Typically 4–9+ months (significant refactor/integration/data work)."; }

        return Map.of(
                "tshirt_size", tshirt,
                "indicative_timeline", indicative,
                "note", "Heuristic only; validate via detailed discovery and IBM tooling outputs."
        );
    }
}
