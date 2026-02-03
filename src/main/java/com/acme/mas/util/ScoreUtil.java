package com.acme.mas.util;

import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.Enums.Severity;
import com.acme.mas.model.Finding;
import com.acme.mas.model.RiskBlock;

import java.util.List;

public final class ScoreUtil {
    private ScoreUtil() {}

    public static Rag worst(List<RiskBlock> blocks) {
        Rag worst = Rag.GREEN;
        for (RiskBlock b : blocks) {
            if (b.rag() == Rag.RED) return Rag.RED;
            if (b.rag() == Rag.AMBER) worst = Rag.AMBER;
        }
        return worst;
    }

    public static Rag ragFromFindings(List<Finding> findings) {
        boolean hasError = findings.stream().anyMatch(f -> f.severity() == Severity.ERROR);
        if (hasError) return Rag.RED;
        boolean hasWarn = findings.stream().anyMatch(f -> f.severity() == Severity.WARN);
        return hasWarn ? Rag.AMBER : Rag.GREEN;
    }

    public static Rag worst(Rag a, Rag b) {
        if (a == Rag.RED || b == Rag.RED) return Rag.RED;
        if (a == Rag.AMBER || b == Rag.AMBER) return Rag.AMBER;
        return Rag.GREEN;
    }
}
