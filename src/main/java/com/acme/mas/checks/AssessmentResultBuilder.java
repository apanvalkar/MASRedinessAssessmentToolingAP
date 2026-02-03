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

import com.acme.mas.model.AssessmentResult;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.Finding;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.ScoreUtil;

import java.util.*;

public final class AssessmentResultBuilder {
    private final Map<String, Object> checks = new LinkedHashMap<>();
    private final Map<String, Object> evidence = new LinkedHashMap<>();
    private final Map<String, Object> derived = new LinkedHashMap<>();
    private final List<RiskBlock> blocks = new ArrayList<>();
    private final List<Finding> findings = new ArrayList<>();

    public void putCheck(String key, Object val) { checks.put(key, val); }
    public void putEvidence(String key, Object val) { evidence.put(key, val); }
    public void putDerived(String key, Object val) { derived.put(key, val); }

    public void addBlock(RiskBlock b) { if (b != null) blocks.add(b); }
    public void addFinding(Finding f) { if (f != null) findings.add(f); }

    public AssessmentResult build() {
        Rag overall = ScoreUtil.worst(blocks);
        Rag fromFindings = ScoreUtil.ragFromFindings(findings);
        overall = ScoreUtil.worst(overall, fromFindings);
        return new AssessmentResult(overall, List.copyOf(blocks), List.copyOf(findings),
                Map.copyOf(checks), Map.copyOf(evidence), Map.copyOf(derived));
    }
}
