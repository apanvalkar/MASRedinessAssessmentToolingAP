package com.acme.mas.model;

import com.acme.mas.model.Enums.Rag;
import java.util.List;
import java.util.Map;

public record AssessmentResult(
        Rag overallRag,
        List<RiskBlock> blocks,
        List<Finding> findings,
        Map<String, Object> checks,
        Map<String, Object> evidence,
        Map<String, Object> derived
) {}
