package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;

public interface Check {
    String id();
    void run(AssessmentContext ctx, AssessmentResultBuilder out) throws Exception;
}
