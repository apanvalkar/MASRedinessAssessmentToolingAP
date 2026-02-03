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

public interface Check {
    String id();
    void run(AssessmentContext ctx, AssessmentResultBuilder out) throws Exception;
}
