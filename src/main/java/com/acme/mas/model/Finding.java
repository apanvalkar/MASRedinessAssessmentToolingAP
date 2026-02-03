package com.acme.mas.model;

import com.acme.mas.model.Enums.Severity;

public record Finding(Severity severity, String category, String message, Object details) {
    public static Finding ok(String c, String m) { return new Finding(Severity.OK, c, m, null); }
    public static Finding ok(String c, String m, Object d) { return new Finding(Severity.OK, c, m, d); }
    public static Finding warn(String c, String m) { return new Finding(Severity.WARN, c, m, null); }
    public static Finding warn(String c, String m, Object d) { return new Finding(Severity.WARN, c, m, d); }
    public static Finding err(String c, String m) { return new Finding(Severity.ERROR, c, m, null); }
    public static Finding err(String c, String m, Object d) { return new Finding(Severity.ERROR, c, m, d); }
}
