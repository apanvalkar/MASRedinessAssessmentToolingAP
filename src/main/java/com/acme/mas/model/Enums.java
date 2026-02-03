package com.acme.mas.model;

public final class Enums {
    private Enums() {}
    public enum Rag { GREEN, AMBER, RED }
    public enum Severity { OK, WARN, ERROR }
    public enum DbType { AUTO, ORACLE, DB2, SQLSERVER, UNKNOWN }
}
