package com.acme.mas.util;

import com.acme.mas.model.Enums.DbType;

public final class Dialect {
    private final DbType dbType;
    public Dialect(DbType dbType) { this.dbType = dbType; }

    public String selectOneFromTable(String tableQ) {
        return switch (dbType) {
            case SQLSERVER -> "SELECT TOP 1 1 AS one FROM " + tableQ;
            case DB2      -> "SELECT 1 AS one FROM " + tableQ + " FETCH FIRST 1 ROWS ONLY";
            case ORACLE   -> "SELECT 1 AS one FROM " + tableQ + " WHERE ROWNUM = 1";
            default       -> "SELECT 1 AS one FROM " + tableQ;
        };
    }

    public String countAll(String tableQ) { return "SELECT COUNT(*) FROM " + tableQ; }
    public String countWhere(String tableQ, String where) { return "SELECT COUNT(*) FROM " + tableQ + " WHERE " + where; }
}
