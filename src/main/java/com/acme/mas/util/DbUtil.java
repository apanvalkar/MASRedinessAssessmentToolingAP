package com.acme.mas.util;

import com.acme.mas.model.Enums.DbType;

import java.sql.*;
import java.util.Locale;

public final class DbUtil {
    private DbUtil() {}

    public static DbType detectDbType(Connection conn) {
        try {
            String name = conn.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT);
            if (name.contains("oracle")) return DbType.ORACLE;
            if (name.contains("db2")) return DbType.DB2;
            if (name.contains("microsoft") || name.contains("sql server")) return DbType.SQLSERVER;
        } catch (SQLException ignored) {}
        return DbType.UNKNOWN;
    }

    public static void execQuery(Connection conn, String sql) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) { }
    }

    public static String scalarString(Connection conn, String sql) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            if (rs.next()) {
                Object v = rs.getObject(1);
                return v == null ? null : v.toString();
            }
            return null;
        }
    }

    public static Long scalarLong(Connection conn, String sql) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(sql)) {
            if (rs.next()) {
                Object v = rs.getObject(1);
                if (v == null) return null;
                if (v instanceof Number n) return n.longValue();
                try { return Long.parseLong(v.toString()); } catch (Exception ignored) { return null; }
            }
            return null;
        }
    }

    public static Long safeCount(Connection conn, Dialect dialect, String schema, String table) {
        try { return scalarLong(conn, dialect.countAll(qualify(schema, table))); }
        catch (Exception ignored) { return -1L; }
    }

    public static Long safeCountWhere(Connection conn, Dialect dialect, String schema, String table, String where) {
        try { return scalarLong(conn, dialect.countWhere(qualify(schema, table), where)); }
        catch (Exception ignored) { return -1L; }
    }

    public static String qualify(String schema, String table) {
        if (schema == null || schema.isBlank()) return table;
        return schema + "." + table;
    }
}
