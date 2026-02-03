package com.acme.mas;

import com.acme.mas.model.Enums.DbType;
import com.acme.mas.util.Dialect;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;

public final class AssessmentContext {
    public final String jdbcUrlRedacted;
    public final String user;
    public final DbType requestedDbType;
    public final DbType expectedDbType;
    public final String schema;
    public final String smpDir;
    public final String propertiesFile;
    public final boolean includeDataVolume;

    public Connection connection; // set when DB is connected
    public DbType effectiveDbType = DbType.UNKNOWN;
    public Dialect dialect = new Dialect(DbType.SQLSERVER);

    public String dbVersionBest;

    public AssessmentContext(String jdbcUrlRedacted, String user, DbType requestedDbType, DbType expectedDbType,
                             String schema, String smpDir, String propertiesFile, boolean includeDataVolume) {
        this.jdbcUrlRedacted = jdbcUrlRedacted;
        this.user = user;
        this.requestedDbType = requestedDbType;
        this.expectedDbType = expectedDbType;
        this.schema = schema;
        this.smpDir = smpDir;
        this.propertiesFile = propertiesFile;
        this.includeDataVolume = includeDataVolume;
    }

    public Path smpPath() {
        if (smpDir == null || smpDir.isBlank()) return null;
        return Paths.get(smpDir);
    }

    public Path propertiesPath() {
        if (propertiesFile == null || propertiesFile.isBlank()) return null;
        return Paths.get(propertiesFile);
    }
}
