@ECHO OFF
SET BASE_DIR=%~dp0
SET JAVA_CMD=java
IF NOT "%JAVA_HOME%"=="" SET JAVA_CMD=%JAVA_HOME%\bin\java
"%JAVA_CMD%" -jar "%BASE_DIR%\.mvn\wrapper\maven-wrapper.jar" "%BASE_DIR%" %*
