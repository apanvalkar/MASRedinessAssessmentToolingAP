#!/usr/bin/env sh
# Minimal Maven Wrapper (self-contained)
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
JAVA_CMD="${JAVA_HOME:+$JAVA_HOME/bin/}java"
if [ ! -x "$JAVA_CMD" ]; then
  JAVA_CMD="java"
fi
exec "$JAVA_CMD" -jar "$BASE_DIR/.mvn/wrapper/maven-wrapper.jar" "$BASE_DIR" "$@"
