# FindBugs / SpotBugs template for MAS9 migration

FindBugs is unmaintained; **SpotBugs** is the recommended successor and supports the same filter schema.

## What this template helps catch (migration-risk signals)
- Null-safety issues (NPE paths)
- Resource leaks (streams/JDBC resources) that hurt pod stability
- Concurrency hazards (races, inconsistent sync)
- Brittle classloading/reflection usage
- Serialization fragility
- Hard-coded absolute file names
- Weak crypto / hard-coded passwords
- Dynamic SQL passed to execute (injection risk)

## Recommended approach
1. Compile your custom Maximo code (or scan compiled class directories).
2. Run SpotBugs using the provided **include/exclude** filters.
3. Treat results as *signals* and validate against your MAS9 target runtime constraints.

## Example command (SpotBugs CLI)
```bash
spotbugs -textui -effort:max -high   -include tools/findbugs/mas9-migration-include.xml   -exclude tools/findbugs/mas9-migration-exclude.xml   -xml:withMessages -output spotbugs.xml   path/to/compiled/classes
```

## Maven profile snippet (optional)
Add this to your **customer customization** Maven project (not this readiness tool), then run:
`mvn -Pspotbugs-mas9 spotbugs:check`

```xml
<profiles>
  <profile>
    <id>spotbugs-mas9</id>
    <build>
      <plugins>
        <plugin>
          <groupId>com.github.spotbugs</groupId>
          <artifactId>spotbugs-maven-plugin</artifactId>
          <version>4.8.6.6</version>
          <configuration>
            <effort>Max</effort>
            <threshold>High</threshold>
            <includeFilterFile>${project.basedir}/tools/findbugs/mas9-migration-include.xml</includeFilterFile>
            <excludeFilterFile>${project.basedir}/tools/findbugs/mas9-migration-exclude.xml</excludeFilterFile>
            <xmlOutput>true</xmlOutput>
            <xmlOutputDirectory>${project.build.directory}</xmlOutputDirectory>
          </configuration>
          <executions>
            <execution>
              <phase>verify</phase>
              <goals>
                <goal>check</goal>
              </goals>
            </execution>
          </executions>
        </plugin>
      </plugins>
    </build>
  </profile>
</profiles>
```

## Notes specific to Maximo → MAS9
This static analysis does **not** fully detect:
- `javax.*` → `jakarta.*` migration impacts
- Removed modules (e.g., JAXB) depending on JDK/runtime packaging
- Application server / container configuration mismatches
- IBM Maximo/MAS API behavioural differences

Use this template as one lane in a larger migration readiness pipeline.
