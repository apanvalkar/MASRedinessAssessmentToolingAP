# SpotBugs/FindBugs - MAS9 migration scan (template)
#
# Typical usage examples:
#   spotbugs -textui -effort:max -high -include tools/findbugs/mas9-migration-include.xml -exclude tools/findbugs/mas9-migration-exclude.xml -xml:withMessages -output spotbugs.xml <classesDirs>
#
# Tuning tips:
#   - Keep include focused on failure-prone patterns for container/JDK upgrades.
#   - Add project-specific excludes for third-party libs or generated sources.
#
