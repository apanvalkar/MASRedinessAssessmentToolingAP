package com.acme.mas.util;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

public final class FsUtil {
    private FsUtil() {}

    public static Map<String, Object> fileStat(String path) {
        Map<String, Object> o = new LinkedHashMap<>();
        o.put("path", path);
        if (path == null) {
            o.put("exists", false);
            o.put("reason", "not provided");
            return o;
        }
        Path p = Paths.get(path);
        o.put("exists", Files.exists(p));
        o.put("is_dir", Files.isDirectory(p));
        o.put("is_file", Files.isRegularFile(p));
        try { if (Files.isRegularFile(p)) o.put("size_bytes", Files.size(p)); } catch (IOException ignored) {}
        return o;
    }

    public static String safeRead(Path p, int maxBytes) {
        try {
            byte[] b = Files.readAllBytes(p);
            if (b.length > maxBytes) b = Arrays.copyOf(b, maxBytes);
            return new String(b, StandardCharsets.UTF_8);
        } catch (IOException e) { return ""; }
    }

    public static Map<String, String> parseProperties(String text) {
        Map<String, String> props = new HashMap<>();
        if (text == null) return props;
        for (String line : text.split("\r")) {
            String ln = line.trim();
            if (ln.isEmpty() || ln.startsWith("#") || !ln.contains("=")) continue;
            int idx = ln.indexOf('=');
            props.put(ln.substring(0, idx).trim(), ln.substring(idx + 1).trim());
        }
        return props;
    }

    public static long countFilesByExt(Path dir, Set<String> exts, int sampleLimit, List<String> sampleOut) throws IOException {
        if (dir == null || !Files.exists(dir) || !Files.isDirectory(dir)) return 0;
        long count = 0;
        try (var stream = Files.walk(dir)) {
            for (Path p : (Iterable<Path>) stream::iterator) {
                if (!Files.isRegularFile(p)) continue;
                String fn = p.getFileName().toString().toLowerCase(Locale.ROOT);
                for (String ext : exts) {
                    if (fn.endsWith(ext)) {
                        count++;
                        if (sampleOut != null && sampleOut.size() < sampleLimit) sampleOut.add(dir.relativize(p).toString());
                        break;
                    }
                }
            }
        }
        return count;
    }

    public static long countFilesByPrefix(Path dir, String prefix, int sampleLimit, List<String> sampleOut) throws IOException {
        if (dir == null || !Files.exists(dir) || !Files.isDirectory(dir)) return 0;
        long count = 0;
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
            for (Path p : ds) {
                if (!Files.isRegularFile(p)) continue;
                String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
                if (name.startsWith(prefix.toLowerCase(Locale.ROOT))) {
                    count++;
                    if (sampleOut != null && sampleOut.size() < sampleLimit) sampleOut.add(name);
                }
            }
        }
        return count;
    }

    public static boolean dirExists(Path p) { return p != null && Files.exists(p) && Files.isDirectory(p); }
}
