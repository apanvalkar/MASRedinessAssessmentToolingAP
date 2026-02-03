package com.acme.mas.checks;

import com.acme.mas.AssessmentContext;
import com.acme.mas.model.Enums.Rag;
import com.acme.mas.model.RiskBlock;
import com.acme.mas.util.FsUtil;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public final class SecurityPostureSignalsCheck implements Check {
    @Override public String id() { return "security-signals"; }

    @Override
    public void run(AssessmentContext ctx, AssessmentResultBuilder out) throws Exception {
        Map<String,Object> ev = new LinkedHashMap<>();
        Rag rag = Rag.GREEN;

        Path props = ctx.propertiesPath();
        if (props != null && Files.exists(props) && Files.isRegularFile(props)) {
            String txt = FsUtil.safeRead(props, 500_000);
            Map<String,String> p = FsUtil.parseProperties(txt);
            String ssl = p.getOrDefault("mxe.use.ssl", "");
            String smtp = p.getOrDefault("mxe.smtp.host", "");
            ev.put("mxe.use.ssl", ssl);
            ev.put("mxe.smtp.host_present", smtp != null && !smtp.isBlank());

            if (ssl.isBlank() || ssl.equalsIgnoreCase("0") || ssl.equalsIgnoreCase("false")) rag = Rag.AMBER;
        } else {
            ev.put("properties_file", ctx.propertiesFile);
            ev.put("note", "maximo.properties not provided; security signals are limited.");
            rag = Rag.AMBER;
        }

        String summary = "Security posture signals derived (heuristic, read-only).";
        out.putCheck("security_signals", ev);
        out.addBlock(new RiskBlock("Security posture signals", rag, summary, ev));
    }
}
