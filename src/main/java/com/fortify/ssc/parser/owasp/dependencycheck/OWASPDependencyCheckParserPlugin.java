package com.fortify.ssc.parser.owasp.dependencycheck;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.plugin.spi.ParserPlugin;
import com.fortify.ssc.parser.owasp.dependencycheck.parser.ScanParser;
import com.fortify.ssc.parser.owasp.dependencycheck.parser.VulnerabilitiesParser;

public class OWASPDependencyCheckParserPlugin implements ParserPlugin<CustomVulnAttribute> {
    private static final Logger LOG = LoggerFactory.getLogger(OWASPDependencyCheckParserPlugin.class);

    @Override
    public void start() throws Exception {
        LOG.info("OWASP dependency-check parser plugin is starting");
    }

    @Override
    public void stop() throws Exception {
        LOG.info("OWASP dependency-check parser plugin is stopping");
    }

    @Override
    public Class<CustomVulnAttribute> getVulnerabilityAttributesClass() {
        return CustomVulnAttribute.class;
    }

    @Override
    public void parseScan(final ScanData scanData, final ScanBuilder scanBuilder) throws ScanParsingException, IOException {
        new ScanParser(scanData, scanBuilder).parse();
    }

	@Override
	public void parseVulnerabilities(final ScanData scanData, final VulnerabilityHandler vulnerabilityHandler) throws ScanParsingException, IOException {
		new VulnerabilitiesParser(scanData, vulnerabilityHandler).parse();
	}
}
