package com.fortify.ssc.parser.owasp.dependencycheck.parser;

import java.io.IOException;
import java.math.BigDecimal;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import com.fortify.plugin.api.BasicVulnerabilityBuilder.Priority;
import com.fortify.plugin.api.FortifyAnalyser;
import com.fortify.plugin.api.FortifyKingdom;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.plugin.api.StaticVulnerabilityBuilder;
import com.fortify.plugin.api.VulnerabilityHandler;
import com.fortify.ssc.parser.owasp.dependencycheck.CustomVulnAttribute;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.CVSSv2;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.Dependency;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.Vulnerability;
import com.fortify.ssc.parser.owasp.dependencycheck.parser.util.Constants;
import com.fortify.util.json.handler.JsonArrayMapperHandler;
import com.fortify.util.ssc.parser.ScanDataStreamingJsonParser;

public class VulnerabilitiesParser {
	private final ScanData scanData;
	private final VulnerabilityHandler vulnerabilityHandler;

    public VulnerabilitiesParser(final ScanData scanData, final VulnerabilityHandler vulnerabilityHandler) {
    	this.scanData = scanData;
		this.vulnerabilityHandler = vulnerabilityHandler;
	}
    
    /**
	 * Main method to commence parsing the SARIF document provided by the
	 * configured {@link ScanData}.
	 * @throws ScanParsingException
	 * @throws IOException
	 */
	public final void parse() throws ScanParsingException, IOException {
		new ScanDataStreamingJsonParser()
			.handler("/dependencies", new JsonArrayMapperHandler<>(dependency->handleDependency(dependency), Dependency.class))
			.parse(scanData);
	}
	
    private final void handleDependency(Dependency dependency) {
		Vulnerability[] vulnerabilities = dependency.getVulnerabilities();
		if ( vulnerabilities!=null && vulnerabilities.length>0 ) {
			for ( Vulnerability vulnerability : vulnerabilities ) {
				buildVulnerability(dependency, vulnerability);
			}
		}
    }
    
    private final void buildVulnerability(Dependency dependency, Vulnerability vulnerability) {
    	String fileName = dependency.getFilePathOrName();
		String uniqueId = DigestUtils.sha256Hex(dependency.getSha256()+vulnerability.getName());
		StaticVulnerabilityBuilder vb = vulnerabilityHandler.startStaticVulnerability(uniqueId);
		vb.setEngineType(Constants.ENGINE_TYPE);
		vb.setKingdom(FortifyKingdom.ENVIRONMENT.getKingdomName());
		vb.setAnalyzer(FortifyAnalyser.CONFIGURATION.getAnalyserName());
		vb.setCategory("Insecure Deployment");
		vb.setSubCategory(vulnerability.getName());
		
		// Set mandatory values to JavaDoc-recommended values
		vb.setAccuracy(5.0f);
		vb.setConfidence(2.5f);
		vb.setLikelihood(2.5f);
		
		vb.setFileName(fileName);
		vb.setVulnerabilityAbstract(vulnerability.getDescription());
		
		try {
			vb.setPriority(Priority.valueOf(StringUtils.capitalize(vulnerability.getSeverity().toLowerCase())));
		} catch ( NullPointerException | IllegalArgumentException e ) {
			vb.setPriority(Priority.Medium);
		}
		
		CVSSv2 cvss = vulnerability.getCvssv2();
		if ( cvss!=null ) {
			vb.setImpact(cvss.getScore()==null 
					? 2.5f // Default value if not defined in JSON
					: (cvss.getScore()/10*5)); // CVVS2 score is 0-10, SSC impact is 0-5
			
			if ( StringUtils.equalsIgnoreCase("LOW", cvss.getAccessComplexity()) ) {
				vb.setProbability(0f);
			} else if ( StringUtils.equalsIgnoreCase("HIGH", cvss.getAccessComplexity()) ) {
				vb.setProbability(5.0f);
			} else {
				vb.setProbability(2.5f);
			}
			
			vb.setDecimalCustomAttributeValue(CustomVulnAttribute.cvssScore, cvss.getScore()==null?null:new BigDecimal(cvss.getScore().toString()));
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAccessVector, cvss.getAccessVector());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAccessComplexity, cvss.getAccessComplexity());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssConfidentialImpact, cvss.getConfidentialImpact());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssIntegrityImpact, cvss.getIntegrityImpact());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAvailabilityImpact, cvss.getAvailabilityImpact());
		}
		
		String[] cwes = vulnerability.getCwes();
		if ( cwes!=null && cwes.length>0 ) {
			// TODO Should this allow us to group by CWE in SSC? Doesn't currently work.
			vb.setMappedCategory(cwes[0].replace("CWE-", "CWE ID "));
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cwes, String.join(", ", cwes));
		}
		
		// TODO Add dependency description field?
		// TODO Add source field (NVD, OSSINDEX)
		// TODO Add references?
		
		vb.setStringCustomAttributeValue(CustomVulnAttribute.notes, vulnerability.getNotes());
		
		vb.completeVulnerability();
    }
}
