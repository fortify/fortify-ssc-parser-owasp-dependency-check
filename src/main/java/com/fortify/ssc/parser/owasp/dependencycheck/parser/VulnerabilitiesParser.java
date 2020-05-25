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
import com.fortify.ssc.parser.owasp.dependencycheck.domain.CVSSv3;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.Dependency;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.Vulnerability;
import com.fortify.util.ssc.parser.EngineTypeHelper;
import com.fortify.util.ssc.parser.ScanDataStreamingJsonParser;

public class VulnerabilitiesParser {
	private static final String ENGINE_TYPE = EngineTypeHelper.getEngineType();
	private final ScanData scanData;
	private final VulnerabilityHandler vulnerabilityHandler;

    public VulnerabilitiesParser(final ScanData scanData, final VulnerabilityHandler vulnerabilityHandler) {
    	this.scanData = scanData;
		this.vulnerabilityHandler = vulnerabilityHandler;
	}
    
    /**
	 * Main method to commence parsing the input provided by the configured {@link ScanData}.
	 * @throws ScanParsingException
	 * @throws IOException
	 */
	public final void parse() throws ScanParsingException, IOException {
		new ScanDataStreamingJsonParser()
			.handler("/dependencies/*", Dependency.class, this::handleDependency)
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
		StaticVulnerabilityBuilder vb = vulnerabilityHandler.startStaticVulnerability(getInstanceId(dependency, vulnerability));
		vb.setEngineType(ENGINE_TYPE);
		vb.setKingdom(FortifyKingdom.ENVIRONMENT.getKingdomName());
		vb.setAnalyzer(FortifyAnalyser.CONFIGURATION.getAnalyserName());
		vb.setCategory("Insecure Deployment");
		vb.setSubCategory("Unpatched Application");
		
		vb.setStringCustomAttributeValue(CustomVulnAttribute.fileName, dependency.getFileName());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.source, vulnerability.getSource());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.name, vulnerability.getName());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.cveUrl, "https://nvd.nist.gov/vuln/detail/"+vulnerability.getName());
		
		// Set mandatory values to JavaDoc-recommended values
		vb.setAccuracy(5.0f);
		vb.setConfidence(2.5f);
		vb.setLikelihood(2.5f);
		
		vb.setFileName(dependency.getFilePathOrName());
		vb.setVulnerabilityAbstract(vulnerability.getDescription());
		
		try {
			vb.setPriority(Priority.valueOf(StringUtils.capitalize(vulnerability.getSeverity().toLowerCase())));
		} catch ( NullPointerException | IllegalArgumentException e ) {
			vb.setPriority(Priority.Medium);
		}
		
		CVSSv3 cvssv3 = vulnerability.getCvssAsv3();
		if ( cvssv3!=null ) {
			vb.setImpact(cvssv3.getBaseScore()==null 
					? 2.5f // Default value if not defined in JSON
					: (cvssv3.getBaseScore()/10*5)); // CVVS3 score is 0-10, SSC impact is 0-5
			
			if ( StringUtils.equalsIgnoreCase("LOW", cvssv3.getAttackComplexity()) ) {
				vb.setProbability(0f);
			} else if ( StringUtils.equalsIgnoreCase("HIGH", cvssv3.getAttackComplexity()) ) {
				vb.setProbability(5.0f);
			} else {
				vb.setProbability(2.5f);
			}
			
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssVersion, vulnerability.getCvssVersion());
			vb.setDecimalCustomAttributeValue(CustomVulnAttribute.cvssBaseScore, cvssv3.getBaseScore()==null?null:new BigDecimal(cvssv3.getBaseScore().toString()));
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAttackVector, cvssv3.getAttackVector());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAttackComplexity, cvssv3.getAttackComplexity());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssConfidentialityImpact, cvssv3.getConfidentialityImpact());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssIntegrityImpact, cvssv3.getIntegrityImpact());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cvssAvailabilityImpact, cvssv3.getAvailabilityImpact());
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

	private final String getInstanceId(Dependency dependency, Vulnerability vulnerability) {
		return DigestUtils.sha256Hex(dependency.getSha256()+vulnerability.getName());
	}
}
