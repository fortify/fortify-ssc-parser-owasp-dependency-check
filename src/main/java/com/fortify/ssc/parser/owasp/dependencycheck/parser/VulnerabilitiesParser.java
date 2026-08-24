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
import com.fortify.plugin.spi.VulnerabilityAttribute;
import com.fortify.ssc.parser.owasp.dependencycheck.CustomVulnAttribute;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.CVSSv3;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.Dependency;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.DependencyPackage;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.PackageUrl;
import com.fortify.ssc.parser.owasp.dependencycheck.domain.Vulnerability;
import com.fortify.util.ssc.parser.EngineTypeHelper;
import com.fortify.util.ssc.parser.json.ScanDataStreamingJsonParser;

public class VulnerabilitiesParser {
	private static final String ENGINE_TYPE = EngineTypeHelper.getEngineType();
	private static final int MAX_LONG_TEXT_LENGTH = VulnerabilityAttribute.MAX_LONG_STRING_LENGTH;
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
		// externalId/externalUrl are the canonical CVE attributes read by the SSC Open Source view
		vb.setStringCustomAttributeValue(CustomVulnAttribute.externalId, vulnerability.getName());
		vb.setStringCustomAttributeValue(CustomVulnAttribute.externalUrl, "https://nvd.nist.gov/vuln/detail/"+vulnerability.getName());
		
		// Set mandatory values to JavaDoc-recommended values
		vb.setAccuracy(5.0f);
		vb.setConfidence(2.5f);
		vb.setLikelihood(2.5f);
		
		vb.setFileName(StringUtils.defaultIfBlank(dependency.getFileName(), dependency.getFilePathOrName()));
		vb.setVulnerabilityAbstract(StringUtils.abbreviate(vulnerability.getDescription(), MAX_LONG_TEXT_LENGTH));
		vb.setStringCustomAttributeValue(CustomVulnAttribute.description, StringUtils.abbreviate(vulnerability.getDescription(), MAX_LONG_TEXT_LENGTH));
		
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
			// Store CWE numbers only, as expected by the SSC Open Source view
			vb.setStringCustomAttributeValue(CustomVulnAttribute.cwes, String.join(", ", cwes).replace("CWE-", ""));
		}
		
		// TODO Add source field (NVD, OSSINDEX)
		// TODO Add references?
		
		setComponentAttributes(vb, dependency);
		
		vb.setStringCustomAttributeValue(CustomVulnAttribute.notes, StringUtils.abbreviate(vulnerability.getNotes(), MAX_LONG_TEXT_LENGTH));
		
		vb.completeVulnerability();
    }

	/**
	 * Populate the open-source component attributes read by the SSC Open Source page,
	 * derived from the dependency's Package URL together with its license and description.
	 */
	private final void setComponentAttributes(StaticVulnerabilityBuilder vb, Dependency dependency) {
		PackageUrl purl = getPackageUrl(dependency);
		if ( purl!=null ) {
			vb.setStringCustomAttributeValue(CustomVulnAttribute.componentPurl, purl.getCoordinates());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.componentPackageType, purl.getType());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.componentNamespace, purl.getNamespace());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.componentName, purl.getName());
			vb.setStringCustomAttributeValue(CustomVulnAttribute.componentVersion, purl.getVersion());
		}
		vb.setStringCustomAttributeValue(CustomVulnAttribute.componentLicenses, StringUtils.abbreviate(dependency.getLicense(), MAX_LONG_TEXT_LENGTH));
		// Stored for querying/future use; intentionally not referenced in the view template
		vb.setStringCustomAttributeValue(CustomVulnAttribute.componentDescription, StringUtils.abbreviate(dependency.getDescription(), MAX_LONG_TEXT_LENGTH));
	}

	private final PackageUrl getPackageUrl(Dependency dependency) {
		DependencyPackage[] packages = dependency.getPackages();
		if ( packages!=null ) {
			for ( DependencyPackage pkg : packages ) {
				PackageUrl purl = PackageUrl.parse(pkg.getId());
				if ( purl!=null ) { return purl; }
			}
		}
		return null;
	}

	private final String getInstanceId(Dependency dependency, Vulnerability vulnerability) {
		return DigestUtils.sha256Hex(dependency.getDependencyIdentifier()+vulnerability.getName());
	}
}
