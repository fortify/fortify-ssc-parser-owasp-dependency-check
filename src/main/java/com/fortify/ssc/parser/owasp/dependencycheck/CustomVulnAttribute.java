package com.fortify.ssc.parser.owasp.dependencycheck;

/**
 * (c) Copyright [2017] Micro Focus or one of its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

public enum CustomVulnAttribute implements com.fortify.plugin.spi.VulnerabilityAttribute {
	fileName(AttrType.STRING),
	source(AttrType.STRING),
	description(AttrType.LONG_STRING),
	notes(AttrType.LONG_STRING),
	cvssVersion(AttrType.STRING),
	cvssBaseScore(AttrType.DECIMAL),
	cvssAttackVector(AttrType.STRING),
	cvssAttackComplexity(AttrType.STRING),
	cvssConfidentialityImpact(AttrType.STRING),
	cvssIntegrityImpact(AttrType.STRING),
	cvssAvailabilityImpact(AttrType.STRING),
	cwes(AttrType.STRING),
	// Open-source issue attributes recognized by the SSC Open Source view
	externalId(AttrType.STRING),
	externalUrl(AttrType.STRING),
	componentPurl(AttrType.STRING),
	// Component / open-source package attributes (parsed from Package URL)
	componentPackageType(AttrType.STRING),
	componentNamespace(AttrType.STRING),
	componentName(AttrType.STRING),
	componentVersion(AttrType.STRING),
	componentLicenses(AttrType.LONG_STRING),
	// Stored for querying/future use; intentionally not referenced in the view template
	componentDescription(AttrType.LONG_STRING),
    ;

    private final AttrType attributeType;

    CustomVulnAttribute(final AttrType attributeType) {
        this.attributeType = attributeType;
    }

    @Override
    public String attributeName() {
        return name();
    }

    @Override
    public AttrType attributeType() {
        return attributeType;
    }
}
