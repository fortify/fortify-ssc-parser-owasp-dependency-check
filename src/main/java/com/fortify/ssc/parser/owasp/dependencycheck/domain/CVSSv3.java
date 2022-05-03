/*******************************************************************************
 * (c) Copyright 2020 Micro Focus or one of its affiliates
 *
 * Permission is hereby granted, free of charge, to any person obtaining a 
 * copy of this software and associated documentation files (the 
 * "Software"), to deal in the Software without restriction, including without 
 * limitation the rights to use, copy, modify, merge, publish, distribute, 
 * sublicense, and/or sell copies of the Software, and to permit persons to 
 * whom the Software is furnished to do so, subject to the following 
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY 
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE 
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF 
 * CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE.
 ******************************************************************************/
package com.fortify.ssc.parser.owasp.dependencycheck.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

import lombok.Getter;

@Getter
public final class CVSSv3 {
	@JsonProperty private Float baseScore;
	@JsonProperty private String attackVector;
	@JsonProperty private String attackComplexity;
	@JsonProperty private String confidentialityImpact;
	@JsonProperty private String integrityImpact;
	@JsonProperty private String availabilityImpact;
	
	// Available in JSON, but currently not used/shown by plugin
	//@JsonProperty private String privilegesRequired;
	//@JsonProperty private String userInteraction;
	//@JsonProperty private String scope;
	//@JsonProperty private String baseSeverity;
	
	public static final CVSSv3 fromCvssv2(CVSSv2 cvssv2) {
		CVSSv3 result = new CVSSv3();
		result.baseScore = cvssv2.getScore();
		result.attackVector = cvssv2.getAccessVector();
		result.attackComplexity = cvssv2.getAccessComplexity();
		result.confidentialityImpact = cvssv2.getConfidentialImpact();
		result.integrityImpact = cvssv2.getIntegrityImpact();
		result.availabilityImpact = cvssv2.getAvailabilityImpact();
		return result;
	}
}