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

import org.apache.commons.lang3.StringUtils;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * Minimal parser for Package URL (purl) strings as found in the
 * <code>packages[].id</code> field of an OWASP dependency-check report, for
 * example <code>pkg:maven/javax.activation/activation@1.1.1</code>. The purl
 * components are used to populate the open-source component attributes shown on
 * the SSC Open Source page.
 * <p>
 * Only the components required by this plugin are exposed. Non-purl identifiers
 * (for example CPE strings) result in a <code>null</code> return value from
 * {@link #parse(String)}.
 */
@Getter
@RequiredArgsConstructor
public final class PackageUrl {
	private static final String PURL_PREFIX = "pkg:";

	private final String type;
	private final String namespace;
	private final String name;
	private final String version;

	/**
	 * Parse the given Package URL string, returning a {@link PackageUrl} instance
	 * or <code>null</code> if the input is blank, not a purl, or does not contain
	 * at least a type and name.
	 */
	public static final PackageUrl parse(String purl) {
		if ( StringUtils.isBlank(purl) || !purl.startsWith(PURL_PREFIX) ) {
			return null;
		}
		String remainder = StringUtils.stripStart(purl.substring(PURL_PREFIX.length()), "/");

		// Strip subpath (#...) and qualifiers (?...)
		remainder = StringUtils.substringBefore(remainder, "#");
		remainder = StringUtils.substringBefore(remainder, "?");

		// Split off version (@...); substringBeforeLast returns the input unchanged when no '@' is present
		String version = StringUtils.trimToNull(StringUtils.substringAfterLast(remainder, "@"));
		remainder = StringUtils.substringBeforeLast(remainder, "@");

		// Remaining is type/namespace.../name
		int firstSlash = remainder.indexOf('/');
		if ( firstSlash<0 ) { return null; }
		String type = remainder.substring(0, firstSlash);
		String path = remainder.substring(firstSlash+1);
		int lastSlash = path.lastIndexOf('/');
		String namespace = lastSlash<0 ? null : StringUtils.trimToNull(path.substring(0, lastSlash));
		String name = lastSlash<0 ? path : path.substring(lastSlash+1);

		if ( StringUtils.isBlank(type) || StringUtils.isBlank(name) ) { return null; }
		return new PackageUrl(type, namespace, name, version);
	}

	/**
	 * Return the canonical Package URL in the form
	 * <code>pkg:type/namespace/name@version</code> expected by the SSC Open Source
	 * view, consistent with the individual component attributes.
	 */
	public final String getCoordinates() {
		StringBuilder sb = new StringBuilder(PURL_PREFIX).append(type).append('/');
		if ( StringUtils.isNotBlank(namespace) ) { sb.append(namespace).append('/'); }
		sb.append(name);
		if ( StringUtils.isNotBlank(version) ) { sb.append('@').append(version); }
		return sb.toString();
	}
}
