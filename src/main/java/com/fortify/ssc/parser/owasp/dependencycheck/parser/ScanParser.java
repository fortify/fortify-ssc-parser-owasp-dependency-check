package com.fortify.ssc.parser.owasp.dependencycheck.parser;

import java.io.IOException;

import com.fortify.plugin.api.ScanBuilder;
import com.fortify.plugin.api.ScanData;
import com.fortify.plugin.api.ScanParsingException;
import com.fortify.util.jackson.IsoDateTimeConverter;
import com.fortify.util.ssc.parser.json.ScanDataStreamingJsonParser;

public class ScanParser {
	private final ScanData scanData;
    private final ScanBuilder scanBuilder;
    
	public ScanParser(final ScanData scanData, final ScanBuilder scanBuilder) {
		this.scanData = scanData;
		this.scanBuilder = scanBuilder;
	}
	
	public final void parse() throws ScanParsingException, IOException {
		new ScanDataStreamingJsonParser()
			.handler("/scanInfo/engineVersion", jp -> scanBuilder.setEngineVersion(jp.getValueAsString()))
			.handler("/projectInfo/reportDate", jp -> scanBuilder.setScanDate(IsoDateTimeConverter.getInstance().convert(jp.getValueAsString())))
			.handler("/projectInfo/name", jp -> scanBuilder.setBuildId(jp.getValueAsString()))
			.handler("/projectInfo/version", jp -> scanBuilder.setScanLabel(jp.getValueAsString()))
			.handler("/dependencies", jp -> scanBuilder.setNumFiles(jp.countArrayEntries()))
			.parse(scanData);
		scanBuilder.completeScan();
	}
}
