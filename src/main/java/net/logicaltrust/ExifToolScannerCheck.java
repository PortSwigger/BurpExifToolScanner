package net.logicaltrust;

import java.net.URL;
import java.util.Arrays;
import java.util.List;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IScanIssue;
import burp.IScannerCheck;
import burp.IScannerInsertionPoint;

public class ExifToolScannerCheck implements IScannerCheck {

	private static final String FILETYPE_KEY = "FileType: ";

	private final IExtensionHelpers helpers;
	private final ExifToolProcess exiftoolProcess;
	private final SimpleLogger logger;

	public ExifToolScannerCheck(IExtensionHelpers helpers, ExifToolProcess exiftoolProcess, SimpleLogger logger) throws ExtensionInitException {
		this.helpers = helpers;
		this.exiftoolProcess = exiftoolProcess;
		this.logger = logger;
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		try {
			List<String> metadata = exiftoolProcess.readMetadataHtml(baseRequestResponse.getResponse());
			if (!metadata.isEmpty()) {
				if (!hasError(metadata)) {
					StringBuilder htmlList = new StringBuilder("<ul>");
					String filetype = fillHtmlList(metadata, htmlList);
					logger.debug("Metadata read from exiftool [IScannerCheck] ");
					return createIssues(baseRequestResponse, htmlList, filetype);
				} else {
					IRequestInfo request = helpers.analyzeRequest(baseRequestResponse);
					logger.debugForce("Cannot read metadata from " + request.getUrl() + ", " + metadata);
				}
			} else {
				logger.debug("No data read from exiftool [IScannerCheck]");
			}
		} catch (Exception e) {
			e.printStackTrace(logger.getStderr());
		}
		
		return null;
	}
	
	private boolean hasError(List<String> metadata) {
		return metadata.stream().anyMatch(e -> e.startsWith("Error: "));
	}

	private List<IScanIssue> createIssues(IHttpRequestResponse baseRequestResponse, StringBuilder list,
			String filetype) {
		URL url = helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest()).getUrl();
		ExifToolScanIssue i = new ExifToolScanIssue(url, 
				list.toString(), 
				new IHttpRequestResponse[] { baseRequestResponse }, 
				baseRequestResponse.getHttpService(),
				"Metadata" + filetype + " (ExifTool)");
		return Arrays.asList(i);
	}
	
	private String fillHtmlList(List<String> metadata, StringBuilder sb) {
		String filetype = "";
		for (String line : metadata) {
			sb.append("<li>").append(line).append("</li>");
			if (line.startsWith(FILETYPE_KEY)) {
				filetype = " in " + line.substring(FILETYPE_KEY.length());
			}
		}
		sb.append("</ul>");
		return filetype;
	}
	
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return existingIssue.getIssueDetail().equals(newIssue.getIssueDetail()) ? -1 : 0;
	}

}
