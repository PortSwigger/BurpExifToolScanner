package net.logicaltrust;

import java.net.URL;
import java.util.ArrayList;
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
	private static final String REVERSE_ISSUE_BACKGROUND = "<i>Changes to PDF files by ExifTool are reversible (by deleting\n" +
			"the update with \"-PDF-update:all=\") because the original " +
			"information is never actually deleted from the file.  So ExifTool " +
			"alone may not be used to securely edit metadata in PDF files.</i><br><br>\nsource: man exiftool";

	private final IExtensionHelpers helpers;
	private final ExifToolProcess exiftoolProcess;
	private final SimpleLogger logger;
	private boolean reversePdf;

	public ExifToolScannerCheck(IExtensionHelpers helpers, ExifToolProcess exiftoolProcess, SimpleLogger logger) throws ExtensionInitException {
		this.helpers = helpers;
		this.exiftoolProcess = exiftoolProcess;
		this.logger = logger;
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		try {
			List<List<String>> result = exiftoolProcess.readMetadataHtml(baseRequestResponse.getResponse(), reversePdf);
			if (!result.isEmpty()) {
				List<String> metadata = result.get(ExifToolResultEnum.NORMAL.getIndex());
				List<IScanIssue> issues = extractMetadata("Metadata", metadata, baseRequestResponse, false);
				if (result.size() > 1) {
					List<String> metadataReversed = result.get(ExifToolResultEnum.REVERSE_PDF.getIndex());
					issues.addAll(extractMetadata("Metadata reversed", metadataReversed, baseRequestResponse, true));
				}
				return issues;
			} else {
				logger.debug("No data read from exiftool [IScannerCheck]");
			}
		} catch (Exception e) {
			e.printStackTrace(logger.getStderr());
		}
		
		return null;
	}

	private List<IScanIssue> extractMetadata(String title, List<String> metadata, IHttpRequestResponse baseRequestResponse, boolean withReversedPdf) {
		List<IScanIssue> issues = new ArrayList<>();
		if (!hasError(metadata)) {
			StringBuilder htmlList = new StringBuilder("<ul>");
			String filetype = fillHtmlList(metadata, htmlList);
			logger.debug("Metadata read from exiftool [IScannerCheck] ");
			issues.add(createIssues(title, baseRequestResponse, htmlList, filetype, withReversedPdf));
		} else {
			IRequestInfo request = helpers.analyzeRequest(baseRequestResponse);
			logger.debugForce("Cannot read metadata from " + request.getUrl() + ", " + metadata);
		}
		return issues;
	}
	
	private boolean hasError(List<String> metadata) {
		return metadata.stream().anyMatch(e -> e.startsWith("Error: "));
	}

	private IScanIssue createIssues(String title, IHttpRequestResponse baseRequestResponse, StringBuilder list,
										  String filetype, boolean withReversedPdf) {
		URL url = helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest()).getUrl();
		ExifToolScanIssue i = new ExifToolScanIssue(url, 
				list.toString(), 
				new IHttpRequestResponse[] { baseRequestResponse }, 
				baseRequestResponse.getHttpService(),
				title + filetype + " (ExifTool)", withReversedPdf ? REVERSE_ISSUE_BACKGROUND : null);
		return i;
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

	public void updateReversePdf(boolean reversePdf) {
		this.reversePdf = reversePdf;
	}

}
