package net.logicaltrust;

import java.net.URL;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IScanIssue;

public class ExifToolScanIssue implements IScanIssue {

	private final URL url;
	private final String issueDetail;
	private final IHttpRequestResponse[] httpMessages;
	private final IHttpService httpService;
	private final String issueName;
	private final String issueBackground;

	public ExifToolScanIssue(URL url, String issueDetail, IHttpRequestResponse[] httpMessages,
			IHttpService httpService, String issueName, String issueBackground) {
		this.url = url;
		this.issueDetail = issueDetail;
		this.httpMessages = httpMessages;
		this.httpService = httpService;
		this.issueName = issueName;
		this.issueBackground = issueBackground;
	}

	@Override
	public URL getUrl() {
		return url;
	}

	@Override
	public String getIssueName() {
		return issueName;
	}

	@Override
	public int getIssueType() {
		return 0x08000000;
	}

	@Override
	public String getSeverity() {
		return "Information";
	}

	@Override
	public String getConfidence() {
		return "Certain";
	}

	@Override
	public String getIssueBackground() {
		return issueBackground;
	}

	@Override
	public String getRemediationBackground() {
		return null;
	}

	@Override
	public String getIssueDetail() {
		return issueDetail;
	}

	@Override
	public String getRemediationDetail() {
		return null;
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return httpMessages;
	}

	@Override
	public IHttpService getHttpService() {
		return httpService;
	}

}
