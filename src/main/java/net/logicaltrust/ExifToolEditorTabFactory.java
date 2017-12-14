package net.logicaltrust;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorController;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;

public class ExifToolEditorTabFactory implements IMessageEditorTabFactory {

	private final IBurpExtenderCallbacks callbacks;
	private final ExifToolProcess exiftoolProcess;
	private final SimpleLogger logger;
	private ExifToolOptionsManager options;

	public ExifToolEditorTabFactory(IBurpExtenderCallbacks callbacks, ExifToolProcess exiftoolProcess, SimpleLogger logger) {
		this.callbacks = callbacks;
		this.exiftoolProcess = exiftoolProcess;
		this.logger = logger;
	}

	@Override
	public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
		logger.debug("Creating ExifToolEditorTab");
		return new ExifToolEditorTab(callbacks.createTextEditor(), exiftoolProcess, logger, options);
	}

	public void setOptionsManager(ExifToolOptionsManager options) {
		this.options = options;
	}

}
