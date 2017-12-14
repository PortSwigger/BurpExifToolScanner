package net.logicaltrust;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.stream.Collectors;

import burp.IBurpExtenderCallbacks;

public class ExifToolOptionsManager {

	private static final Collection<String> DEFAULT_MIME_TYPES_TO_IGNORE = Arrays.asList("HTML", "JSON", "script", "CSS", "XML");
	private static final Collection<String> DEFAULT_LINES_TO_IGNORE = Arrays.asList("ExifToolVersion", "FileSize");
	private static final String DELIMETER = "\n";
	
	private final String PASSIVE_SCAN = "PASSIVE_SCAN";
	private final String MESSAGE_EDITOR = "MESSAGE_EDITOR";
	private final String MIME_TYPES_TO_IGNORE = "MIME_TYPES_TO_IGNORE";
	private final String LINES_TO_IGNORE = "LINES_TO_IGNORE";
	private final String DEBUG_OUTPUT = "DEBUG_OUTPUT";
	private final String FULL_RESULT_IN_MESSAGE_EDITOR = "FULL_RESULT_IN_MESSAGE_EDITOR";
	
	private final IBurpExtenderCallbacks callbacks;
	private final ExifToolScannerCheck scanner;
	private final ExifToolEditorTabFactory tabFactory;
	private final ExifToolProcess exiftoolProcess;
	private final SimpleLogger stdout;
	
	private volatile boolean fullResultInMessageEditor;

	public ExifToolOptionsManager(IBurpExtenderCallbacks callbacks, ExifToolProcess exiftoolProcess,
			ExifToolScannerCheck scanner, ExifToolEditorTabFactory tabFactory, SimpleLogger stdout) {
		this.callbacks = callbacks;
		this.exiftoolProcess = exiftoolProcess;
		this.scanner = scanner;
		this.tabFactory = tabFactory;
		this.stdout = stdout;
		exiftoolProcess.setTypesToIgnore(getMimeTypesToIgnore());
		exiftoolProcess.setLinesToIgnore(getLinesToIgnore());
		fullResultInMessageEditor = loadSettingWithFallback(FULL_RESULT_IN_MESSAGE_EDITOR, false);
	}
	
	public boolean isPassiveScanOn() {
		return loadSettingWithFallback(PASSIVE_SCAN, true);
	}
	
	public boolean isMessageEditorOn() {
		return loadSettingWithFallback(MESSAGE_EDITOR, true); 
	}
	
	public boolean isDebugOn() {
		return loadSettingWithFallback(DEBUG_OUTPUT, false);
	}
	
	public boolean isFullResultInMessageEditor() {
		return fullResultInMessageEditor;
	}
	
	private boolean loadSettingWithFallback(String optionName, boolean fallback) {
		String setting = callbacks.loadExtensionSetting(optionName);
		return setting != null ? Boolean.parseBoolean(setting) : fallback;
	}
	
	private Collection<String> getIgnoreSettings(String settingName, Collection<String> fallback) {
		String settingsSerialized = callbacks.loadExtensionSetting(settingName);
		Collection<String> settings = settingsSerialized != null ? Arrays.stream(settingsSerialized.split(DELIMETER)).collect(Collectors.toCollection(LinkedHashSet::new)) : fallback;
		return settings;
	}
	
	public Collection<String> getMimeTypesToIgnore() {
		return getIgnoreSettings(MIME_TYPES_TO_IGNORE, DEFAULT_MIME_TYPES_TO_IGNORE);
	}
	
	public Collection<String> getLinesToIgnore() {
		return getIgnoreSettings(LINES_TO_IGNORE, DEFAULT_LINES_TO_IGNORE);
	}
	
	public Collection<String> getDefaultMimeTypesToIgnore() {
		return DEFAULT_MIME_TYPES_TO_IGNORE;
	}
	
	public Collection<String> getDefaultLinesToIgnore() {
		return DEFAULT_LINES_TO_IGNORE;
	}
	
	public void changePassiveScan(boolean on) {
		callbacks.saveExtensionSetting(PASSIVE_SCAN, Boolean.toString(on));
		if (on) { 
			callbacks.registerScannerCheck(scanner); 
		} else {
			callbacks.removeScannerCheck(scanner);
		}
	}
	
	public void changeMessageEditor(boolean on) {
		callbacks.saveExtensionSetting(MESSAGE_EDITOR, Boolean.toString(on));
		if (on) {
			callbacks.registerMessageEditorTabFactory(tabFactory);
		} else {
			callbacks.removeMessageEditorTabFactory(tabFactory);
		}
	}
	
	public void changeDebugOutput(boolean on) {
		callbacks.saveExtensionSetting(DEBUG_OUTPUT, Boolean.toString(on));
		if (on) {
			stdout.enableDebug();
		} else {
			stdout.disableDebug();
		}
	}
	
	public void changeFullResultInMessageEditor(boolean on) {
		callbacks.saveExtensionSetting(FULL_RESULT_IN_MESSAGE_EDITOR, Boolean.toString(on));
		fullResultInMessageEditor = on;
	}
	
	public void updateMimeTypesToIgnore(Collection<String> mimeTypes) {
		callbacks.saveExtensionSetting(MIME_TYPES_TO_IGNORE, String.join(DELIMETER, mimeTypes));
		exiftoolProcess.setTypesToIgnore(mimeTypes);
	}
	
	public void updateLinesToIgnore(Collection<String> lines) {
		callbacks.saveExtensionSetting(LINES_TO_IGNORE, String.join(DELIMETER, lines));
		exiftoolProcess.setLinesToIgnore(lines);
	}
	
}
