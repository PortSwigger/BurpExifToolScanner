package burp;

import java.io.PrintWriter;

import net.logicaltrust.ExifToolEditorTabFactory;
import net.logicaltrust.ExifToolOptionsManager;
import net.logicaltrust.ExifToolProcess;
import net.logicaltrust.ExifToolScannerCheck;
import net.logicaltrust.ExtensionInitException;
import net.logicaltrust.SimpleLogger;
import net.logicaltrust.gui.ExifToolPanel;

public class BurpExtender implements IBurpExtender {

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		
		PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
		SimpleLogger logger = new SimpleLogger(new PrintWriter(callbacks.getStdout(), true), stderr);
		
		try {
			ExifToolProcess exiftoolProcess = new ExifToolProcess(callbacks.getHelpers(), logger);
			ExifToolScannerCheck scanner = new ExifToolScannerCheck(callbacks.getHelpers(), exiftoolProcess, logger);
			ExifToolEditorTabFactory tabFactory = new ExifToolEditorTabFactory(callbacks, exiftoolProcess, logger);
			ExifToolOptionsManager optionsManager = new ExifToolOptionsManager(callbacks, exiftoolProcess, scanner, tabFactory, logger);
			tabFactory.setOptionsManager(optionsManager);
			callbacks.addSuiteTab(new ExifToolPanel(optionsManager, logger));
			callbacks.registerExtensionStateListener(exiftoolProcess);
		} catch (ExtensionInitException e) {
			e.printStackTrace(stderr);
		}
	}

}
