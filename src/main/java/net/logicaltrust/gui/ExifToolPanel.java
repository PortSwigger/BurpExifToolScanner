package net.logicaltrust.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

import burp.ITab;
import net.logicaltrust.ExifToolOptionsManager;
import net.logicaltrust.SimpleLogger;

public class ExifToolPanel extends JPanel implements ITab {

	private static final long serialVersionUID = 1L;
	private final SimpleLogger stderr;

	public ExifToolPanel(ExifToolOptionsManager optionsManager, SimpleLogger logger) {
		this.stderr = logger;
		setLayout(new BorderLayout(0, 0));
		
		JPanel githubPanel = new JPanel();
		githubPanel.setBorder(new EmptyBorder(5, 5, 5, 5));
		add(githubPanel, BorderLayout.SOUTH);
		githubPanel.setLayout(new BorderLayout(0, 0));
		
		JLabel githubLabel = createLabelURL("https://github.com/LogicalTrust/BurpExifToolScanner");
		githubPanel.add(githubLabel);
		
		JPanel checkboxPanel = new JPanel();
		add(checkboxPanel, BorderLayout.NORTH);
		checkboxPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 5, 5));
		
		JCheckBox chckbxDebug = new JCheckBox("Debug output");
		chckbxDebug.addActionListener(e -> optionsManager.changeDebugOutput(chckbxDebug.isSelected()));
		chckbxDebug.setSelected(optionsManager.isDebugOn());
		optionsManager.changeDebugOutput(optionsManager.isDebugOn());
		
		JCheckBox chckbxPassiveScan = new JCheckBox("Passive Scan");
		chckbxPassiveScan.addActionListener(e -> optionsManager.changePassiveScan(chckbxPassiveScan.isSelected()));
		if (optionsManager.isPassiveScanOn()) {
			chckbxPassiveScan.doClick();
		}
	
		JCheckBox chckbxMessageEditor = new JCheckBox("Message Editor");
		chckbxMessageEditor.addActionListener(e -> optionsManager.changeMessageEditor(chckbxMessageEditor.isSelected()));
		if (optionsManager.isMessageEditorOn()) {
			chckbxMessageEditor.doClick();
		}
		
		JCheckBox chckbxFullResultInMessageEditor = new JCheckBox("Full result in Message Editor");
		chckbxFullResultInMessageEditor.addActionListener(e -> optionsManager.changeFullResultInMessageEditor(chckbxFullResultInMessageEditor.isSelected()));
		chckbxFullResultInMessageEditor.setSelected(optionsManager.isFullResultInMessageEditor());

		JCheckBox chckbxReversePdf = new JCheckBox("Reverse PDF metadata (-PDF-update:all=)");
		chckbxReversePdf.addActionListener(e -> optionsManager.changeReversePdf(chckbxReversePdf.isSelected()));
		if (optionsManager.isReversePdf()) {
			chckbxReversePdf.doClick();
		}

		checkboxPanel.add(chckbxPassiveScan);
		checkboxPanel.add(chckbxMessageEditor);
		checkboxPanel.add(chckbxFullResultInMessageEditor);
		checkboxPanel.add(chckbxDebug);
		checkboxPanel.add(chckbxReversePdf);
		
		JPanel tablesPanel = new JPanel();
		add(tablesPanel, BorderLayout.CENTER);
		tablesPanel.setLayout(new GridLayout(0, 2, 0, 0));
		
		JPanel mimeTable = new ExifToolTable("Ignore MIME Types", "Do not scan specified MIME Types. The possible values are the same as those used in the main Burp UI",
				optionsManager.getMimeTypesToIgnore(), 
				optionsManager.getDefaultMimeTypesToIgnore(), 
				optionsManager::updateMimeTypesToIgnore,
				logger.getStderr());
		tablesPanel.add(mimeTable);
		
		JPanel fieldsTable = new ExifToolTable("Ignore result lines", "Do not print lines with specified tags.",
				optionsManager.getLinesToIgnore(), 
				optionsManager.getDefaultLinesToIgnore(), 
				optionsManager::updateLinesToIgnore,
				logger.getStderr());
		tablesPanel.add(fieldsTable);
	}
	
	private JLabel createLabelURL(String url) {
		JLabel lblUrl = new JLabel(url);
		lblUrl.setForeground(Color.BLUE);
		lblUrl.setCursor(new Cursor(Cursor.HAND_CURSOR));
		lblUrl.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				try {
					Desktop.getDesktop().browse(new URI(lblUrl.getText()));
				} catch (URISyntaxException | IOException ex) {
					ex.printStackTrace(stderr.getStderr());
				}
			}
		});
		return lblUrl;
	}
	
	@Override
	public String getTabCaption() {
		return "ExifTool";
	}

	@Override
	public Component getUiComponent() {
		return this;
	}
	
}
