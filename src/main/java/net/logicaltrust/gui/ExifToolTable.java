package net.logicaltrust.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.function.Consumer;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;

public class ExifToolTable extends JPanel {

	private static final long serialVersionUID = 1L;
	private final ExifToolTableModel model;

	public ExifToolTable(String title, String tooltip, Collection<String> values, Collection<String> defaultValues, 
			Consumer<Collection<String>> updateValues, PrintWriter stderr) {
		
		this.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0)), title, TitledBorder.LEADING, TitledBorder.TOP, null, null));
		this.setToolTipText(tooltip);
		this.setLayout(new BorderLayout(0, 0));
		
		model = new ExifToolTableModel(values, stderr);
		
		JPanel buttonPanel = new JPanel();
		this.add(buttonPanel, BorderLayout.WEST);
		GridBagLayout buttonPanelLayout = new GridBagLayout();
		buttonPanelLayout.columnWidths = new int[] {50};
		buttonPanelLayout.rowHeights = new int[] {0, 0, 0, 25};
		buttonPanelLayout.columnWeights = new double[]{0.0};
		buttonPanelLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		buttonPanel.setLayout(buttonPanelLayout);
		
		JButton addButton = new JButton("Add");
		buttonPanel.add(addButton, createTableButtonConstraints(0));
		
		JButton deleteButton = new JButton("Delete");
		buttonPanel.add(deleteButton, createTableButtonConstraints(1));
		
		JButton defaultButton = new JButton("Default");
		buttonPanel.add(defaultButton, createTableButtonConstraints(2));
		defaultButton.addActionListener(e -> {
			model.replaceAll(defaultValues);
			model.fireTableDataChanged();
		}); 
		
		JButton undoButton = new JButton("Undo");
		buttonPanel.add(undoButton, createTableButtonConstraints(3));
		undoButton.setEnabled(false);
		undoButton.addActionListener(e -> model.undo());
		
		JTable table = new JTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		this.add(table, BorderLayout.CENTER);
		
		JScrollPane scroll = new JScrollPane(table);
		scroll.setVisible(true);
		this.add(scroll);
		
		model.addTableModelListener(e -> {
			undoButton.setEnabled(model.canUndo());
			Set<String> modelValues = getModelValues();
			updateValues.accept(modelValues);
		});
		
		table.setModel(model);
		
		deleteButton.addActionListener(e -> {
			int selectedRow = table.getSelectedRow();
			if (selectedRow != -1) {
				model.removeRow(selectedRow);
				model.fireTableDataChanged();
			}
		});
		
		addButton.addActionListener(e -> {
			String value = JOptionPane.showInputDialog("Insert value");
			if (value != null) {
				model.addRow(new Object[] { value });
				model.fireTableDataChanged();
			}
		});
		
		JButton loadFromFileButton = new JButton("Load...");
		buttonPanel.add(loadFromFileButton, createTableButtonConstraints(4));
		loadFromFileButton.addActionListener(e -> {
			JFileChooser fileChooser = new JFileChooser();
			int dialog = fileChooser.showOpenDialog(null);
			if (dialog == JFileChooser.APPROVE_OPTION) {
				File file = fileChooser.getSelectedFile();
				try {
					model.addRows(Files.lines(file.toPath()));
					model.fireTableDataChanged();
				} catch (IOException e1) {
					e1.printStackTrace(stderr);
				}
			}
		});
		
		JButton saveToFile = new JButton("Save...");
		buttonPanel.add(saveToFile, createTableButtonConstraints(5));
		saveToFile.addActionListener(e -> {
			JFileChooser fileChooser = new JFileChooser();
			int dialog = fileChooser.showSaveDialog(null);
			if (dialog == JFileChooser.APPROVE_OPTION) {
				File file = fileChooser.getSelectedFile();
				try {
					Files.write(file.toPath(), getModelValues());
				} catch (IOException e1) {
					e1.printStackTrace(stderr);
				}
			}
		});
		
	}

	private Set<String> getModelValues() {
		int c = model.getRowCount();
		Set<String> modelValues = new LinkedHashSet<>(c);
		for (int i = 0; i < c; i++) {
			modelValues.add((String) model.getValueAt(i, 0)); 
		}
		return modelValues;
	}
	
	private GridBagConstraints createTableButtonConstraints(int index) {
		GridBagConstraints btnConstraints = new GridBagConstraints();
		btnConstraints.fill = GridBagConstraints.HORIZONTAL;
		btnConstraints.anchor = GridBagConstraints.NORTH;
		btnConstraints.gridx = 0;
		btnConstraints.gridy = index;
		return btnConstraints;
	}

}
