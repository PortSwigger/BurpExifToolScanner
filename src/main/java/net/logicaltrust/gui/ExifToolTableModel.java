package net.logicaltrust.gui;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Vector;
import java.util.stream.Stream;

import javax.swing.table.DefaultTableModel;

public class ExifToolTableModel extends DefaultTableModel {

	private static final long serialVersionUID = 1L;
	
	private UndoAction lastAction = null;

	@SuppressWarnings("unused")
	private final PrintWriter stderr;
	
	public ExifToolTableModel(Collection<String> values, PrintWriter stderr) {
		super(values.stream().map(v -> new Object[] { v }).toArray(Object[][]::new), new String[] { "" });
		this.stderr = stderr;
	}
	
	@SuppressWarnings("unchecked")
	@Override
	public void removeRow(int row) {
		lastAction = new RemoveRowUndoAction((Vector<Object>) this.dataVector.get(row), row);
		super.removeRow(row);
	}
	
	@Override
	public void setValueAt(Object aValue, int row, int column) {
		lastAction = new ModifyCellUndoAction(this.getValueAt(row, column), row, column);
		super.setValueAt(aValue, row, column);
	}
	
	@Override
	public void addRow(Object[] rowData) {
		lastAction = new AddRowUndoAction(this.getRowCount());
		super.addRow(rowData);
	}
	
	void undo() {
		lastAction.undo(this);
	}
	
	@SuppressWarnings("rawtypes")
	void undoRemoveRow(Object value, int row) {
		lastAction = null;
		super.insertRow(row, (Vector) value);
		
	}
	
	void undoModifyCell(Object value, int row, int column) {
		lastAction = null;
		super.setValueAt(value, row, column);
	}
	
	void undoAddRow(int rows) {
		lastAction = null;
		super.removeRow(rows);
	}
	
	boolean canUndo() {
		return lastAction != null;
	}
	
	void replaceAll(Collection<String> defaultValues) {
		this.replaceAll(defaultValues, true);
	}

	private void replaceAll(Collection<?> defaultValues, boolean createUndo) {
		if (createUndo) {
			List<Object> oldValues = new ArrayList<>(this.getRowCount());
			for (int i = 0; i < this.getRowCount(); i++) {
				oldValues.add(this.getValueAt(i, 0));
			}
			lastAction = new ReplaceAllUndoAction(oldValues);
		}

		for (int i = this.getRowCount()-1; i >= 0; i--) {
			super.removeRow(i);
		}
		
		for (Object defValue : defaultValues) {
			super.addRow(new Object[] { defValue });
		}
	}
	
	void replaceAllUndo(Collection<?> values) {
		lastAction = null;
		this.replaceAll(values, false);
	}

	public void addRows(Stream<String> lines) {
		lastAction = new AddRowsUndoAction(getRowCount());
		lines.forEach(line -> super.addRow(new Object[] { line }));
	}

	public void removeRowsFrom(int lastRowIndex) {
		for (int i = getRowCount() - 1; i >= lastRowIndex; i--) {
			super.removeRow(i);
		}
	}
}
