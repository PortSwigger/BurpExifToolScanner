package net.logicaltrust.gui;

public class AddRowsUndoAction implements UndoAction {

	private final int lastRowIndex;
	
	public AddRowsUndoAction(int lastRowIndex) {
		this.lastRowIndex = lastRowIndex;
	}

	@Override
	public void undo(ExifToolTableModel exifToolTableModel) {
		exifToolTableModel.removeRowsFrom(lastRowIndex);
	}

}
