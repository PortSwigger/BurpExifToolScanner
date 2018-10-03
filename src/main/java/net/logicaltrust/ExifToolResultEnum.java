package net.logicaltrust;

public enum ExifToolResultEnum {

	NORMAL(0),

	REVERSE_PDF(1);

	private final int index;

	ExifToolResultEnum(int index) {
		this.index = index;
	}

	public int getIndex() {
		return index;
	}
}
