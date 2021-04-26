package net.logicaltrust;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import burp.IResponseInfo;

public class ExifToolProcess implements IExtensionStateListener {
	
	private volatile Collection<String> typesToIgnore;
	private volatile Collection<String> linesToIgnore;
	private final Collection<String> ALWAYS_TO_IGNORE = Collections.unmodifiableCollection(Arrays.asList("Directory", "FileAccessDate", "FileInodeChangeDate", "FileModifyDate", "FileName", "FilePermissions"));
	
	private static final FileAttribute<Set<PosixFilePermission>> TEMP_FILE_PERMISSIONS = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"));
	private static final FileAttribute<Set<PosixFilePermission>> TEMP_DIR_PERMISSIONS = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));

	private final PrintWriter writer;
	private final BufferedReader reader;
	private final IExtensionHelpers helpers;
	private final Path tempDirectory;
	private final SimpleLogger logger;
	private Process process;

	public ExifToolProcess(IExtensionHelpers helpers, SimpleLogger stdout) throws ExtensionInitException {
		this.helpers = helpers;
		this.logger = stdout;
		
		try {
			if (isWindows()) {
				tempDirectory = Files.createTempDirectory("burpexiftool");
				setWindowsPermissions(tempDirectory);
			} else {
				tempDirectory = Files.createTempDirectory("burpexiftool", TEMP_DIR_PERMISSIONS);
			}
			stdout.debugForce("Temp directory " + tempDirectory + " created");
		} catch (IOException e) {
			throw new ExtensionInitException("Cannot create temporary directory", e);
		}
		
		try {
			process = runProcess();
			writer = new PrintWriter(process.getOutputStream());
			reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			stdout.debugForce("Process started");
		} catch (ExtensionInitException e) {
			deleteDir(tempDirectory.toFile());
			throw e;
		}
	}
	
	public void setTypesToIgnore(Collection<String> typesToIgnore) {
		this.typesToIgnore = typesToIgnore;
	}
	
	public void setLinesToIgnore(Collection<String> linesToIgnore) {
		this.linesToIgnore = linesToIgnore.stream().map(line -> line + ":").collect(Collectors.toSet());
	}
	
	public List<List<String>> readMetadataHtml(byte[] response, boolean reversePdf) throws IOException {
		return readMetadata(response, "-m\n-S\n-E\n-sort\n", false, reversePdf);
	}
	
	public List<List<String>> readMetadata(byte[] response, boolean displayFullResult, boolean reversePdf) throws IOException {
		return readMetadata(response, "-m\n-S\n-sort\n", displayFullResult, reversePdf);
	}
	
	public boolean canReadMetadata(byte[] response) {
		IResponseInfo responseInfo = helpers.analyzeResponse(response);
		if (isBodyEmpty(response, responseInfo)) {
			return false;
		}
		return isMimeTypeAppropriate(responseInfo);
	}

	private boolean isBodyEmpty(byte[] response, IResponseInfo responseInfo) {
		return responseInfo.getBodyOffset() == response.length;
	}
	
	private List<List<String>> readMetadata(byte[] response, String exifToolParams, boolean displayFullResult, boolean reversePdf) throws IOException {
		logger.debug("Reading metadata from response");
		IResponseInfo responseInfo = helpers.analyzeResponse(response);
		if (!isMimeTypeAppropriate(responseInfo)) {
			logger.debug("Inappropriate MIME Type: " + responseInfo.getStatedMimeType() + ", " + responseInfo.getInferredMimeType());
			return Collections.emptyList();
		}
		
		Path tmp = writeToTempFile(responseInfo, response);
		List<List<String>> result = new ArrayList<>();
		synchronized (this) {
			notifyExifTool(tmp, exifToolParams);
			result.add(readResult(displayFullResult));

			if (reversePdf && isResultPDF(result)) {
				notifyExifTool(tmp, "-PDF-update:all=\n");
				readResult(displayFullResult);
				notifyExifTool(tmp, exifToolParams);
				List<String> pdfResult = readResult(displayFullResult);
				if (!isResultPDFTheSame(result, pdfResult)) {
					result.add(pdfResult);
					logger.debug("Detected reversed PDF");
				} else {
					logger.debug("Reversed PDF not detected");
				}
			}
		}

		logger.debug("Deleting temp file " + tmp);
		Files.deleteIfExists(tmp);

		return result;
	}

	private boolean isResultPDF(List<List<String>> result) {
		return result.get(ExifToolResultEnum.NORMAL.getIndex()).contains("FileType: PDF");
	}

	private boolean isResultPDFTheSame(List<List<String>> result, List<String> reversePdf) {
		List<String> normal = result.get(ExifToolResultEnum.NORMAL.getIndex());
		return normal.equals(reversePdf);
	}
	
	private boolean isMimeTypeAppropriate(IResponseInfo responseInfo) {
		return !typesToIgnore.contains(responseInfo.getStatedMimeType()) && !typesToIgnore.contains(responseInfo.getInferredMimeType());
	}
	
	private Path createTempFile(String prefix, String suffix, FileAttribute<Set<PosixFilePermission>> permissions) throws IOException {
		Path tmp;
		if (isWindows()) {
			tmp = Files.createTempFile(tempDirectory, prefix, suffix);
			setWindowsPermissions(tmp);
		} else {
			 tmp = Files.createTempFile(tempDirectory, prefix, suffix, permissions);
		}
		return tmp;
	}
	
	private Path writeToTempFile(IResponseInfo responseInfo, byte[] response) throws IOException {
		logger.debug("Creating temp file");
		Path tmp = createTempFile("file", "", TEMP_FILE_PERMISSIONS);
		OutputStream tmpOs = Files.newOutputStream(tmp);
		tmpOs.write(response, responseInfo.getBodyOffset(), response.length - responseInfo.getBodyOffset());
		tmpOs.close();
		logger.debug("Temp file " + tmp + " created");
		return tmp;
	}
	
	private void notifyExifTool(Path tmp, String exifToolParams) {
		logger.debug("Notifying exiftool");
		writer.write(exifToolParams);
		writer.write(tmp.toString());
		writer.write("\n-execute\n");
		writer.flush();
		logger.debug("Exiftool notified");
	}
	
	private void exitExifTool() {
		logger.debugForce("Exit exiftool");
		writer.write("-stay_open\nFalse\n");
		writer.flush();
	}

	private List<String> readResult(boolean displayFullResult) throws IOException {
		logger.debug("Reading result from exiftool");
		List<String> result = new ArrayList<>();
		String line;
		while ((line = reader.readLine()) != null && logger.debug(line) && !("{ready}".equals(line) || "{ready-}".equals(line))) {
			if (notStartsWith(ALWAYS_TO_IGNORE, line) && (displayFullResult || notStartsWith(linesToIgnore, line))) {
				result.add(line);
			}
		}
		logger.debug(result.size() +  " elements read");
		return result;
	}

	private boolean notStartsWith(Collection<String> lines, String line) {
		return lines.stream().noneMatch((lineToIgnore) -> line.startsWith(lineToIgnore));
	}
	
	private boolean isWindows() {
		return System.getProperty("os.name").toLowerCase().contains("win");
	}
	
	private void setWindowsPermissions(Path path) {
		File file = path.toFile();
		file.setReadable(false, true);
		file.setWritable(true, true);
		file.setExecutable(false);
	}
	
	private Process runProcess() throws ExtensionInitException {
		try {
			Process process = new ProcessBuilder(prepareProcessParams("exiftool")).start();
			return process;
		} catch (IOException e) {
			logger.debugForce("'exiftool' not found in PATH.");
			try {
				Path extractedBinary = extractBinary();
				logger.debugForce("Extracting exiftool to " + extractedBinary);
				Process process = new ProcessBuilder(prepareProcessParams(extractedBinary.toString())).start();
				return process;
			} catch (IOException | InterruptedException e1) {
				throw new ExtensionInitException("Cannot run or extract embedded exiftool. Do you have 'exiftool' set in PATH?", e);
			} 
		}
	}
	
	private Path extractBinary() throws IOException, InterruptedException, ExtensionInitException  {
		if (isWindows()) {
			return extractResource("/exiftool.exe", ".exe");
		} else {
			Path archive = extractResource("/Image-ExifTool-12.25.tar.gz", ".tar.gz");
			Process process = new ProcessBuilder("tar", "xf", archive.toString(), "-C", tempDirectory.toString()).start();
			process.waitFor(30, TimeUnit.SECONDS);
			if (process.exitValue() != 0) {
				throw new ExtensionInitException("Failed to extract tar.gz archive");
			}
			return tempDirectory.resolve(Paths.get("Image-ExifTool-12.25", "exiftool"));
		}
	}

	private Path extractResource(String resource, String ext) throws IOException, FileNotFoundException {
		InputStream resourceAsStream = getClass().getResourceAsStream(resource);
		Path exifToolBinary = createTempFile("exiftool", ext, TEMP_FILE_PERMISSIONS);
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(exifToolBinary.toFile());
			byte[] buffer = new byte[32768];
			int read = 0;
			while ((read = resourceAsStream.read(buffer)) != -1) {
				fos.write(buffer, 0, read);
			}
			fos.flush();
		} finally {
			if (fos != null) {
				fos.close();
			}
		}
		
		return exifToolBinary;
	}
	
	private String[] prepareProcessParams(String executable) {
		return new String[] { executable, "-stay_open", "True", "-@", "-" };
	}

	private void deleteDir(File dir) {
		File[] files = dir.listFiles();
		if (files != null) {
			for (File f : files) {
				if (f.isDirectory()) {
					deleteDir(f);
				} else {
					deleteFile(f);
				}
			}
		}
		logger.debugForce("Deleting dir " + dir);
		deleteFile(dir);
	}
	
	private void deleteFile(File f) {
		boolean delete = f.delete();
		if (!delete) {
			logger.debugForce("Cannot delete " + f);
		}
	}
	
	@Override
	public void extensionUnloaded() {
		exitExifTool();
		try {
			process.waitFor(30, TimeUnit.SECONDS);
			logger.debugForce("Process ended with value " + process.exitValue());
			deleteDir(tempDirectory.toFile());
		} catch (InterruptedException e1) {
			e1.printStackTrace(logger.getStderr());
		}
	}
	
}
