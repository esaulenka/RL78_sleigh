package ghidra.rl78.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class RL78InstructionAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RL78 Instruction Analyzer";
	private static final String DESCRIPTION = "Fixes unnecessary error bookmarks during disassembly";

	public RL78InstructionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("RL78");
	}

	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		BookmarkManager bman = program.getBookmarkManager();
		bman.removeBookmarks(set, BookmarkType.ERROR, monitor);
		return true;
	}

	public boolean getDefaultEnablement(Program program) {
		return true;
	}

}
