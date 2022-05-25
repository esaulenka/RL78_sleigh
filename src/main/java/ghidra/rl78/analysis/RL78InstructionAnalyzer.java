package ghidra.rl78.analysis;

import java.math.BigInteger;
import java.util.ArrayList;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.util.Msg;
import ghidra.util.bytesearch.DittedBitSequence;
import ghidra.util.bytesearch.Match;
import ghidra.util.bytesearch.MatchAction;
import ghidra.util.bytesearch.MemoryBytePatternSearcher;
import ghidra.util.bytesearch.Pattern;
import ghidra.util.bytesearch.PostRule;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlPullParser;

public class RL78InstructionAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "RL78 Instruction Analyzer";
	private static final String DESCRIPTION = "Sets context for all possible SKIP instructions";
	private static final DittedBitSequence SKIP_SEQ1 = new DittedBitSequence("0x61 11..1000");
	private static final DittedBitSequence SKIP_SEQ2 = new DittedBitSequence("0x61 111.0011");

	public RL78InstructionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("RL78");
	}

	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		SkipAction action = new SkipAction(program);
		Pattern pattern1 = new Pattern(SKIP_SEQ1, 0, new PostRule[0], new MatchAction[]{action});
		Pattern pattern2 = new Pattern(SKIP_SEQ2, 0, new PostRule[0], new MatchAction[]{action});
		ArrayList<Pattern> patterns = new ArrayList<>(2);
		patterns.add(pattern1);
		patterns.add(pattern2);
		MemoryBytePatternSearcher searcher = new MemoryBytePatternSearcher("Locating SKIP Instructions", patterns);
		searcher.search(program, set, monitor);
		return true;
	}

	public boolean getDefaultEnablement(Program program) {
		return true;
	}

	private static class SkipAction implements MatchAction {

		private final Register reg;

		SkipAction(Program program) {
			reg = program.getRegister("skip_mode");
		}

		@Override
		public void apply(Program program, Address addr, Match match) {
			PseudoDisassembler dis = new PseudoDisassembler(program);
			try {
				Instruction inst = dis.disassemble(addr.add(2));
				if (inst != null) {
					ProgramContext context = program.getProgramContext();
					context.setValue(reg, addr, addr, BigInteger.valueOf(inst.getLength()));
				}
			} catch (Exception e) {
				Msg.info(this, "Error determining next instruction length", e);
			}
		}

		@Override
		public void restoreXml(XmlPullParser parser) {
		}
	}

}
