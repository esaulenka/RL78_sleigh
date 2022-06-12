package ghidra.rl78.disassembly;

import java.math.BigInteger;

import ghidra.app.util.PseudoDisassembler;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemBuffer;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class RL78Disassembler extends Disassembler {

	private static final byte MAP2 = 0x61;
	private static final byte SKIP_OP_1 = (byte) 0xC8;
	private static final byte SKIP_MASK_1 = (byte) 0xCF;
	private static final byte SKIP_OP_2 = (byte) 0xE3;
	private static final byte SKIP_MASK_2 = (byte) 0xEF;

	private final Register skipReg;

	public RL78Disassembler(Program program, TaskMonitor monitor, DisassemblerMessageListener listener) {
		super(program, monitor, listener);
		skipReg = language.getRegister("skip_mode");
	}

	public RL78Disassembler(Language language, AddressFactory addrFactory, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		super(language, addrFactory, monitor, listener);
		skipReg = language.getRegister("skip_mode");
	}

	public RL78Disassembler(Program program, boolean markBadInstructions,
			boolean markUnimplementedPcode, boolean restrictToExecuteMemory, TaskMonitor monitor,
			DisassemblerMessageListener listener) {
		super(
			program, markBadInstructions, markUnimplementedPcode,
			restrictToExecuteMemory, monitor, listener);
		skipReg = language.getRegister("skip_mode");
	}

	@Override
	protected void adjustPreParseContext(MemBuffer instrMemBuffer) {
		try {
			if (instrMemBuffer.getByte(0) != MAP2) {
				return;
			}
			byte b = instrMemBuffer.getByte(1);
			if ((b & SKIP_MASK_1) != SKIP_OP_1 && (b & SKIP_MASK_2) != SKIP_OP_2) {
				return;
			}
			Program program = instrMemBuffer.getMemory().getProgram();
			Address addr = instrMemBuffer.getAddress();
			PseudoDisassembler dis = new PseudoDisassembler(program);
			Instruction inst = dis.disassemble(addr.add(2));
			if (inst == null) {
				return;
			}
			RegisterValue value = new RegisterValue(skipReg, BigInteger.valueOf(inst.getLength()));
			disassemblerContext.setContextRegisterValue(value, addr);
		} catch (Exception e) {
			Msg.error(this, null, e);
		}
	}

}
