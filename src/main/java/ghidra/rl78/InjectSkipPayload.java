package ghidra.rl78;

import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayloadCallother;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class InjectSkipPayload extends InjectPayloadCallother {

	public InjectSkipPayload(String sourceName) {
		super(sourceName);
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		PcodeOp[] ops = super.getPcode(program, con);
		Instruction inst = program.getListing().getInstructionAt(con.nextAddr);
		AddressSpace cspace = program.getAddressFactory().getConstantSpace();
		Varnode in = new Varnode(cspace.getAddress(inst.getLength()), 2);
		ops[0].setInput(in, 0);
		return ops;
	}

	@Override
	protected void setTemplate(ConstructTpl ctl) {
		super.setTemplate(ctl);
	}

}
