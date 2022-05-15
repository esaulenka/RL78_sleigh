package ghidra.rl78;

import ghidra.app.plugin.processors.sleigh.SleighException;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.template.ConstructTpl;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.lang.PcodeParser;
import ghidra.program.model.lang.InjectPayload.InjectParameter;
import ghidra.sleigh.grammar.Location;

public class RL78InjectLibrary extends PcodeInjectLibrary {

    public RL78InjectLibrary(PcodeInjectLibrary op2) {
        super(op2);
    }

    public RL78InjectLibrary(SleighLanguage l) {
        super(l);
    }

    @Override
	public PcodeInjectLibrary clone() {
		return new RL78InjectLibrary(this);
	}

    @Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (name.equals("getNextInstructionLength")) {
            return new InjectSkipPayload(sourceName);
        }
		return super.allocateInject(sourceName, name, tp);
    }

    @Override
    public void parseInject(InjectPayload payload) throws SleighException {
        if (!(payload instanceof InjectSkipPayload)) {
            super.parseInject(payload);
            return;
        }
        String sourceName = payload.getSource();
    	if (sourceName == null) {
    		sourceName = "unknown";
    	}
        InjectSkipPayload payloadSleigh = (InjectSkipPayload) payload;
        PcodeParser parser = new PcodeParser(language, uniqueBase);
        Location loc = new Location(sourceName, 1);
        InjectParameter[] input = payload.getOutput();
        for (InjectParameter element : input) {
            parser.addOperand(loc, element.getName(), element.getIndex());
        }
        String pcodeText = "len = 0:2;";
        ConstructTpl constructTpl = parser.compilePcode(pcodeText, sourceName, 1);

        uniqueBase = parser.getNextTempOffset();

        payloadSleigh.setTemplate(constructTpl);
    }

}
