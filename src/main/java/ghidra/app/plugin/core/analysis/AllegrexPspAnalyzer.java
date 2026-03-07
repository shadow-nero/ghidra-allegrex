package ghidra.app.plugin.core.analysis;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.framework.options.Options;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.symbol.FlowType;
import allegrex.analysis.RecoverSections;

@SuppressWarnings("unused")
public class AllegrexPspAnalyzer extends AbstractAnalyzer {
	private boolean doSectionRecovery = false;
  private boolean pspResolveNIDs = false;
	
	private static final String NAME = "PSP Analyzer (Allegrex)";
	private static final String DESCRIPTION = "Analyze PSP";
  private static final String OPTION_RECOVER = "Recover PSP Sections";
  private static final String OPTION_NIDS = "Resolve NIDs & Types";
  private static final String DESC_RECOVER = "Restores Exports, Imports, lib stub, rodata sceModuleInfo, etc.";
  private static final String DESC_NIDS = "Resolves NIDs and recovers function parameters/returns based on JSON definitions.";

  public AllegrexPspAnalyzer () {
    super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
  }
  
  @Override
  public void registerOptions(Options options, Program program){
	      super.registerOptions(options, program);
        options.registerOption(OPTION_RECOVER, doSectionRecovery, null, "Recover PSP sections");
        options.registerOption(OPTION_NIDS, pspResolveNIDs, null, "Resolver PSP NIDs");
  }
  
  @Override
    public void optionsChanged(Options options, Program program) {
        super.optionsChanged(options, program);
        doSectionRecovery = options.getBoolean(OPTION_RECOVER, false);
        pspResolveNIDs = options.getBoolean(OPTION_NIDS, false);
    }
  
  @Override
  public boolean canAnalyze(Program program){
    return program.getLanguage().getProcessor().equals(Processor.findOrPossiblyCreateProcessor("Allegrex"));
  }
  
    @Override
  public boolean added (Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
    throws CancelledException {

      if (doSectionRecovery == true) {
        try {
            RecoverSections.RecoverSections(program, pspResolveNIDs);
        } catch (Exception e) {
            log.appendException(e);
            return false; 
        }
    }

		return true;
	}
}
