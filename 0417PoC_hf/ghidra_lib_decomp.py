from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


TARGET_STRINGS = [
    '{"serialNumber": "%s", "dateOfPurchase": "%s", "countryPurchased": "%s"}',
    'sso_body=%s\n',
    'sso_productregister parse data fail..',
    '/bin/sh',
]


TARGET_SYMBOLS = [
    'sso_product_register',
    'send_data',
    'system',
    'popen',
]


def get_func(addr):
    return currentProgram.getFunctionManager().getFunctionContaining(addr)


def decompile_func(func):
    if func is None:
        print("NO_FUNCTION")
        return
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    res = ifc.decompileFunction(func, 60, ConsoleTaskMonitor())
    if not res.decompileCompleted():
        print("DECOMPILE_FAILED %s" % func.getEntryPoint())
        return
    print("=== DECOMPILE %s @ %s ===" % (func.getName(), func.getEntryPoint()))
    print(res.getDecompiledFunction().getC())


already = set()


def maybe_decompile(func):
    if func is None:
        return
    ep = str(func.getEntryPoint())
    if ep in already:
        return
    already.add(ep)
    decompile_func(func)


for target in TARGET_STRINGS:
    found = False
    data_iter = currentProgram.getListing().getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        value = data.getValue()
        if value is None or str(value) != target:
            continue
        found = True
        addr = data.getAddress()
        print("=== STRING %s @ %s ===" % (target, addr))
        refs = getReferencesTo(addr)
        if not refs:
            print("NO_REFS")
        for ref in refs:
            func = get_func(ref.getFromAddress())
            print("REF from=%s func=%s entry=%s type=%s" % (
                ref.getFromAddress(),
                func.getName() if func else "<no_func>",
                func.getEntryPoint() if func else "<no_entry>",
                ref.getReferenceType(),
            ))
            maybe_decompile(func)
    if not found:
        print("=== STRING %s ===" % target)
        print("STRING_NOT_FOUND")


for name in TARGET_SYMBOLS:
    print("=== SYMBOL %s ===" % name)
    syms = currentProgram.getSymbolTable().getSymbols(name)
    if not syms:
        print("SYMBOL_NOT_FOUND")
        continue
    for sym in syms:
        print("SYM_ADDR %s" % sym.getAddress())
        func = get_func(sym.getAddress())
        maybe_decompile(func)
        refs = getReferencesTo(sym.getAddress())
        if not refs:
            print("NO_REFS")
        for ref in refs:
            caller = get_func(ref.getFromAddress())
            print("REF from=%s func=%s entry=%s type=%s" % (
                ref.getFromAddress(),
                caller.getName() if caller else "<no_func>",
                caller.getEntryPoint() if caller else "<no_entry>",
                ref.getReferenceType(),
            ))
            maybe_decompile(caller)
