from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType


TARGET_STRINGS = [
    "bd_genie_prodcut_register.cgi",
    "purchase_date",
    "/tmp/register.txt",
    "cat /tmp/register.txt | PATH_INFO=/api/services/readycloud REQUEST_METHOD=PUT /opt/broken/readycloud_control.cgi",
    "readycloud_control.cgi",
    "country",
    "system",
    "popen",
    "_eval",
    "sso_product_register",
]


def iter_defined_strings():
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        try:
            value = data.getValue()
        except Exception:
            continue
        if value is None:
            continue
        s = str(value)
        if isinstance(s, str):
            yield data, s


def get_function(program, addr):
    return program.getFunctionManager().getFunctionContaining(addr)


def print_refs_for_string(s):
    print("=== STRING: %s ===" % s)
    found = False
    for data, value in iter_defined_strings():
        if value == s:
            found = True
            addr = data.getAddress()
            print("STRING_ADDR %s" % addr)
            refs = getReferencesTo(addr)
            if not refs:
                print("NO_REFS")
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = get_function(currentProgram, from_addr)
                func_name = func.getName() if func else "<no_func>"
                entry = func.getEntryPoint() if func else "<no_entry>"
                print("REF from=%s func=%s entry=%s type=%s" % (from_addr, func_name, entry, ref.getReferenceType()))
    if not found:
        print("STRING_NOT_FOUND")


def print_callers(name):
    print("=== SYMBOL: %s ===" % name)
    symtab = currentProgram.getSymbolTable()
    syms = symtab.getSymbols(name)
    if not syms:
        print("SYMBOL_NOT_FOUND")
        return
    for sym in syms:
        addr = sym.getAddress()
        print("SYMBOL_ADDR %s" % addr)
        refs = getReferencesTo(addr)
        if not refs:
            print("NO_CALLERS")
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = get_function(currentProgram, from_addr)
            func_name = func.getName() if func else "<no_func>"
            entry = func.getEntryPoint() if func else "<no_entry>"
            print("CALLER from=%s func=%s entry=%s type=%s" % (from_addr, func_name, entry, ref.getReferenceType()))


def decompile_function(entry_text):
    addr = toAddr(entry_text)
    func = get_function(currentProgram, addr)
    print("=== DECOMPILE: %s ===" % entry_text)
    if func is None:
        print("NO_FUNCTION")
        return
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    res = ifc.decompileFunction(func, 60, ConsoleTaskMonitor())
    if not res.decompileCompleted():
        print("DECOMPILE_FAILED")
        return
    print(res.getDecompiledFunction().getC())


def decompile_symbol(name):
    print("=== DECOMPILE_SYMBOL: %s ===" % name)
    symtab = currentProgram.getSymbolTable()
    syms = symtab.getSymbols(name)
    if not syms:
        print("SYMBOL_NOT_FOUND")
        return
    for sym in syms:
        func = get_function(currentProgram, sym.getAddress())
        if func is None:
            print("NO_FUNCTION_FOR_SYMBOL %s" % sym.getAddress())
            continue
        decompile_function(str(func.getEntryPoint()))


def run():
    for s in TARGET_STRINGS:
        print_refs_for_string(s)
    print_callers("system")
    print_callers("popen")
    print_callers("_eval")

    # These entry points are filled in manually after the first pass if needed.
    for entry in [
        "0x000ca2ac",
        "0x00092594",
        "0x00092c30",
        "0x00092d50",
    ]:
        decompile_function(entry)
    for name in [
        "sso_product_register",
        "send_data",
    ]:
        decompile_symbol(name)


run()
