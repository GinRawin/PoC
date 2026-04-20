from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


STRINGS = [
    "bd_genie_prodcut_register.cgi",
    "purchase_date",
    "/tmp/register.txt",
    "Product Register...",
    "sso_body=",
    "sso_productregister parse data fail..",
    "sh -c",
    "/bin/sh",
]


SYMS = [
    "sso_product_register",
    "system",
    "popen",
]


def func_at(addr):
    return currentProgram.getFunctionManager().getFunctionContaining(addr)


def dec(func):
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


def dump_string_refs(target):
    listing = currentProgram.getListing()
    data_iter = listing.getDefinedData(True)
    printed = False
    while data_iter.hasNext():
        data = data_iter.next()
        value = data.getValue()
        if value is None:
            continue
        if str(value) != target:
            continue
        printed = True
        addr = data.getAddress()
        print("=== STRING %s @ %s ===" % (target, addr))
        refs = getReferencesTo(addr)
        if not refs:
            print("NO_REFS")
        for ref in refs:
            f = func_at(ref.getFromAddress())
            print("REF from=%s func=%s entry=%s type=%s" % (
                ref.getFromAddress(),
                f.getName() if f else "<no_func>",
                f.getEntryPoint() if f else "<no_entry>",
                ref.getReferenceType(),
            ))
    if not printed:
        print("=== STRING %s ===" % target)
        print("STRING_NOT_FOUND")


def dump_symbol_refs(name):
    print("=== SYMBOL %s ===" % name)
    syms = currentProgram.getSymbolTable().getSymbols(name)
    if not syms:
        print("SYMBOL_NOT_FOUND")
        return
    for sym in syms:
        print("SYM_ADDR %s" % sym.getAddress())
        refs = getReferencesTo(sym.getAddress())
        if not refs:
            print("NO_REFS")
        for ref in refs:
            f = func_at(ref.getFromAddress())
            print("REF from=%s func=%s entry=%s type=%s" % (
                ref.getFromAddress(),
                f.getName() if f else "<no_func>",
                f.getEntryPoint() if f else "<no_entry>",
                ref.getReferenceType(),
            ))


for s in STRINGS:
    dump_string_refs(s)

for s in SYMS:
    dump_symbol_refs(s)

for addr in [
    "0x000ca2ac",
    "0x00092594",
]:
    func = func_at(toAddr(addr))
    if func is not None:
        dec(func)
