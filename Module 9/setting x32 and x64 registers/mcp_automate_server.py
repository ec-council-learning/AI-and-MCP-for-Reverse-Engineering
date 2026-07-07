from fastmcp import FastMCP
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import RegDump32
from x64dbg_automate.models import RegDump64
from x64dbg_automate.models import Symbol

mcp = FastMCP("MCP_Automate_Server")


x32client = X64DbgClient(r"C:\Program Files\x64dbg\release\x32\x32dbg.exe")
x64client = X64DbgClient(r"C:\Program Files\x64dbg\release\x64\x64dbg.exe")
debugger = None #select_debugger() will assign one of the above


# --------------------------------------------------------------------
# Internal helper functions (not MCP tools)
# Used by get_regs_x32() and get_regs_x64()
# --------------------------------------------------------------------
def _decode_eflags(val: int) -> dict:
    """
    Decode selected EFLAGS/RFLAGS bits into booleans.
    Only ZF, PF, AF, OF, SF, DF, CF, TF, and IF are included.
    """
    return {
        "CF": bool(val & (1 << 0)),   # Carry
        "PF": bool(val & (1 << 2)),   # Parity
        "AF": bool(val & (1 << 4)),   # Aux carry
        "ZF": bool(val & (1 << 6)),   # Zero
        "SF": bool(val & (1 << 7)),   # Sign
        "TF": bool(val & (1 << 8)),   # Trap
        "IF": bool(val & (1 << 9)),   # Interrupt enable
        "DF": bool(val & (1 << 10)),  # Direction
        "OF": bool(val & (1 << 11)),  # Overflow
    }


# --------------------------------------------------------------------
# MCP tools start here
# --------------------------------------------------------------------
@mcp.tool()
def select_debugger(debugger_type: str) -> str:
    """
    Sets the working debugger to be either x32client or x64client. 
    Ask user which debugger is needed. Do not call this function without first getting a
    reply from user. Also this function needs to be called once to set the working debugger
    before any session begins, or before any other functions is called.

    Args:
        debugger_type: Whether it is x32 or x64

    Returns:
        str: Debugger path, or, error messages
    """
    global debugger
    dbg = debugger_type.strip().lower()

    if dbg == "x32":
        debugger = x32client
    elif dbg == "x64":
        debugger = x64client
    else:
        raise ValueError("debugger_type must be 'x32' or 'x64'")
    
    return f"Debugger set to {dbg}"

@mcp.tool()
def start_session(target_exe: str = "") -> int:
    """
    Start a new x64dbg session and optionally load an executable into it. 
    If target_exe is not provided, the debugger starts without any executable. 
    This is useful for performing configuration before the debuggee is loaded.

    Args:
        target_exe: The path to the target executable (optional)

    Returns:
        int: The debug session ID
    """
    return debugger.start_session(target_exe)


@mcp.tool()
def detach_session() -> None:
    """
    Detach from the current x64dbg session, leaving the debugger process running.
    If start_session() has been previously called, 
    then this function must be called prior to any new calls to 
    start_session(). start_session() must not be called without
    first detaching from any existing session. Before calling
    this function, ask user whether to detach_session() or terminate_session()

    Args:
        None

    Returns:
        None
    """
    debugger.detach_session()

@mcp.tool()
def terminate_session() -> None:
    """
    End the current debugger session, terminating the debugger process.
    If start_session() has been previously called,
    then this function must be called prior to any new calls to 
    start_session(). start_session() must not be called without
    first terminating existing session. Before calling
    this function, ask user whether to detach_session() or terminate_session()

    Args: 
        None

    Returns: 
        None
    """
    debugger.terminate_session()

@mcp.tool()
def attach_session(session_pid: int) -> None:
    """
    Attach to an existing debugger session

    Args:
        session_pid: The process ID (PID) of the existing debugger process to attach to
    """
    debugger.attach_session(session_pid)

@mcp.tool()
def get_reg(reg: str) -> str:
    """
    Get a single register or subregister. Do not this function to get flags, instead
    use either get_regs_x32(), or get_regs_x64()

    Args:
        reg: Register to get
        (e.g. eax, ebx, ah, al ... or, rax, rbx, ... etc)
    
    Returns:
        str: the hex value stored in the register (e.g., '0x64ff84')
        with the '0x' prefix meant to indicate hex
    """
    value = debugger.get_reg(reg)
    return hex(value)

@mcp.tool()
def get_regs_x32() -> dict:
    """
    Dump the general-purpose registers and flags of the x32dbg debugger.
    Includes decoded ZF, PF, AF, OF, SF, DF, CF, TF, and IF flags.

    Returns:
        dict: register dump with 0x-prefixed uppercase hex, plus FLAGS booleans.
    """
    if debugger is None:
        raise RuntimeError("No debugger selected. Call select_debugger('x32') first.")

    dump: RegDump32 = debugger.get_regs()
    ef = dump.context.eflags
    regs = {
        # GPRs
        "EIP":    f"0x{dump.context.eip:X}",
        "EAX":    f"0x{dump.context.eax:X}",
        "EBX":    f"0x{dump.context.ebx:X}",
        "ECX":    f"0x{dump.context.ecx:X}",
        "EDX":    f"0x{dump.context.edx:X}",
        "ESI":    f"0x{dump.context.esi:X}",
        "EDI":    f"0x{dump.context.edi:X}",
        "ESP":    f"0x{dump.context.esp:X}",
        "EBP":    f"0x{dump.context.ebp:X}",

        # Flags
        "FLAGS":  _decode_eflags(ef),
    }
    return regs



@mcp.tool()
def get_regs_x64() -> dict:
    """
    Dump the general-purpose registers and flags of the x64dbg debugger.
    Includes decoded ZF, PF, AF, OF, SF, DF, CF, TF, and IF flags.

    Returns:
        dict: register dump with 0x-prefixed uppercase hex, plus FLAGS booleans.
    """
    if debugger is None:
        raise RuntimeError("No debugger selected. Call select_debugger('x64') first.")

    dump: RegDump64 = debugger.get_regs()
    ef = dump.context.eflags
    regs = {
        # GPRs
        "RIP": f"0x{dump.context.rip:X}",
        "RAX": f"0x{dump.context.rax:X}",
        "RBX": f"0x{dump.context.rbx:X}",
        "RCX": f"0x{dump.context.rcx:X}",
        "RDX": f"0x{dump.context.rdx:X}",
        "RSI": f"0x{dump.context.rsi:X}",
        "RDI": f"0x{dump.context.rdi:X}",
        "RSP": f"0x{dump.context.rsp:X}",
        "RBP": f"0x{dump.context.rbp:X}",
        "R8":  f"0x{dump.context.r8:X}",
        "R9":  f"0x{dump.context.r9:X}",
        "R10": f"0x{dump.context.r10:X}",
        "R11": f"0x{dump.context.r11:X}",
        "R12": f"0x{dump.context.r12:X}",
        "R13": f"0x{dump.context.r13:X}",
        "R14": f"0x{dump.context.r14:X}",
        "R15": f"0x{dump.context.r15:X}",

        # Flags
        "FLAGS":  _decode_eflags(ef),
    }
    return regs

@mcp.tool()
def set_reg(reg: str, val) -> bool:
    """
    Set a single register or subregister to a value.

    Args:
        reg: Register to set
        val: Integer or string value to set.
             Examples:
                0xAB    -> decimal 171
                "0xAB"  -> decimal 171
                "171"   -> decimal 171

    Returns:
        bool: True if the register was set successfully, False otherwise.
    """
    if not isinstance(val, int):
        val = int(val, 0)  # auto-detect base from prefix (0x, 0o, 0b)

    return debugger.set_reg(reg, val)

@mcp.tool()
def get_symbol_at(addr) -> dict:
    """
    Retrieves the symbol at the specified address.
    Accepts integer or string (e.g., 0x12345678 or "0x12345678").
    Returns a dictionary with symbol details.
    """
    # Normalize address
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return {"error": f"Invalid address: {addr!r}"}

    s: Symbol = debugger.get_symbol_at(a)
    if not s:
        return {"error": f"No symbol found at {hex(a)}"}

    return {
        "addr": s.addr,
        "decoratedSymbol": s.decoratedSymbol,
        "undecoratedSymbol": s.undecoratedSymbol,
        "type": s.type,
        "ordinal": s.ordinal
    }

@mcp.tool()
def eval_sync(eval_str: str) -> dict:
    """
    Evaluates an expression that results in a numerical output,
    e.g: esp + 0x4, rsp + 0x28, LoadLibraryA + 0x20.
    Notes:
      - On x32, use esp/ebp, etc
      - On x64, use rsp/rbp, etc.
      - Useful for getting the addresses of the stack where parameters 
        are pushed to the stack prior to a function call on x32, 
        eg. esp+4, esp+8, esp+C, etc...
      - On x64 (Windows), the first four integer/pointer parameters are in
        rcx, rdx, r8, r9. The caller reserves 32 bytes of shadow space at
        [rsp+0x20 .. rsp+0x38]. Additional parameters start at [rsp+0x40]
        and advance in 8-byte steps: [rsp+0x40], [rsp+0x48], [rsp+0x50], ...

    Args:
        eval_str: The expression to be evaluated

    Returns:
        dict: {
            "dec": int,          # raw decimal result 
            "hex": str,          # hex string with 0x prefix
            "success": bool      # True if evaluation succeeded
        }
    """
    result, success = debugger.eval_sync(eval_str)
    return {
        "dec": result,
        "hex": hex(result) if success else None,
        "success": success
    }




if __name__ == "__main__":
    mcp.run()