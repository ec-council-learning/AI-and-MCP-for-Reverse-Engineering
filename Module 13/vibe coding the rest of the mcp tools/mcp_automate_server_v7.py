from fastmcp import FastMCP
from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import RegDump32
from x64dbg_automate.models import RegDump64
from x64dbg_automate.models import Symbol
from x64dbg_automate.events import DbgEvent, EventType
from x64dbg_automate.models import BreakpointType, Breakpoint, StandardBreakpointType
from x64dbg_automate.models import HardwareBreakpointType, MemoryBreakpointType
from x64dbg_automate.models import SegmentReg, ReferenceViewRef

mcp = FastMCP("MCP_Automate_Server")


x32client = X64DbgClient(r"C:\Program Files\x64dbg\release\x32\x32dbg.exe")
x64client = X64DbgClient(r"C:\Program Files\x64dbg\release\x64\x64dbg.exe")
debugger = None #select_debugger() will assign one of the above


# --------------------------------------------------------------------
# Internal helper functions (not MCP tools)
# --------------------------------------------------------------------

# Used by get_regs_x32() and get_regs_x64()
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

# Used by disassemble_with_alignment_detection and disassemble_smart


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

# --------------------------------------------------------------------
# SESSION CONTROL
# --------------------------------------------------------------------
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

# --------------------------------------------------------------------
# REGISTERS AND EXPRESSIONS
# --------------------------------------------------------------------
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
    Always use this function to calculate stack addresses, eg rsp + 0x20,
    esp + 0x4 etc...
    This returns memory addresses not data or values stored at those address.
    For getting values or data, use this first to calculate the memory
    address then use the memory address in read_memory function to fetch the data or value
    stored at the address.

    Notes:
      - On x32, use esp/ebp, etc
      - On x64, use rsp/rbp, etc.
      - Useful for getting the addresses of the stack where parameters 
        are pushed to the stack prior to a function call on x32, 
        eg. esp + 0x4, esp + 0x8, esp + 0xC, etc...
      - On x64 (Windows), the first four integer/pointer parameters are in
        rcx, rdx, r8, r9. The fifth parameter is located at [rsp + 0x20], and additional
        parameters continue at [rsp + 0x28], [rsp + 0x30], etc., in 8-byte steps.

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

# --------------------------------------------------------------------
# MEMORY CONTROL
# --------------------------------------------------------------------
@mcp.tool()
def read_memory(addr, size) -> dict:
    """
    Reads data from the debuggee's memory. Do not use this directly if
    you need to do calculation on addresses, eg esp + 0x4 etc. Always use
    eval_sync() to do calculation first to get the effective memory address,
    before using this function.

    Args:
        addr: The address to read from (int or str like "0x64FF7C")
        size: Number of bytes to read (int or str like "4" or "0x4")

    Returns:
        {"addr": "0x...", "size": int, "data_hex": "..."} or {"error": "..."}
        data_hex is returned in little-endian corrected (flipped to little-endian order).

    """
    # If AI agent provides values with "0x" prefix
    # int(addr, 0) will auto-detect base from prefix (e.g. "0x" for hex)
    a = int(addr, 0) if isinstance(addr, str) else addr
    n = int(size, 0) if isinstance(size, str) else size

    data = debugger.read_memory(a, n)

    # Flip endianness so hex string matches the integer value in memory
    flipped = bytes(data[::-1]).hex()

    return {"addr": hex(a), "size": n, "data_hex": "0x"+flipped}

@mcp.tool()
def read_aob(addr, size) -> dict:
    """
    Read raw bytes from the debuggee's memory and return them as an
    AoB (Array of Bytes) signature string without any endianness flipping.

    Args:
        addr: The address to read from. Accepts int or str (e.g., 0x64FF7C or "0x64FF7C").
        size: Number of bytes to read. Accepts int or str (e.g., 9 or "0x9").

    Returns:
        dict:
            {
                "addr": "0x...",          # address as hex string
                "size": int,              # number of bytes read
                "aob": "AA BB CC ...",    # space-separated, uppercase bytes as seen in memory
                "hex_bytes": "0xAABBCC..."# contiguous hex form (no spaces), same order as memory
            }

    Notes:
        - Works with both x32 and x64 debuggers (assumes a debugger has been selected).
        - Unlike read_memory(), this function DOES NOT flip bytes to account for little-endian.
          The order is preserved exactly as it appears in memory.
    """
    # Normalize inputs (mirror read_memory style)
    a = int(addr, 0) if isinstance(addr, str) else addr
    n = int(size, 0) if isinstance(size, str) else size

    data = debugger.read_memory(a, n)  # returns bytes

    # Preserve order exactly as read from memory
    hex_no_prefix = data.hex().upper()
    # Insert spaces every 2 hex chars to build AoB string
    aob = " ".join(hex_no_prefix[i:i+2] for i in range(0, len(hex_no_prefix), 2))

    return {
        "addr": hex(a),
        "size": n,
        "aob": aob,
        "hex_bytes": "0x" + hex_no_prefix
    }


@mcp.tool()
def read_str_from_memory(addr, size, encoding: str = "ascii") -> dict:
    """
    Reads bytes from the debuggee's memory and returns them in both hex and decoded form.

    Args:
        addr: The address to read from (int or str like "0x64FF7C")
        size: Number of bytes to read (int or str like "4" or "0x4")
        encoding: Text encoding for decoding bytes (default: "ascii")

    Returns:
        {
            "addr": "0x...",
            "hex_bytes": "0x...",
            "string": "..."   # best-effort decoded string
        }
        or {"error": "..."}
    """
    # --- Normalize the memory address ---
    # If addr is a string like "0x64FF7C", convert to int using base auto-detection.
    # If addr is already an int, leave it as-is.
    a = int(addr, 0) if isinstance(addr, str) else addr

    # --- Normalize the size to read ---
    # Same logic: convert string values ("4", "0x4") into int.
    n = int(size, 0) if isinstance(size, str) else size

    try:
        # --- Attempt to read raw bytes from the debuggee's memory ---
        # This calls the debugger backend to extract 'n' bytes starting at address 'a'.
        hex_bytes = debugger.read_memory(a, n)
    except Exception as e:
        # If memory access fails (invalid address, access violation, etc.),
        # return a dictionary with the error message.
        return {"error": str(e)}

    try:
        # --- Try decoding the raw bytes into a human-readable string ---
        # Use the provided encoding (default: ASCII), could be unicode (utf-16) etc...
        # errors="replace" means undecodable bytes will be replaced with � instead of raising an exception.
        text = hex_bytes.decode(encoding, errors="replace")
    except Exception:
        # If decoding fails entirely (e.g., invalid encoding), just set text to None.
        text = None

    # --- Return results as a dictionary ---
    return {
        "addr": hex(a),                       # Address formatted as hex string
        "hex_bytes": "0x" + hex_bytes.hex(),  # Raw bytes in hex (big-endian string format, ie. bytes as they appear in memory L to R)
        "string": text,                       # Decoded text (if possible), otherwise None
    }

@mcp.tool()
def virt_query(addr) -> dict:
    """
    Query the virtual memory information for the page containing the given address.
    This wraps x64dbg's VirtualQuery-like API and returns a dictionary suitable
    for JSON serialization.

    Args:
        addr: The address to query (int or str like "0x7FF6C0000000").

    Returns:
        dict on success:
        {
            "base_address": "0x...",       # page base
            "allocation_base": "0x...",    # allocation base
            "allocation_protect": int,     # PAGE_* protection at allocation
            "partition_id": int,
            "region_size": int,            # size in bytes
            "state": int,                  # MEM_COMMIT / MEM_RESERVE / MEM_FREE
            "protect": int,                # current PAGE_* protection
            "type": int,                   # MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
            "info": str                    # human-readable summary from backend
        }

        or {"error": "..."} if the address is invalid or the query fails.
    """
    # --- Normalize the memory address, mirroring read_str_from_memory ---
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return {"error": f"Invalid address: {addr!r}"}

    # --- Perform the query and convert the MemPage model into a dict ---
    try:
        mp = debugger.virt_query(a)
    except Exception as e:
        return {"error": str(e)}

    if not mp:
        return {"error": f"No memory information for {hex(a)}"}

    return {
        "base_address":       hex(mp.base_address),
        "allocation_base":    hex(mp.allocation_base),
        "allocation_protect": mp.allocation_protect,
        "partition_id":       mp.partition_id,
        "region_size":        mp.region_size,
        "state":              mp.state,
        "protect":            mp.protect,
        "type":               mp.type,
        "info":               mp.info,
    }

@mcp.tool()
def memmap() -> dict:
    """
    Retrieves the complete memory map of the debugged process.
    Returns information about all memory regions including their base addresses,
    sizes, protection flags, and states.

    Args:
        None

    Returns:
        dict: {
            "memory_pages": [
                {
                    "base_address": "0x...",       # page base address
                    "allocation_base": "0x...",    # allocation base address
                    "allocation_protect": int,     # PAGE_* protection at allocation
                    "partition_id": int,
                    "region_size": int,            # size in bytes
                    "state": int,                  # MEM_COMMIT / MEM_RESERVE / MEM_FREE
                    "protect": int,                # current PAGE_* protection
                    "type": int,                   # MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
                    "info": str                    # human-readable summary
                },
                ...
            ],
            "total_pages": int                     # total number of memory pages
        }
        or {"error": "..."} if the operation fails.
    """
    try:
        # Call the debugger's memmap function to get list of MemPage objects
        pages = debugger.memmap()
    except Exception as e:
        return {"error": str(e)}

    if not pages:
        return {"error": "No memory pages found or memmap failed"}

    # Convert list of MemPage objects to list of dictionaries
    memory_pages = []
    for page in pages:
        memory_pages.append({
            "base_address":       hex(page.base_address),
            "allocation_base":    hex(page.allocation_base),
            "allocation_protect": page.allocation_protect,
            "partition_id":       page.partition_id,
            "region_size":        page.region_size,
            "state":              page.state,
            "protect":            page.protect,
            "type":               page.type,
            "info":               page.info,
        })

    return {
        "memory_pages": memory_pages,
        "total_pages": len(memory_pages)
    }

@mcp.tool()
def write_memory(addr, data) -> bool:
    """
    Write raw bytes to the debuggee's memory. It can also write strings to the memory address.

    Args:
        addr: Memory address to write to. Accepts int or str (e.g., 0x7FF6C0000000 or "0x7FF6C0000000").
        data: The bytes to write. Accepts:
              - bytes / bytearray
              - iterable of ints (0-255)
              - hex string (e.g., "9090" or "0x9090" or "90 90")
              - plain string (encoded as UTF-8)

    Returns:
        bool: True on success, False on failure.

    Notes:
        - If you get False, use virt_query(addr) or memmap() to inspect page protections
          and ensure the region is writable.
    """
    # --- Normalize address, mirroring style from read_str_from_memory/virt_query ---
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return False

    # --- Normalize data into a bytes payload ---
    payload: bytes
    try:
        if isinstance(data, (bytes, bytearray)):
            payload = bytes(data)
        elif isinstance(data, str):
            s = data.strip()
            # Accept hex-like strings with or without 0x and with optional spaces
            if s.lower().startswith("0x"):
                s = s[2:]
            try:
                payload = bytes.fromhex(s.replace(" ", ""))
            except ValueError:
                # Fallback: treat as plain text to be UTF-8 encoded
                payload = s.encode("utf-8")
        else:
            # Accept iterables of ints (0-255)
            payload = bytes(data)
    except Exception:
        return False

    # --- Perform the write ---
    try:
        return bool(debugger.write_memory(a, payload))
    except Exception:
        return False

@mcp.tool()
def memset(addr, byte_val, size) -> bool:
    """
    Set memory in the debuggee's address space to a specified byte value.
    Similar to the C memset() function.

    Args:
        addr: Memory address to set. Accepts int or str (e.g., 0x7FF6C0000000 or "0x7FF6C0000000").
        byte_val: The byte value to set memory to. Accepts int or str (0-255).
        size: Number of bytes to set. Accepts int or str.

    Returns:
        bool: True on success, False on failure.

    Notes:
        - If you get False, use virt_query(addr) or memmap() to inspect page protections
          and ensure the region is writable.
        - byte_val will be masked to 0-255 range if larger values are provided.
    """
    # --- Normalize address, following pattern from other memory functions ---
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return False

    # --- Normalize byte value ---
    try:
        b = int(byte_val, 0) if isinstance(byte_val, str) else int(byte_val)
        # Ensure byte value is in valid range (0-255)
        b = b & 0xFF
    except (TypeError, ValueError):
        return False

    # --- Normalize size ---
    try:
        s = int(size, 0) if isinstance(size, str) else int(size)
        if s <= 0:
            return False
    except (TypeError, ValueError):
        return False

    # --- Perform the memset operation ---
    try:
        return bool(debugger.memset(a, b, s))
    except Exception:
        return False

# --------------------------------------------------------------------
# ASSEMBLING and DISASSEMBLING
# --------------------------------------------------------------------
@mcp.tool()
def disassemble_at(addr) -> dict:
    """
    Disassemble a single instruction at the specified address.
    Works with both 32-bit and 64-bit programs.

    Args:
        addr: The address to disassemble at (int or str like "0x401000")

    Returns:
        dict: {
            "addr": "0x...",           # address as hex string
            "instruction": str,        # disassembled instruction text
            "argcount": int,           # number of arguments
            "instr_size": int,         # instruction size in bytes
            "type": int,               # DisasmInstrType (0=Normal, 1=Branch, 2=Stack)
            "args": [                  # list of instruction arguments
                {
                    "mnemonic": str,   # argument mnemonic
                    "type": int,       # DisasmArgType (0=Normal, 1=Memory)
                    "segment": int,    # SegmentReg enum value
                    "constant": int,   # constant value
                    "value": int,      # argument value
                    "memvalue": int    # memory value
                },
                ...
            ]
        }
        or {"error": "..."} if disassembly fails
    """
    # --- Normalize address, following pattern from other memory functions ---
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return {"error": f"Invalid address: {addr!r}"}

    # --- Perform the disassembly ---
    try:
        instruction = debugger.disassemble_at(a)
    except Exception as e:
        return {"error": str(e)}

    if not instruction:
        return {"error": f"Failed to disassemble instruction at {hex(a)}"}

    # --- Convert InstructionArg objects to dictionaries ---
    args = []
    for arg in instruction.arg:
        args.append({
            "mnemonic": arg.mnemonic,
            "type": int(arg.type),
            "segment": int(arg.segment),
            "constant": arg.constant,
            "value": arg.value,
            "memvalue": arg.memvalue
        })

    # --- Return the instruction details as a dictionary ---
    return {
        "addr": hex(a),
        "instruction": instruction.instruction,
        "argcount": instruction.argcount,
        "instr_size": instruction.instr_size,
        "type": int(instruction.type),
        "args": args
    }

@mcp.tool()
def disassemble_smart(addr, num_lines: int = 10) -> dict:
    """
    Disassemble multiple instructions starting at the specified address with automatic alignment detection.
    Works with both 32-bit and 64-bit programs. Automatically detects proper instruction boundaries
    to ensure accurate disassembly even when the starting address might be in the middle of an instruction.

    Args:
        addr: The starting address to disassemble from (int or str like "0x401000")
        num_lines: Number of instructions to disassemble (default: 10)

    Returns:
        dict: {
            "start_addr": "0x...",     # starting address as hex string (may differ from input if realigned)
            "num_lines": int,          # number of instructions requested
            "instructions": [          # list of disassembled instructions
                {
                    "addr": "0x...",           # address as hex string
                    "instruction": str,        # disassembled instruction text
                    "argcount": int,           # number of arguments
                    "instr_size": int,         # instruction size in bytes
                    "type": int,               # DisasmInstrType (0=Normal, 1=Branch, 2=Stack)
                    "args": [                  # list of instruction arguments
                        {
                            "mnemonic": str,   # argument mnemonic
                            "type": int,       # DisasmArgType (0=Normal, 1=Memory)
                            "segment": int,    # SegmentReg enum value
                            "constant": int,   # constant value
                            "value": int,      # argument value
                            "memvalue": int    # memory value
                        },
                        ...
                    ]
                },
                ...
            ],
            "total_bytes": int,        # total bytes covered by all instructions
            "original_addr": "0x...",  # the original address you requested
            "alignment_offset": int,   # bytes offset applied for proper alignment (0 if no adjustment)
            "confidence_score": int,   # reliability metric for the alignment detection
            "architecture": str        # "x32" or "x64" based on debugger type
        }
        or {"error": "..."} if disassembly fails
    """
    global debugger, x32client, x64client
    
    # Normalize target address
    try:
        target_addr = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return {"error": f"Invalid address: {addr!r}"}

    # Determine architecture and set parameters
    is_x64 = (debugger == x64client)
    search_window = 32 if is_x64 else 16
    
    # Try to find proper alignment by testing multiple starting points
    best_start = target_addr
    best_score = 0
    
    for offset in range(search_window + 1):
        start_addr = target_addr - offset
        if start_addr < 0:
            continue
            
        try:
            # Test this starting point
            score = 0
            current_addr = start_addr
            valid_count = 0
            covers_target = False
            
            # Try to disassemble 5-8 instructions from this point
            test_limit = 8 if is_x64 else 5
            for _ in range(test_limit):
                try:
                    instr = debugger.disassemble_at(current_addr)
                    if not instr or instr.instr_size <= 0:
                        break
                    
                    valid_count += 1
                    
                    # Check if this instruction covers our target address
                    if current_addr <= target_addr < current_addr + instr.instr_size:
                        covers_target = True
                        score += 5  # Bonus for covering target
                    
                    # Score based on instruction quality
                    instr_text = instr.instruction.lower()
                    if any(keyword in instr_text for keyword in ['mov', 'push', 'call', 'lea']):
                        score += 2
                    elif any(keyword in instr_text for keyword in ['add', 'sub', 'cmp', 'test', 'jmp']):
                        score += 1
                    elif any(keyword in instr_text for keyword in ['int ', 'hlt', 'invalid']):
                        score -= 5
                    
                    current_addr += instr.instr_size
                    
                    if covers_target and valid_count >= 3:
                        break
                        
                except Exception:
                    break
            
            # Final scoring
            score += valid_count
            if offset == 0:
                score += 1  # Small bonus for exact match
            if covers_target:
                score += 3
                
            if score > best_score and valid_count >= 2:
                best_score = score
                best_start = start_addr
                
        except Exception:
            continue
    
    # Disassemble from the best starting point
    try:
        # Implement the disassembly logic directly (no dependency on old disassemble function)
        instructions = []
        current_addr = best_start
        total_bytes = 0

        for i in range(num_lines):
            try:
                # Disassemble instruction at current address
                instruction = debugger.disassemble_at(current_addr)
            except Exception as e:
                return {
                    "error": f"Failed to disassemble at {hex(current_addr)} (instruction {i+1}/{num_lines}): {str(e)}",
                    "partial_results": {
                        "start_addr": hex(best_start),
                        "num_lines": num_lines,
                        "instructions": instructions,
                        "total_bytes": total_bytes
                    }
                }

            if not instruction:
                return {
                    "error": f"No instruction found at {hex(current_addr)} (instruction {i+1}/{num_lines})",
                    "partial_results": {
                        "start_addr": hex(best_start),
                        "num_lines": num_lines,
                        "instructions": instructions,
                        "total_bytes": total_bytes
                    }
                }

            # Convert InstructionArg objects to dictionaries
            args = []
            for arg in instruction.arg:
                args.append({
                    "mnemonic": arg.mnemonic,
                    "type": int(arg.type),
                    "segment": int(arg.segment),
                    "constant": arg.constant,
                    "value": arg.value,
                    "memvalue": arg.memvalue
                })

            # Add instruction to results
            instructions.append({
                "addr": hex(current_addr),
                "instruction": instruction.instruction,
                "argcount": instruction.argcount,
                "instr_size": instruction.instr_size,
                "type": int(instruction.type),
                "args": args
            })

            # Move to next instruction
            total_bytes += instruction.instr_size
            current_addr += instruction.instr_size

        # Return complete results with alignment information
        return {
            "start_addr": hex(best_start),
            "num_lines": num_lines,
            "instructions": instructions,
            "total_bytes": total_bytes,
            "original_addr": hex(target_addr),
            "alignment_offset": target_addr - best_start,
            "confidence_score": best_score,
            "architecture": "x64" if is_x64 else "x32"
        }
        
    except Exception as e:
        return {"error": f"Failed disassembly: {str(e)}"}
    
@mcp.tool()
def assemble_at(addr, instr) -> int | None:
    """
    Assemble a single instruction at the specified address.

    Args:
        addr: The address to assemble at (int or str like "0x401000").
        instr: Instruction to assemble (str), e.g. "mov rax, OutputDebugStringA",
               "lea rcx, [rcx * 2 + 4]", etc.

    Returns:
        int or None: The size (in bytes) of the assembled instruction on success,
                     or None on failure.

    Notes:
        - Works for both win32 and win64 targets (architecture is inferred from the
          active debugger).
        - If assembling fails due to page protections, use virt_query(addr) or memmap()
          to inspect protections, then adjust protections in the debugger UI/x64dbg
          as needed before retrying.
        - Symbol/label expressions are resolved by x64dbg (e.g., function names,
          module!symbol, labels).
    """
    # --- Normalize the address, mirroring other memory/disasm helpers ---
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        return None

    # --- Validate instruction text ---
    if not isinstance(instr, str):
        return None
    asm = instr.strip()
    if not asm:
        return None

    # --- Attempt to assemble at the target address ---
    try:
        # x64dbg-automate exposes assemble_at(address, instruction) -> size(int) or 0/None
        size = debugger.assemble_at(a, asm)
    except Exception:
        return None

    # Defensive: treat falsy/zero as failure per contract
    try:
        if size is None:
            return None
        size_int = int(size)
        return size_int if size_int > 0 else None
    except Exception:
        return None

# --------------------------------------------------------------------
# DEBUG CONTROL
# --------------------------------------------------------------------
@mcp.tool()
def run(pass_exceptions=False, swallow_exceptions=False) -> bool:
    """
    Run or resume execution of the debuggee (x86 or x64). This call blocks until the
    debuggee is in the running state.

    When to use:
        - After setting breakpoints, patching memory, or stepping, to continue
          program execution.
        - After handling an exception (e.g., access violation) to decide whether
          to pass it to the program or swallow it so execution continues.

    Args:
        pass_exceptions (bool | str): If True, first-chance exceptions are passed
            to the debuggee (the program’s own handler can see them). If False,
            the debugger handles them.
            Accepts common string booleans, e.g. "true"/"false", "1"/"0", "yes"/"no".
        swallow_exceptions (bool | str): If True, exceptions are swallowed so the
            debuggee keeps running automatically; if False, exceptions will break
            into the debugger as usual.
            Accepts common string booleans, e.g. "true"/"false", "1"/"0", "yes"/"no".

    Returns:
        bool: True if the resume request was successfully issued and the debuggee
        transitioned to the running state; False otherwise (e.g., not attached,
        target already running, or an underlying API error).

    Typical patterns:
            # Let program handle its own exceptions
            go(pass_exceptions=True, swallow_exceptions=False)

            # Keep running through noisy first-chance exceptions (e.g., SEH probes)
            go(pass_exceptions=False, swallow_exceptions=True)
    """

    def _to_bool(v):
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
        # Fallback: Python truthiness (e.g., non-empty -> True)
        return bool(v)

    pe = _to_bool(pass_exceptions)
    se = _to_bool(swallow_exceptions)

    try:
        # Underlying client call (works for both x86/x64 debuggee sessions)
        ok = debugger.go(pass_exceptions=pe, swallow_exceptions=se)
        return bool(ok)
    except Exception:
        # Keep the tool contract simple: return False on failure
        return False

@mcp.tool()
def step_into(
    step_count=1,
    pass_exceptions=False,
    swallow_exceptions=False,
    wait_for_ready=True,
    wait_timeout=2
) -> bool:
    """
    Step INTO N instructions (x86/x64), optionally controlling first-chance exception
    behavior and whether to block until the debugger is stopped.

    When to use:
        - Classic “Step Into” behavior to enter CALL targets and walk through callee code.
        - Fine-grained tracing of control flow where you need to observe each instruction.
        - Investigations where library/user calls must be entered (vs. stepped over).

    Parameters:
        step_count (int | str, default=1):
            Number of single-step-into operations to perform. Accepts decimal or hex
            strings (e.g., 1, "3", "0x10"). Values <= 0 are coerced to 1.

        pass_exceptions (bool | str, default=False):
            If True, pass first-chance exceptions to the debugee (its own handler can
            see them). Accepts "true"/"1"/"yes" etc.

        swallow_exceptions (bool | str, default=False):
            If True, swallow first-chance exceptions so stepping won’t stop on them.
            Accepts common truthy/falsey strings.
            NOTE: cannot be True at the same time as pass_exceptions.

        wait_for_ready (bool | str, default=True):
            If True, block until the debugger reaches a **stopped** state after the step(s).

        wait_timeout (int | str, default=2):
            Maximum seconds to wait while blocking for the debugger to stop. Accepts
            decimal or hex strings; values < 1 are coerced to 1.

    Returns:
        bool:
            True if the stepping request was successfully issued (and, if waiting,
            the debugger reported a stop in time); False otherwise.

    Raises:
        ValueError:
            If both pass_exceptions and swallow_exceptions are True.
    """
    # --- helpers for input normalization (match style in other tools) ---
    def _to_bool(v):
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
        return bool(v)

    def _to_int(v, default):
        try:
            return int(v, 0) if isinstance(v, str) else int(v)
        except Exception:
            return default

    pe = _to_bool(pass_exceptions)
    se = _to_bool(swallow_exceptions)
    if pe and se:
        raise ValueError("Cannot pass and swallow exceptions at the same time")

    sc = _to_int(step_count, 1)
    if sc <= 0:
        sc = 1

    wf = _to_bool(wait_for_ready)
    wt = _to_int(wait_timeout, 2)
    if wt < 1:
        wt = 1

    try:
        ok = debugger.stepi(
            step_count=sc,
            pass_exceptions=pe,
            swallow_exceptions=se,
            wait_for_ready=wf,
            wait_timeout=wt,
        )
        return bool(ok)
    except Exception:
        return False


@mcp.tool()
def step_over(
    step_count=1,
    pass_exceptions=False,
    swallow_exceptions=False,
    wait_for_ready=True,
    wait_timeout=2
) -> bool:
    """
    Step OVER N instructions (x86/x64), optionally controlling first-chance exception
    behavior and whether to block until the debugger is stopped.

    When to use:
        - Classic “Step Over” behavior to execute CALLs without entering the callee.
        - Walk forward across inlineable helpers or library calls you don’t need to trace.
        - Coarse-grained tracing when you only need to advance over the next N instructions.

    Parameters:
        step_count (int | str, default=1):
            Number of single-step-over operations to perform. Accepts decimal or hex
            strings (e.g., 1, "3", "0x10"). Values <= 0 are coerced to 1.

        pass_exceptions (bool | str, default=False):
            If True, pass first-chance exceptions to the debugee (so its own handler
            can see them). Accepts "true"/"1"/"yes" etc.

        swallow_exceptions (bool | str, default=False):
            If True, swallow first-chance exceptions so stepping won’t stop on them.
            Accepts common truthy/falsey strings.
            NOTE: cannot be True at the same time as pass_exceptions.

        wait_for_ready (bool | str, default=True):
            If True, block until the debugger reaches a **stopped** state after the step(s).

        wait_timeout (int | str, default=2):
            Maximum seconds to wait while blocking for the debugger to stop. Accepts
            decimal or hex strings; values < 1 are coerced to 1.

    Returns:
        bool:
            True if the stepping request was successfully issued (and, if waiting,
            the debugger reported a stop in time); False otherwise.

    Raises:
        ValueError:
            If both pass_exceptions and swallow_exceptions are True.
    """
    # --- helpers for input normalization (match style in other tools) ---
    def _to_bool(v):
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
        return bool(v)

    def _to_int(v, default):
        try:
            return int(v, 0) if isinstance(v, str) else int(v)
        except Exception:
            return default

    pe = _to_bool(pass_exceptions)
    se = _to_bool(swallow_exceptions)
    if pe and se:
        raise ValueError("Cannot pass and swallow exceptions at the same time")

    sc = _to_int(step_count, 1)
    if sc <= 0:
        sc = 1

    wf = _to_bool(wait_for_ready)
    wt = _to_int(wait_timeout, 2)
    if wt < 1:
        wt = 1

    try:
        ok = debugger.stepo(
            step_count=sc,
            pass_exceptions=pe,
            swallow_exceptions=se,
            wait_for_ready=wf,
            wait_timeout=wt,
        )
        return bool(ok)
    except Exception:
        # Keep the tool contract simple & robust: return False on failure.
        return False


@mcp.tool()
def step_until_ret(frames=1, wait_timeout=10) -> bool:
    """
    Run until return from the current (or a higher) stack frame (x86/x64).

    When to use:
        - After stepping into a function and you want to continue execution
          until that function returns (classic "Run to return").
        - When you want to unwind multiple frames (e.g., return from a callee
          and its caller) without single-stepping or placing manual temp BPs.

    Parameters:
        frames (int | str, default=1):
            How many returns to wait for before stopping.
            - 1  => return from the current function
            - 2  => return from the caller of the current function
            - N  => unwind N stack frames
            Accepts decimal or hex strings (e.g., 2, "2", "0x2").
            Values <= 0 will be coerced to 1.

        wait_timeout (int | str, default=10):
            Maximum seconds to wait for the debugger to reach the stop state
            after issuing the run-until-return request. Accepts decimal or
            hex strings (e.g., 10, "10", "0xA"). Values < 1 are coerced to 1.

    Returns:
        bool:
            True if the operation was issued successfully and the debugger
            reported a stop within the specified timeout, otherwise False.

    Examples:
        # Return from the current function
        step_until_ret()

        # Return two frames (callee and its caller)
        step_until_ret(frames=2)

        # Custom timeout (hex accepted)
        step_until_ret(frames="0x1", wait_timeout="0x14")  # 20s
    """
    def _to_int(v, default):
        try:
            return int(v, 0) if isinstance(v, str) else int(v)
        except Exception:
            return default

    f = _to_int(frames, 1)
    if f <= 0:
        f = 1

    wt = _to_int(wait_timeout, 10)
    if wt < 1:
        wt = 1

    try:
        # Underlying high-level client API handles both archs and waiting.
        ok = debugger.ret(frames=f, wait_timeout=wt)
        return bool(ok)
    except Exception:
        return False

@mcp.tool()
def get_latest_debug_event() -> dict | None:
    """
    Get the most recent debug event from the debugee and remove it from the
    internal event queue (works with both x32 and x64 debuggers).

    When to use:
        - After run/step/command operations to observe what stopped the debugger
          (e.g., breakpoint hit, exception, DLL load, thread create/exit, etc.).
        - In polling loops to consume one event at a time from the queue.

    Parameters:
        None (assumes a debugger has already been selected via select_debugger()
        and a session is attached/started).

    Returns:
        dict | None:
            A JSON-serializable dictionary with:
                {
                    "event_type": str,     # One of EventType.* strings
                    "event_data": dict     # Shape depends on event_type
                }
            or None if no event is available.

        Event types (EventType):
            - "EVENT_BREAKPOINT"
            - "EVENT_SYSTEMBREAKPOINT"
            - "EVENT_CREATE_THREAD"
            - "EVENT_EXIT_THREAD"
            - "EVENT_LOAD_DLL"
            - "EVENT_UNLOAD_DLL"
            - "EVENT_OUTPUT_DEBUG_STRING"
            - "EVENT_EXCEPTION"

        Notes:
            • Each call pops exactly one event from the queue (if any).
            • The tool returns plain JSON; complex event_data objects are flattened
              via attribute inspection so they can be consumed by clients directly.
            • Works uniformly for x32 and x64 sessions (based on the global `debugger`).

    Examples:
        ev = get_latest_debug_event()
        if ev and ev["event_type"] == "EVENT_BREAKPOINT":
            bp = ev["event_data"]
            # e.g., bp["addr"], bp["name"], bp["hitCount"], ...
    """

    try:
        ev = debugger.get_latest_debug_event()
    except Exception as ex:
        return {"error": f"{type(ex).__name__}: {ex}"}

    if not ev:
        return None

    def _to_plain(o):
        # Simple JSON-ifier that turns dataclass/objects into dicts, recursively.
        if o is None or isinstance(o, (bool, int, float, str)):
            return o
        if isinstance(o, (list, tuple)):
            return [_to_plain(x) for x in o]
        if isinstance(o, dict):
            return {k: _to_plain(v) for k, v in o.items()}
        # Fall back to attributes for model objects (e.g., BreakpointEventData, etc.)
        d = getattr(o, "__dict__", None)
        if isinstance(d, dict):
            return {k: _to_plain(v) for k, v in d.items()}
        # Last resort: string representation
        return str(o)

    return {
        "event_type": getattr(ev, "event_type", None),
        "event_data": _to_plain(getattr(ev, "event_data", None)),
    }

@mcp.tool()
def is_running() -> bool:
    """
    Check whether the current debugee is in the **running** state.

    When to use:
        - After issuing run/step commands to decide if execution is still flowing
          or if you should wait/handle a stop event.
        - In polling loops (e.g., wait until stopped) to gate actions that require
          a paused debugger (reading/writing memory, inspecting state, etc.).
        - As a quick health check to branch logic between "running" vs "stopped".

    Parameters:
        None

    Returns:
        bool:
            True  -> The debugee is currently **running**.
            False -> The debugee is **not running** (paused/stopped), or an error
                     occurred.
    """
    try:
        return bool(debugger.is_running())
    except Exception:
        # Keep the tool contract simple/robust: False on any failure.
        return False
    
@mcp.tool()
def pause() -> bool:
    """
    Pause the current debuggee (x86/x64) and block until the debugger is in the
    **stopped** state.

    When to use:
        - You need to interrupt a running program (e.g., to inspect registers,
          memory, stacks, or to set/adjust breakpoints).
        - You want to stop a long "Run"/trace/animation loop immediately.
        - Prior to actions that require a paused debugger state (safe memory writes,
          stable disassembly around RIP/EIP, etc.).

    Parameters:
        None 

    Returns:
        bool:
            True  -> The pause request was issued successfully and the debugger
                     reached a stopped state.
            False -> The request failed (e.g., no session, transport error) or
                     the debugger did not acknowledge the command.
    """
    try:
        # Use high-level pause if the client provides it
        if hasattr(debugger, "pause"):
            return bool(debugger.pause())
        return False
    except Exception:
        # Keep tool contract simple & robust.
        return False

# --------------------------------------------------------------------
# BREAKPOINTS
# --------------------------------------------------------------------
@mcp.tool()
def get_breakpoints(bp_type) -> list[dict]:
    """
    Retrieve breakpoints from the active x64dbg session (x86/x64) as JSON-friendly dicts.

    Parameters:
        bp_type : int | str
            The breakpoint category to fetch. Accepts:
            • Integer/hex values matching BreakpointType (1=Normal, 2=Hardware, 4=Memory, 8=Dll, 16=Exception)
            • Case-insensitive strings:
                    "normal", "software", "soft", "sw"
                    "hardware", "hw"
                    "memory", "mem"
                    "dll"
                    "exception", "exc", "seh"
            • "all" — convenience option to return all types (union of Normal, Hardware, Memory, Dll, Exception)

    Returns:
        list[dict]
            A list of dictionaries, one per breakpoint, with fields:
                {
                "type": int,                 # BreakpointType value (e.g., 1, 2, 4, 8, 16)
                "type_name": str,            # BreakpointType name (e.g., "BpNormal")
                "addr": int,                 # address as integer
                "addr_hex": str,             # address as hex, e.g., "0x7FF6C0..."
                "enabled": bool,
                "singleshoot": bool,
                "active": bool,
                "name": str,
                "mod": str,
                "slot": int,
                "typeEx": int,
                "hwSize": int,
                "hitCount": int,
                "fastResume": bool,
                "silent": bool,
                "breakCondition": str,
                "logText": str,
                "logCondition": str,
                "commandText": str,
                "commandCondition": str
                }

    When to use:
        Call after setting/toggling/clearing breakpoints to enumerate current state; or poll it
        before resuming to verify BPs are armed as expected.
    """
    # --- normalize bp_type into BreakpointType or list thereof ---
    def _normalize_bp_type(v):
        if isinstance(v, int):
            return [BreakpointType(v)]
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("all", "*"):
                return [BreakpointType.BpNormal,
                        BreakpointType.BpHardware,
                        BreakpointType.BpMemory,
                        BreakpointType.BpDll,
                        BreakpointType.BpException]
            aliases = {
                "normal": BreakpointType.BpNormal,
                "software": BreakpointType.BpNormal,
                "soft": BreakpointType.BpNormal,
                "sw": BreakpointType.BpNormal,
                "hardware": BreakpointType.BpHardware,
                "hw": BreakpointType.BpHardware,
                "memory": BreakpointType.BpMemory,
                "mem": BreakpointType.BpMemory,
                "dll": BreakpointType.BpDll,
                "exception": BreakpointType.BpException,
                "exc": BreakpointType.BpException,
                "seh": BreakpointType.BpException,
            }
            if s in aliases:
                return [aliases[s]]
            # allow numeric strings like "1", "0x10"
            try:
                return [BreakpointType(int(s, 0))]
            except Exception:
                pass
        raise ValueError("bp_type must be a BreakpointType int/hex or one of: "
                         "normal/software, hardware, memory, dll, exception, all")

    types = _normalize_bp_type(bp_type)

    # --- fetch & flatten ---
    def _bp_to_dict(b: Breakpoint) -> dict:
        return {
            "type": int(b.type),
            "type_name": getattr(b.type, "name", str(b.type)),
            "addr": b.addr,
            "addr_hex": f"0x{b.addr:X}",
            "enabled": b.enabled,
            "singleshoot": b.singleshoot,
            "active": b.active,
            "name": b.name,
            "mod": b.mod,
            "slot": b.slot,
            "typeEx": b.typeEx,
            "hwSize": b.hwSize,
            "hitCount": b.hitCount,
            "fastResume": b.fastResume,
            "silent": b.silent,
            "breakCondition": b.breakCondition,
            "logText": b.logText,
            "logCondition": b.logCondition,
            "commandText": b.commandText,
            "commandCondition": b.commandCondition,
        }

    results: list[dict] = []
    try:
        for t in types:
            bps = debugger.get_breakpoints(t)  # returns list[Breakpoint] per API
            if bps:
                results.extend(_bp_to_dict(b) for b in bps)
    except Exception as ex:
        return [{"error": f"{type(ex).__name__}: {ex}"}]

    return results

@mcp.tool()
def set_breakpoint(address_or_symbol, name: str | None = None,
                   bp_type: StandardBreakpointType = StandardBreakpointType.Short,
                   singleshoot: bool = False) -> bool:
    """
    Set a standard (software) breakpoint in the current debug session.

    Parameters:
        address_or_symbol : int | str
            Target location for the breakpoint. Accepts:
            - int (e.g., 0x401000)
            - numeric string (e.g., "0x401000" or "4198400")
            - symbol/expression resolvable by x64dbg (e.g., "kernel32!LoadLibraryA",
            "GetModuleHandleA+0x10", "rip+5", "module.base()+0x1234").
            If a non-numeric string is provided, it is passed through as an expression.

        name : str | None, optional
            Optional label for the breakpoint as shown in x64dbg’s Breakpoints view.
            If omitted, the client will derive a name (e.g., "bpx_<addr_or_symbol>").

        bp_type : StandardBreakpointType, optional
            Encoding of the software breakpoint. Valid values:
            - StandardBreakpointType.Short  -> INT3 (CC, 1 byte)  [default]
            - StandardBreakpointType.Long   -> CD03 (2 bytes)
            - StandardBreakpointType.Ud2    -> UD2 (0F0B, 2 bytes)
            - StandardBreakpointType.SingleShotInt3 -> Single-shot INT3
            Note: You can also pass a case-insensitive string alias: "short", "long", "ud2", "ss".
            Aliases are coerced to the enum before calling the client.

        singleshoot : bool, optional
            If True, sets the breakpoint as single-shot (auto-removed on first hit).

    Returns:
        bool
            True on success, False on failure.

    When to use:
        Use this to stop on function entries, instruction addresses, or any expression
        x64dbg can evaluate.
    """

    # Coerce singleshoot to bool (accept common truthy/falsey strings)
    def _to_bool(v) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
        return bool(v)

    # Accept string aliases for bp_type and normalize to StandardBreakpointType
    def _normalize_bp_type(t) -> StandardBreakpointType:
        if isinstance(t, StandardBreakpointType):
            return t
        if isinstance(t, str):
            s = t.strip().lower()
            if s in ("short",):
                return StandardBreakpointType.Short
            if s in ("long",):
                return StandardBreakpointType.Long
            if s in ("ud2",):
                return StandardBreakpointType.Ud2
            if s in ("ss", "singleshot", "single", "singleshotint3"):
                return StandardBreakpointType.SingleShotInt3
        # Fallback
        return StandardBreakpointType.Short

    # Try to parse numeric strings to int; pass through symbolic expressions verbatim
    target = address_or_symbol
    if isinstance(address_or_symbol, str):
        s = address_or_symbol.strip()
        try:
            target = int(s, 0)  # "0x...", decimal, etc.
        except Exception:
            target = s  # keep as expression/symbol

    enum_type = _normalize_bp_type(bp_type)
    single = _to_bool(singleshoot) or (enum_type == StandardBreakpointType.SingleShotInt3)

    try:
        return bool(debugger.set_breakpoint(target, name=name, bp_type=enum_type, singleshoot=single))
    except Exception:
        return False

@mcp.tool()
def set_hardware_breakpoint(address_or_symbol,
                            bp_type: HardwareBreakpointType = HardwareBreakpointType.x,
                            size=1) -> bool:
    """
    Set a hardware breakpoint at an address or symbol (works with x32 & x64).

    Parameters:
        address_or_symbol : int | str
            - Integer address (e.g., 0x401000 or "0x401000" or "4198400"), or
            - A symbol/expression resolvable by x64dbg (e.g., "kernel32!LoadLibraryA",
            "GetModuleHandleA+0x10", "rip+5", "module.base()+0x1234").
            Numeric-looking strings are parsed to int; other strings are passed through.

        bp_type : HardwareBreakpointType | str
            Hardware breakpoint type:
            • r  -> read/write
            • w  -> write
            • x  -> execute    (default)
            Accepts the enum or case-insensitive string {"r","w","x"}.

        size : int | str
            Breakpoint byte size. One of {1, 2, 4, 8}. Note: 8 is valid on x64 only.
            Strings like "0x8" are accepted. The address must be aligned to `size`
            when an integer address is provided.

    Returns:
        bool
            True on success; False on invalid inputs or underlying client failure.

    When to use:
        Use hardware breakpoints to watch instruction execution (`x`) or data access
        (`r`/`w`) without modifying code bytes, or where software INT3 isn’t suitable
        (e.g., read/write watchpoints or self-checking code).
    """

    # --- normalize size ---
    try:
        s = int(size, 0) if isinstance(size, str) else int(size)
    except Exception:
        return False
    if s not in (1, 2, 4, 8):
        return False
    # 8-byte hardware BPs are only valid on x64
    if s == 8 and debugger == x32client:
        return False

    # --- normalize bp_type ---
    try:
        if isinstance(bp_type, str):
            bp_type_norm = HardwareBreakpointType(bp_type.lower())
        else:
            bp_type_norm = bp_type
    except Exception:
        return False

    # --- normalize address_or_symbol ---
    target = address_or_symbol
    if isinstance(address_or_symbol, str):
        stripped = address_or_symbol.strip()
        try:
            # Numeric-like string -> int; others remain symbolic
            target = int(stripped, 0)
        except Exception:
            target = stripped

    # --- alignment check for concrete integer addresses ---
    if isinstance(target, int) and (target % s) != 0:
        return False

    try:
        return bool(debugger.set_hardware_breakpoint(target, bp_type=bp_type_norm, size=s))
    except Exception:
        return False

@mcp.tool()
def set_memory_breakpoint(
    address_or_symbol,
    bp_type: MemoryBreakpointType = MemoryBreakpointType.a,
    singleshoot: bool = False
) -> bool:
    """
    Set a MEMORY (GUARD_PAGE) breakpoint at an address or resolvable symbol/expression.
    Works with both x32dbg and x64dbg sessions (assumes `select_debugger()` already set `debugger`).

    Parameters:    
        address_or_symbol : int | str
            Where to break. Accepts:
            • Integer address (e.g., 0x401000 or "0x401000" or "4198400")
            • Symbol/expression x64dbg can resolve (e.g., "kernel32!VirtualAlloc", "GetModuleHandleA+0x10",
                "rip+5", "module.base()+0x1234"). Numeric-looking strings are parsed to int; other strings are
                passed through verbatim.

        bp_type : MemoryBreakpointType | str, default=MemoryBreakpointType.a
            Access type to watch:
            • 'r' -> read
            • 'w' -> write
            • 'x' -> execute
            • 'a' -> all (read+write+execute, default)
            You can pass the enum or the case-insensitive single-letter string.

        singleshoot : bool | str, default=False
            If True, create a single-shot memory breakpoint (auto-removed on first hit).
            Accepts common truthy/falsey strings like "1"/"0", "true"/"false", "yes"/"no".

    Returns:
        bool
            True on success, False on failure (e.g., invalid inputs, no debugger selected, underlying API error).

    When to use:
        Use memory breakpoints to trap data/Code access without modifying bytes (e.g., watch a buffer read/write,
        or catch execute on a region). 
    """

    # --- normalize singleshoot to bool ---
    def _to_bool(v) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
        return bool(v)

    # --- normalize bp_type (enum or single-letter string) ---
    try:
        if isinstance(bp_type, str):
            bp_enum = MemoryBreakpointType(bp_type.lower())
        else:
            bp_enum = bp_type
    except Exception:
        return False

    # --- normalize address_or_symbol ---
    target = address_or_symbol
    if isinstance(address_or_symbol, str):
        s = address_or_symbol.strip()
        try:
            target = int(s, 0)  # parse hex/dec if it's numeric-like
        except Exception:
            target = s          # keep symbolic/expression forms as-is

    single = _to_bool(singleshoot)

    try:
        return bool(debugger.set_memory_breakpoint(target, bp_type=bp_enum, singleshoot=single))
    except Exception:
        return False

@mcp.tool()
def clear_breakpoint(address_name_symbol_or_none: int | str | None = None) -> bool:
    """
    Clear a software breakpoint (INT3/UD2/CD03) by address, name, or symbol.

    Parameters:
        address_name_symbol_or_none : int | str | None
            • int / numeric string (e.g., 0x401000, "0x401000", "4198400") → clears the BP at that address  
            • non-numeric string (e.g., "kernel32!CreateFileW", "MyBreakpointName") → clears by symbol/name  
            • None → clears **all** software breakpoints

    Returns:
        bool
            True on success; False otherwise.

    When to use:
        Use after you no longer need a software breakpoint (e.g., to avoid re-breaking on the same site),
        or to quickly remove all software breakpoints before a clean run.

    Notes:
        Numeric-looking strings are parsed to integers; other strings are passed through as expressions.
    """
    try:
        target = address_name_symbol_or_none
        if isinstance(target, str):
            s = target.strip()
            try:
                target = int(s, 0)  # parse "0x..." or decimal strings
            except Exception:
                # keep symbolic/name strings as-is
                target = s
        # Delegate to the client; it handles None (clear all) vs int vs str
        return bool(debugger.clear_breakpoint(target))
    except Exception:
        return False

@mcp.tool()
def clear_hardware_breakpoint(address_symbol_or_none=None) -> bool:
    """
    Clear a hardware breakpoint by address or symbol; clear all when None.

    Parameters:
        address_symbol_or_none : int | str | None, default=None
            • int / numeric string (e.g., 0x401000, "0x401000", "4198400") → clears the HWBP at that address
            • non-numeric string (e.g., "kernel32!CreateFileW", "MyBreakpointName") → clears by symbol/name
            • None → clears **all** hardware breakpoints

    Returns:
        bool
            True on success; False otherwise.

    When to use:
        Use this after you no longer need a hardware watchpoint (execute/read/write),
        or to quickly remove all HWPBs before a clean run.
    """
    try:
        target = address_symbol_or_none
        if isinstance(target, str):
            s = target.strip()
            try:
                target = int(s, 0)  # parse "0x..." or decimal strings
            except Exception:
                # keep symbolic/name strings as-is
                target = s

        return bool(debugger.clear_hardware_breakpoint(target))
    except Exception:
        return False
    
@mcp.tool()
def clear_memory_breakpoint(address_symbol_or_none=None) -> bool:
    """
    Clear a memory breakpoint by address or symbol; clear all when None.

    Parameters:
        address_symbol_or_none : int | str | None, default=None
            • int / numeric string (e.g., 0x401000, "0x401000", "4198400") → clears the memory BP at that address
            • non-numeric string (e.g., "kernel32!CreateFileW", "MyBpName") → clears by symbol/name
            • None → clears **all** memory breakpoints

    Returns:
        bool
            True on success; False otherwise.

    When to use:
        Use after you no longer need a memory watchpoint (read/write/execute),
        or to quickly remove all memory breakpoints before a clean run.
    """
    try:
        target = address_symbol_or_none
        if isinstance(target, str):
            s = target.strip()
            try:
                target = int(s, 0)  # parse "0x..." or decimal strings
            except Exception:
                target = s          # keep symbolic/name strings as-is

        return bool(debugger.clear_memory_breakpoint(target))
    except Exception:
        return False

@mcp.tool()
def toggle_breakpoint(address_name_symbol_or_none: int | str | None = None, on: bool = True) -> bool:
    """
    Enable or disable one or more **software** breakpoints (x86/x64).

    Parameters:
        address_name_symbol_or_none : int | str | None
            Target to toggle. Accepts:
            • int (e.g., 0x401000)
            • numeric string (e.g., "0x401000" or "4198400")
            • name/symbol/expression resolvable by x64dbg (e.g., "kernel32!LoadLibraryA",
                "GetModuleHandleA+0x10", "rip+5", "module.base()+0x1234")
            • None → apply to **all** software breakpoints (per upstream API)

        on : bool | str
            True to **enable** (bpe), False to **disable** (bpd).
            Common truthy/falsey strings are accepted ("true"/"false", "1"/"0", "yes"/"no", etc).

    Returns:
        bool
            True on success, False on failure.

    When to use:
        Use this to quickly arm/disarm software breakpoints that already exist, or to
        mass-enable/disable all software breakpoints when `address_name_symbol_or_none` is None.
    """

    # normalize booleans similar to other tools
    def _to_bool(v) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
        return bool(v)

    on_flag = _to_bool(on)

    # normalize the address/name/symbol argument
    target = address_name_symbol_or_none
    if isinstance(target, str):
        s = target.strip()
        try:
            # numeric-looking strings become ints; symbolic expressions are passed through
            target = int(s, 0)
        except Exception:
            target = s  # keep expression/name as-is

    try:
        return bool(debugger.toggle_breakpoint(target, on=on_flag))
    except Exception:
        return False

@mcp.tool()
def toggle_hardware_breakpoint(address_symbol_or_none=None, on=True) -> bool:
    """
    Toggle (enable/disable) one or more hardware breakpoints in the active x32/x64 session.

    Parameters:
        address_symbol_or_none (int | str | None)
            • Integer address (e.g., 0x401000 or "0x401000"), or
            • A symbol / expression resolvable by x64dbg (e.g., "kernel32!LoadLibraryA",
              "GetModuleHandleA+0x10", "rip+5"), or
            • None -> apply to ALL hardware breakpoints (enable or disable them all).
            Numeric-looking strings are parsed to int; other strings are passed through.

        on (bool | str)
            True  -> enable the specified hardware breakpoint(s).
            False -> disable the specified hardware breakpoint(s).
            Common truthy/falsey strings are accepted ("true"/"false", "1"/"0", "yes"/"no", etc).

    Returns:
        bool
            True on success, False on failure (e.g., invalid args or underlying client error).

    When to use:
        Use this to quickly enable/disable an existing hardware breakpoint by address/symbol,
        or to bulk enable/disable all hardware breakpoints at once (pass None).
        This does NOT place or remove breakpoints;
        for that, use set_hardware_breakpoint() / clear_hardware_breakpoint().

    Notes:
        The address must satisfy the size/alignment constraints of the original hardware BP.
    """
    # normalize 'on' to a bool (accept strings)
    def _to_bool(v):
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
        return bool(v)

    on_bool = _to_bool(on)

    # normalize the target: parse numeric strings, otherwise pass symbolic text through
    target = address_symbol_or_none
    if isinstance(address_symbol_or_none, str):
        s = address_symbol_or_none.strip()
        try:
            target = int(s, 0)  # handles "0x..." or decimal
        except Exception:
            target = s  # keep as expression/symbol
    # None is allowed and means "all"

    try:
        return bool(debugger.toggle_hardware_breakpoint(target, on_bool))
    except Exception:
        return False

@mcp.tool()
def toggle_memory_breakpoint(address_symbol_or_none=None, on=True) -> bool:
    """
    Toggle (enable/disable) one or more **memory (GUARD_PAGE)** breakpoints in the
    active x32/x64 session.

    Parameters:
        address_symbol_or_none : int | str | None
            Target to toggle. Accepts:
            • int (e.g., 0x401000)
            • numeric string (e.g., "0x401000" or "4198400")
            • symbol/expression resolvable by x64dbg (e.g., "kernel32!VirtualAlloc",
              "GetModuleHandleA+0x10", "rip+5", "module.base()+0x1234")
            • None → apply to **all** memory breakpoints (per upstream API)

        on : bool | str (default=True)
            True  → enable the specified memory breakpoint(s) (bpme)
            False → disable the specified memory breakpoint(s) (bpmd)
            Common truthy/falsey strings are accepted ("true"/"false", "1"/"0",
            "yes"/"no", "on"/"off").

    Returns:
        bool
            True on success, False on failure (e.g., invalid input or underlying client error).

    When to use:
        Use this to quickly arm/disarm existing memory watchpoints by address/symbol,
        or to bulk enable/disable all memory breakpoints (pass None).
        This does **not** create or remove breakpoints; use set_memory_breakpoint() /
        clear_memory_breakpoint() for that.
    """
    # normalize 'on' to a bool (accept common strings)
    def _to_bool(v) -> bool:
        if isinstance(v, bool):
            return v
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("1", "true", "yes", "y", "on"):
                return True
            if s in ("0", "false", "no", "n", "off"):
                return False
        return bool(v)

    on_flag = _to_bool(on)

    # normalize the address/symbol argument
    target = address_symbol_or_none
    if isinstance(target, str):
        s = target.strip()
        try:
            # numeric-looking strings become ints; symbolic expressions are passed through
            target = int(s, 0)
        except Exception:
            target = s

    try:
        # delegate to the high-level client (internally maps to bpme/bpmd)
        return bool(debugger.toggle_memory_breakpoint(target, on=on_flag))
    except Exception:
        return False

# --------------------------------------------------------------------
# ANNOTATIONS (COMMENTS and LABELS)
# --------------------------------------------------------------------
@mcp.tool()
def set_comment_at(address, text) -> bool:
    """
    Set a comment at a specific address in the current x64dbg session.

    Parameters:
        address (int | str):
            The absolute address where the comment should be placed. Accepts an int
            (e.g., 0x401000) or a numeric string in decimal/hex form (e.g., "4198400",
            "0x401000"). If you need to compute an address from an expression like
            "rsp + 0x20" or a symbol, first resolve it with `eval_sync()` and then pass
            the resulting integer address here.

        text (str):
            The comment text to set at the address. The underlying x64dbg automate API
            does not permit double quotes (\"\") in the text. If a double quote is present,
            this tool will return False. Consider replacing double quotes with single quotes
            before calling.

    Returns:
        bool: True on success, False on failure.

    When to use:
        Use this tool to annotate code/data at a given address with a descriptive comment—
        e.g., documenting a function prologue, marking a decoded string location, or noting
        parameter meanings at a call site. 
    """
    # --- Normalize/validate inputs ---
    try:
        a = int(address, 0) if isinstance(address, str) else int(address)
    except (TypeError, ValueError):
        return False

    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return False

    # x64dbg automate (annotations API) forbids double quotes in the comment text
    if '"' in text:
        return False

    try:
        return bool(debugger.set_comment_at(a, text))
    except Exception:
        return False

@mcp.tool()
def del_comment_at(address) -> bool:
    """
    Delete the comment at a specific address.

    Parameters:
        address (int | str)
            The absolute address whose comment should be removed.
            Accepts an int (e.g., 0x401000) or a numeric string in decimal/hex
            form (e.g., "4198400", "0x401000").
            If you need to compute an effective address from an expression
            (e.g., "rsp + 0x20") or a symbol, resolve it first with eval_sync()
            and pass the resulting integer here.

    Returns:
        bool
            True on success; False on invalid input or underlying client error.

    When to use:
        Call this to clear previously set annotations when cleaning up analysis,
        removing outdated notes, or preparing a region for fresh labeling/comments.
    """
    try:
        a = int(address, 0) if isinstance(address, str) else int(address)
    except (TypeError, ValueError):
        return False

    try:
        return bool(debugger.del_comment_at(a))
    except Exception:
        return False

@mcp.tool()
def get_comment_at(addr) -> str:
    """
    Retrieve the comment text at a specific address.

    Args:
        addr: Address to query for a comment. Accepts int (e.g., 0x401000) or
              str with auto-detected base (e.g., "0x401000", "4198400").

    Returns:
        str
            The comment string if a comment exists at the address; otherwise
            an empty string "".

    When to use:
        Use this to read an existing annotation/comment attached to an
        instruction or address in the current session. Typical cases include
        confirming a comment you previously set via set_comment_at(), or
        displaying annotations while browsing disassembly.
    """
    # Normalize address input (supports int or numeric strings like "0x401000")
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        # Contract mirrors upstream: return empty string on failure / invalid input
        return ""

    try:
        comment = debugger.get_comment_at(a)
    except Exception:
        return ""

    return comment or ""

@mcp.tool()
def set_label_at(address, text) -> bool:
    """
    Set a label at a specific address in the current x64dbg session.

    Parameters:
        address (int | str):
            The absolute address where the label should be placed. Accepts an int
            (e.g., 0x401000) or a numeric string in decimal/hex form (e.g., "4198400",
            "0x401000"). If you need to compute an address from an expression like
            "rsp + 0x20" or a symbol, first resolve it with eval_sync() and then pass
            the resulting integer address here.

        text (str):
            The label text to set at the address. Per the x64dbg-automate Annotations API,
            the text cannot contain a double quote ("). If a double quote is present,
            this tool returns False. Consider replacing double quotes with single quotes
            before calling.

    Returns:
        bool: True on success, False on failure.

    When to use:
        Use this tool to create a symbolic label for an address to make navigation,
        cross-references, and disassembly browsing easier (e.g., naming function starts,
        jump targets, or important data locations).
    """
    # --- Normalize/validate inputs (match style of set_comment_at) ---
    try:
        a = int(address, 0) if isinstance(address, str) else int(address)
    except (TypeError, ValueError):
        return False

    if not isinstance(text, str):
        try:
            text = str(text)
        except Exception:
            return False

    # The upstream API forbids double quotes in the label text
    if '"' in text:
        return False

    try:
        return bool(debugger.set_label_at(a, text))
    except Exception:
        return False

@mcp.tool()
def del_label_at(address) -> bool:
    """
    Delete the label at a specific address.

    Parameters:
        address (int | str)
            The absolute address whose label should be removed.
            Accepts an int (e.g., 0x401000) or a numeric string in decimal/hex
            form (e.g., "4198400", "0x401000").
            If you need to compute an effective address from an expression
            (e.g., "rsp + 0x20") or a symbol, resolve it first with eval_sync()
            and pass the resulting integer here.

    Returns:
        bool
            True on success; False on invalid input or underlying client error.

    When to use:
        Use this to clear labels you previously set (e.g., temporary waypoints
        during analysis)
    """
    # Normalize the address (supports int or numeric strings like "0x401000")
    try:
        a = int(address, 0) if isinstance(address, str) else int(address)
    except (TypeError, ValueError):
        return False

    try:
        return bool(debugger.del_label_at(a))
    except Exception:
        return False

@mcp.tool()
def get_label_at(addr, segment_reg: SegmentReg = SegmentReg.SegDefault) -> str:
    """
    Retrieve the label text at a specific address (x86/x64), optionally using a
    specific segment register override.

    Parameters:
        addr (int | str)
            Address to query for a label. Accepts an int (e.g., 0x401000) or a
            numeric string in decimal/hex form (e.g., "4198400", "0x401000").
            If you need to compute an effective address from an expression
            (e.g., "rsp + 0x20") or a symbol, resolve it first with eval_sync()
            and pass the resulting integer here.

        segment_reg (SegmentReg, default=SegmentReg.SegDefault)
            Segment register to use for the label lookup. Typical values include:
            SegDefault, SegEs, SegDs, SegFs, SegGs, SegCs, SegSs.

    Returns:
        str
            The label string if a label exists at the address; otherwise
            an empty string "".

    When to use:
        Use this to read any label associated with an instruction or data address,
        e.g., to confirm labels placed with set_label_at(), inspect auto-labels,
        or display symbolic names while browsing disassembly.
    """
    # Normalize address input (supports int or numeric strings like "0x401000")
    try:
        a = int(addr, 0) if isinstance(addr, str) else int(addr)
    except (TypeError, ValueError):
        # Match get_comment_at() contract: return empty string on bad input
        return ""

    # Be forgiving: allow callers to pass ints/strings for the segment reg too.
    seg = segment_reg
    try:
        if isinstance(segment_reg, int):
            seg = SegmentReg(segment_reg)
        elif isinstance(segment_reg, str):
            # Accept names like "SegFs", "segfs", "FS", etc.
            s = segment_reg.strip().lower()
            aliases = {
                "segdefault": SegmentReg.SegDefault,
                "seges": SegmentReg.SegEs, "es": SegmentReg.SegEs,
                "segds": SegmentReg.SegDs, "ds": SegmentReg.SegDs,
                "segfs": SegmentReg.SegFs, "fs": SegmentReg.SegFs,
                "seggs": SegmentReg.SegGs, "gs": SegmentReg.SegGs,
                "segcs": SegmentReg.SegCs, "cs": SegmentReg.SegCs,
                "segss": SegmentReg.SegSs, "ss": SegmentReg.SegSs,
            }
            seg = aliases.get(s, SegmentReg.SegDefault)
    except Exception:
        seg = SegmentReg.SegDefault

    try:
        label = debugger.get_label_at(a, seg)
    except Exception:
        return ""

    return label or ""

# --------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------
@mcp.tool()
def gui_refresh_views() -> bool:
    """
    Refresh all x64dbg GUI views (x86/x64).

    Parameters:
        None

    Returns:
        bool
            True on success; False on failure.

    When to use:
        Call after programmatic changes (e.g., writing memory, assembling,
        setting/deleting comments or labels, toggling breakpoints) when you
        want the UI to reflect the latest state immediately. Also useful after
        temporarily disabling updates and then re-enabling them to force a
        manual refresh of views.
    """
    try:
        return bool(debugger.gui_refresh_views())
    except Exception:
        return False

@mcp.tool()
def log(fmt_str) -> int:
    """
    Logs a string to the x64dbg Log window (x86/x64).

    Parameters:
        fmt_str (str)
            format String to log. Accepts any value that can be converted to str.

    Returns:
        int
            1 on success; 0 on failure.

    When to use:
        Use this to emit diagnostic messages, computed values, or progress notes
        to x64dbg’s Log pane from automations/scripts. For example, after
        evaluating expressions or scanning memory, call log() to show results
        without interrupting control flow.
    """
    # Normalize to string (be liberal with input types)
    if not isinstance(fmt_str, str):
        try:
            fmt_str = str(fmt_str)
        except Exception:
            return 0

    try:
        # X64DbgClient.log(fmt_str) returns int | None per API; coerce to 1/0
        ret = debugger.log(fmt_str)
        return int(ret) if isinstance(ret, int) else (1 if ret else 0)
    except Exception:
        return 0


if __name__ == "__main__":
    # run locally
    mcp.run()
    # listen on all interfaces (LAN) on port 9628
    #mcp.run(transport="sse", host="0.0.0.0", port=9628)