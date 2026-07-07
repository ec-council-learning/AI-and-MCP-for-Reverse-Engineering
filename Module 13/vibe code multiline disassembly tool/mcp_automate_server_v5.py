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
# DISASSEMBLING
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
    
if __name__ == "__main__":
    # run locally
    mcp.run()
    # listen on all interfaces (LAN) on port 9628
    #mcp.run(transport="sse", host="0.0.0.0", port=9628)