from fastmcp import FastMCP
from x64dbg_automate import X64DbgClient

mcp = FastMCP("MCP_Automate_Server")


x32client = X64DbgClient(r"C:\Program Files\x64dbg\release\x32\x32dbg.exe")
x64client = X64DbgClient(r"C:\Program Files\x64dbg\release\x64\x64dbg.exe")
debugger = None #select_debugger() will assign one of the above



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
    Get a single register

    Args:
        reg: Register to get
        (e.g. eax, ebx, ... or, rax, rbx, ... etc)
    
    Returns:
        str: the hex value stored in the register (e.g., '0x64ff84')
        with the '0x' prefix meant to indicate hex
    """
    value = debugger.get_reg(reg)
    return hex(value)

if __name__ == "__main__":
    mcp.run()