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
    before any session begins.

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
def start_session(greeting: str) -> str:
    """
    Sends a greeting

    Args:
        greeting: message to use for greeting

    Returns:
        str: The greeting message
    """
    return greeting


if __name__=="__main__":
    mcp.run()