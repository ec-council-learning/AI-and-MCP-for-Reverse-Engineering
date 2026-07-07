from fastmcp import FastMCP

mcp = FastMCP("MCP_Automate_Server")

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