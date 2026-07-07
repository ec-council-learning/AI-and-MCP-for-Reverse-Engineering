



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
    message = start_session("Hello World")
    print(message)