import socket


def resolve_host(hostname: str) -> dict:
    """
    Resolve a hostname to an IP address.
    """

    result = {
        "hostname": hostname,
        "ip": None,
        "status": "unresolved",
    }

    try:
        result["ip"] = socket.gethostbyname(hostname)
        result["status"] = "resolved"

    except socket.gaierror:
        pass

    return result