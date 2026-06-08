import socket


COMMON_SUBDOMAINS = [
    "www",
    "api",
    "mail",
    "smtp",
    "dev",
    "test",
    "staging",
    "vpn",
    "admin",
    "portal",
]


def enumerate_subdomains(domain: str) -> list[dict]:
    """
    Resolve common subdomains.
    """

    discovered = []

    for subdomain in COMMON_SUBDOMAINS:
        hostname = f"{subdomain}.{domain}"

        try:
            ip = socket.gethostbyname(hostname)

            discovered.append(
                {
                    "hostname": hostname,
                    "ip": ip,
                }
            )

        except socket.gaierror:
            continue

    return discovered