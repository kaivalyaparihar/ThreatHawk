#backend\utils\ioc_type_detector.py

import re


# Regex patterns
IPV4_PATTERN = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")

EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)


def detect_ioc_type(ioc: str) -> str:
    """
    Detects the type of an IOC string.
    Returns: 'ip', 'domain', 'md5', 'sha1', 'sha256', 'email', or 'unknown'
    """
    ioc = ioc.strip()

    if IPV4_PATTERN.match(ioc):
        # Extra validation — each octet must be 0-255
        parts = ioc.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return "ip"

    if EMAIL_PATTERN.match(ioc):
        return "email"

    if SHA256_PATTERN.match(ioc):
        return "sha256"

    if SHA1_PATTERN.match(ioc):
        return "sha1"

    if MD5_PATTERN.match(ioc):
        return "md5"

    if DOMAIN_PATTERN.match(ioc):
        return "domain"

    return "unknown"


def is_valid_ioc(ioc: str) -> bool:
    """Returns True if the IOC is a recognised type."""
    return detect_ioc_type(ioc) != "unknown"