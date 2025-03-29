import ipaddress
from typing import Tuple
import re

def is_valid_ip(ip: str) -> bool:
    """Validate if a string is a valid IPv4 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def reverse_ip(ip: str) -> str:
    """Reverse an IP address for DNSBL lookups."""
    return '.'.join(reversed(ip.split('.')))

def validate_target(target: str) -> Tuple[bool, str]:
    """Validate if a target is either a valid IP address or domain name."""
    if is_valid_ip(target):
        return True, ""
    elif is_valid_domain(target):
        return True, ""
    else:
        return False, "Target must be a valid IP address or domain name"

def is_valid_domain(domain: str) -> bool:
    """Validate if a string is a valid domain name."""
    if not domain:
        return False
        
    pattern = r'^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain)) 