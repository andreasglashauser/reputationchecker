import re
from typing import Tuple

def is_valid_ip(ip: str) -> bool:
    """
    Validate if a string is a valid IPv4 address.
    
    Args:
        ip: The IP address to validate
        
    Returns:
        bool: True if the IP is valid, False otherwise
    """
    try:
        parts = ip.split('.')
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except (AttributeError, TypeError, ValueError):
        return False

def is_valid_domain(domain: str) -> bool:
    """
    Validate if a string is a valid domain name.
    
    Args:
        domain: The domain name to validate
        
    Returns:
        bool: True if the domain is valid, False otherwise
    """
    if not domain:
        return False
        
    pattern = r'^([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def validate_target(target: str) -> Tuple[bool, str]:
    """
    Validate if a target is either a valid IP address or domain name.
    
    Args:
        target: The target to validate (IP or domain)
        
    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if is_valid_ip(target):
        return True, ""
    elif is_valid_domain(target):
        return True, ""
    else:
        return False, "Target must be a valid IP address or domain name" 