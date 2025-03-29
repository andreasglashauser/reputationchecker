from dataclasses import dataclass
from typing import Optional

@dataclass
class DNSBLResult:
    """Represents the result of a DNSBL check."""
    list_name: str
    description: str
    category: str
    status: str
    details: str

@dataclass
class DNSBLService:
    """Represents a DNSBL service configuration."""
    name: str
    dnsbl: str
    description: str
    category: str
    special: bool = False
    return_codes: Optional[dict] = None 
    color_logic: Optional[dict] = None