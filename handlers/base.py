from abc import ABC, abstractmethod
from typing import Tuple, Optional, Dict, List
import dns.resolver
from models.dnsbl import DNSBLService, DNSBLResult
from utils.ip import is_valid_ip

class DNSBLHandler(ABC):
    """Base class for DNSBL handlers."""
    
    RETURN_CODES: Dict[str, str] = {}
    RATE_LIMIT_CODES: Dict[str, str] = {}
    COLOR_LOGIC: Dict[str, List[str]] = {}
    
    def __init__(self, service: DNSBLService):
        """
        Initialize the handler with a DNSBL service configuration.
        
        Args:
            service: DNSBLService configuration object
        """
        self.service = service
    
    def check(self, target: str) -> Tuple[bool, str]:
        """
        Check if a target is listed in the DNSBL service.
        
        Args:
            target: The target to check (IP or domain)
            
        Returns:
            Tuple[bool, str]: (is_listed, details)
        """
        lookup = self._get_lookup_name(target)
        return_ip = self._get_a_record(lookup)
        
        if not return_ip:
            return False, "Not listed"
            
        if return_ip in self.RATE_LIMIT_CODES:
            return False, self.RATE_LIMIT_CODES[return_ip]
            
        if return_ip in self.RETURN_CODES:
            return True, f"{self.RETURN_CODES[return_ip]} (Return IP: {return_ip})"
            
        return True, f"Listed (Return IP: {return_ip})"
    
    def create_result(self, is_listed: bool, details: str) -> DNSBLResult:
        """
        Create a DNSBLResult object from the check result.
        
        Args:
            is_listed: Whether the target is listed
            details: Details about the listing
            
        Returns:
            DNSBLResult: The result object
        """
        return_ip = None
        if "(Return IP: " in details:
            return_ip = details.split("(Return IP: ")[1].rstrip(")")
        
        status = "Listed" if is_listed else "Not Listed"
        if return_ip and self.COLOR_LOGIC:
            for color, codes in self.COLOR_LOGIC.items():
                if return_ip in codes:
                    status = color.capitalize()
                    break
        
        return DNSBLResult(
            list_name=self.service.name,
            description=self.service.description,
            category=self.service.category,
            status=status,
            details=details
        )
    
    def _reverse_ip(self, ip: str) -> str:
        """
        Reverse an IP address for DNSBL lookup.
        
        Args:
            ip: The IP address to reverse
            
        Returns:
            str: The reversed IP address
        """
        return '.'.join(reversed(ip.split('.')))
    
    def _get_lookup_name(self, target: str) -> str:
        """
        Get the DNS lookup name for a target.
        
        Args:
            target: The target to check (IP or domain)
            
        Returns:
            str: The DNS lookup name
        """
        if is_valid_ip(target):
            return f"{self._reverse_ip(target)}.{self.service.dnsbl}"
        return f"{target}.{self.service.dnsbl}"
    
    def _get_a_record(self, lookup: str) -> Optional[str]:
        """
        Get the A record for a DNS lookup.
        
        Args:
            lookup: The DNS lookup name
            
        Returns:
            Optional[str]: The A record if found, None otherwise
        """
        try:
            answers = dns.resolver.resolve(lookup, 'A')
            return str(answers[0])
        except dns.resolver.NXDOMAIN:
            return None
        except Exception as e:
            raise Exception(f"DNS lookup error: {str(e)}") 