import dns.resolver
import click
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from typing import List, Dict, Optional, Tuple
from datetime import datetime

from models.dnsbl import DNSBLResult
from config.dnsbl_config import DNSBL_SERVICES
from utils.ip import is_valid_ip, is_valid_domain, reverse_ip, validate_target
from handlers.spamhaus import SpamhausHandler
from handlers.barracuda import BarracudaHandler
from handlers.spamcop import SpamCopHandler
from handlers.dronebl import DroneBLHandler
from handlers.blocklist_de import BlocklistDEHandler
from handlers.cinsscore import CINSScoreHandler
from handlers.spamrats import SpamRATSHandler
from handlers.hostkarma import HostkarmaHandler
from handlers.mailspike import MailspikeHandler

console = Console()

def setup_logging(verbosity: int):
    """Configure logging based on verbosity level."""
    log_levels = {
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
        3: logging.DEBUG
    }
    
    logging.basicConfig(
        level=log_levels.get(verbosity, logging.WARNING),
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    logger = logging.getLogger('reputationchecker')
    
    if verbosity >= 2:
        fh = logging.FileHandler('reputationchecker.log')
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    
    return logger

HANDLERS = {
    'spamhaus': SpamhausHandler(DNSBL_SERVICES['spamhaus']),
    'barracuda': BarracudaHandler(DNSBL_SERVICES['barracuda']),
    'spamcop': SpamCopHandler(DNSBL_SERVICES['spamcop']),
    'dronebl': DroneBLHandler(DNSBL_SERVICES['dronebl']),
    'blocklist_de': BlocklistDEHandler(DNSBL_SERVICES['blocklist_de']),
    'cinsscore': CINSScoreHandler(DNSBL_SERVICES['cinsscore']),
    'spamrats': SpamRATSHandler(DNSBL_SERVICES['spamrats']),
    'hostkarma': HostkarmaHandler(DNSBL_SERVICES['hostkarma']),
    'mailspike': MailspikeHandler(DNSBL_SERVICES['mailspike'])
}

def check_dns_list(target: str, service: str, logger: logging.Logger) -> DNSBLResult:
    """
    Check if a target is listed in a DNSBL service.
    
    Args:
        target: The target to check (IP or domain)
        service: The service name to check against
        logger: Logger instance for debugging
        
    Returns:
        DNSBLResult: The result of the check
    """
    logger.debug(f"Checking {target} against {service}")
    service_config = DNSBL_SERVICES[service]
    logger.debug(f"Service config: {service_config}")
    
    if service_config.special and service in HANDLERS:
        logger.debug(f"Using special handler for {service}")
        handler = HANDLERS[service]
        is_listed, details = handler.check(target)
        logger.debug(f"Special handler result: listed={is_listed}, details={details}")
    else:
        logger.debug(f"Using generic DNSBL check for {service}")
        if is_valid_ip(target):
            lookup = f"{reverse_ip(target)}.{service_config.dnsbl}"
        else:
            lookup = f"{target}.{service_config.dnsbl}"
        logger.debug(f"DNS lookup: {lookup}")
            
        try:
            answers = dns.resolver.resolve(lookup, 'A')
            return_ip = str(answers[0])
            is_listed = True
            details = f"Listed (Return IP: {return_ip})"
            logger.debug(f"DNS lookup successful: {return_ip}")
        except dns.resolver.NXDOMAIN:
            is_listed = False
            details = "Not listed"
            logger.debug("Target not listed")
        except Exception as e:
            is_listed = False
            details = f"Error: {str(e)}"
            logger.error(f"DNS lookup error: {str(e)}", exc_info=True)
    
    result = DNSBLResult(
        list_name=service,
        description=service_config.description,
        category=service_config.category,
        status="Listed" if is_listed else "Not Listed",
        details=details
    )
    logger.debug(f"Created result: {result}")
    return result

def group_results_by_category(results: List[DNSBLResult], logger: logging.Logger) -> Dict[str, List[DNSBLResult]]:
    """
    Group results by their category.
    
    Args:
        results: List of DNSBLResult objects
        logger: Logger instance for debugging
        
    Returns:
        Dict[str, List[DNSBLResult]]: Results grouped by category
    """
    logger.debug(f"Grouping {len(results)} results by category")
    grouped = {}
    for result in results:
        if result.category not in grouped:
            grouped[result.category] = []
        grouped[result.category].append(result)
    logger.debug(f"Grouped results: {grouped}")
    return grouped

def display_results(target: str, results: List[DNSBLResult], logger: logging.Logger):
    """
    Display the results in a formatted table.
    
    Args:
        target: The target that was checked
        results: List of DNSBLResult objects
        logger: Logger instance for debugging
    """
    logger.debug(f"Displaying results for {target}")
    table = Table(title=f"DNSBL Check Results for {target}")
    table.add_column("Service", style="cyan")
    table.add_column("Description", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Details", style="white")
    
    for result in results:
        service_config = DNSBL_SERVICES.get(result.list_name)
        handler = HANDLERS.get(result.list_name)
        
        status_style = "white"  
        if handler and hasattr(handler, 'COLOR_LOGIC'):
            return_ip = None
            if "Return IP:" in result.details:
                return_ip = result.details.split("Return IP:")[1].strip().split(")")[0].strip()
            
            if return_ip:
                for color, ips in handler.COLOR_LOGIC.items():
                    if return_ip in ips:
                        status_style = color
                        break
        
        if status_style == "white":
            status_style = "red" if result.status == "Listed" else "green"
        
        details = result.details
        if handler and hasattr(handler, 'RETURN_CODES'):
            if "Return IP:" in result.details:
                return_ip = result.details.split("Return IP:")[1].strip().split(")")[0].strip()
                if return_ip in handler.RETURN_CODES:
                    details = handler.RETURN_CODES[return_ip]
        
        table.add_row(
            result.list_name,
            result.description,
            Text(result.status, style=status_style),
            details
        )
        logger.debug(f"Added row: {result.list_name} - {result.status} (style: {status_style})")
    
    console.print(table)
    
    grouped_results = group_results_by_category(results, logger)
    category_table = Table(title="Category Summary")
    category_table.add_column("Category", style="cyan")
    category_table.add_column("Total", style="white")
    category_table.add_column("Listed", style="red")
    category_table.add_column("Not Listed", style="green")
    
    for category, category_results in grouped_results.items():
        listed_count = sum(1 for r in category_results if r.status == "Listed")
        total_count = len(category_results)
        not_listed_count = total_count - listed_count
        
        category_table.add_row(
            category,
            str(total_count),
            str(listed_count),
            str(not_listed_count)
        )
    
    console.print(category_table)
    
    listed_count = sum(1 for r in results if r.status == "Listed")
    total_count = len(results)
    summary = f"Found {listed_count} out of {total_count} services listing the target"
    logger.info(summary)
    
    if listed_count > 0:
        console.print(Panel(summary, title="Overall Summary", style="red"))
    else:
        console.print(Panel(summary, title="Overall Summary", style="green"))

@click.command()
@click.argument('target')
@click.option('--category', '-c', help='Filter results by category')
@click.option('--verbose', '-v', count=True, help='Increase verbosity (can be used multiple times)')
def main(target: str, category: str = None, verbose: int = 0):
    """
    Check if an IP address or domain is listed in various DNSBL services.
    
    TARGET can be either an IP address or domain name.
    """
    logger = setup_logging(verbose)
    logger.info(f"Starting check for target: {target}")
    
    is_valid, error_msg = validate_target(target)
    if not is_valid:
        logger.error(f"Invalid target: {error_msg}")
        console.print(f"[red]Error: {error_msg}[/red]")
        return
    
    results = []
    for service_name, service_config in DNSBL_SERVICES.items():
        if category and service_config.category != category:
            logger.debug(f"Skipping {service_name} - category mismatch")
            continue
            
        try:
            logger.info(f"Checking {service_name}")
            result = check_dns_list(target, service_name, logger)
            results.append(result)
        except Exception as e:
            logger.error(f"Error checking {service_name}: {str(e)}", exc_info=True)
            console.print(f"[yellow]Warning: Error checking {service_name}: {str(e)}[/yellow]")
    
    display_results(target, results, logger)
    logger.info("Check completed")

if __name__ == '__main__':
    main() 