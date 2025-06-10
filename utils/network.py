"""
Network utilities for the reconnaissance tool.
Provides common networking functions and helpers.
"""

import socket
import asyncio
import aiohttp
import time
import random
from typing import List, Tuple, Optional, Dict, Any
import logging
from urllib.parse import urlparse
import ssl
import certifi


class NetworkUtils:
    """Network utilities for reconnaissance operations."""
    
    def __init__(self, config):
        """
        Initialize network utilities.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.session = None
    
    async def get_session(self) -> aiohttp.ClientSession:
        """
        Get or create an aiohttp session with proper configuration.
        
        Returns:
            aiohttp.ClientSession: Configured session
        """
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(
                total=self.config.get('general.timeout', 10),
                connect=self.config.get('general.timeout', 10)
            )
            
            headers = {
                'User-Agent': self.config.get('general.user_agent', 'ReconTool/1.0')
            }
            
            # SSL context for secure connections
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            
            connector = aiohttp.TCPConnector(
                ssl_context=ssl_context,
                limit=self.config.get('general.threads', 50),
                limit_per_host=10
            )
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=connector
            )
        
        return self.session
    
    async def close_session(self):
        """Close the aiohttp session."""
        if self.session and not self.session.closed:
            await self.session.close()
    
    async def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[Dict[str, Any]]:
        """
        Make an HTTP request with proper error handling and rate limiting.
        
        Args:
            url (str): URL to request
            method (str): HTTP method
            **kwargs: Additional arguments for the request
        
        Returns:
            Dict containing response data or None if failed
        """
        session = await self.get_session()
        
        try:
            # Rate limiting
            await self.rate_limit()
            
            async with session.request(method, url, **kwargs) as response:
                return {
                    'status': response.status,
                    'headers': dict(response.headers),
                    'text': await response.text(),
                    'url': str(response.url)
                }
                
        except asyncio.TimeoutError:
            self.logger.warning(f"Request timeout for {url}")
            return None
        except aiohttp.ClientError as e:
            self.logger.warning(f"Request error for {url}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error for {url}: {e}")
            return None
    
    async def rate_limit(self):
        """Apply rate limiting between requests."""
        delay = self.config.get('general.rate_limit_delay', 1.0)
        if delay > 0:
            await asyncio.sleep(delay + random.uniform(0, 0.5))
    
    def is_port_open(self, host: str, port: int, timeout: float = 3.0) -> bool:
        """
        Check if a port is open on a host.
        
        Args:
            host (str): Target host
            port (int): Target port
            timeout (float): Connection timeout
        
        Returns:
            bool: True if port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    async def async_port_check(self, host: str, port: int, timeout: float = 3.0) -> bool:
        """
        Asynchronously check if a port is open.
        
        Args:
            host (str): Target host
            port (int): Target port
            timeout (float): Connection timeout
        
        Returns:
            bool: True if port is open
        """
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    def resolve_hostname(self, hostname: str) -> List[str]:
        """
        Resolve hostname to IP addresses.
        
        Args:
            hostname (str): Hostname to resolve
        
        Returns:
            List of IP addresses
        """
        try:
            result = socket.getaddrinfo(hostname, None)
            ips = list(set([res[4][0] for res in result]))
            return ips
        except socket.gaierror:
            return []
    
    def is_valid_ip(self, ip: str) -> bool:
        """
        Check if a string is a valid IP address.
        
        Args:
            ip (str): IP address string
        
        Returns:
            bool: True if valid IP
        """
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def is_valid_domain(self, domain: str) -> bool:
        """
        Check if a string is a valid domain name.
        
        Args:
            domain (str): Domain name string
        
        Returns:
            bool: True if valid domain
        """
        try:
            # Basic validation
            if not domain or len(domain) > 253:
                return False
            
            # Check for valid characters and structure
            parts = domain.split('.')
            if len(parts) < 2:
                return False
            
            for part in parts:
                if not part or len(part) > 63:
                    return False
                if not part.replace('-', '').isalnum():
                    return False
                if part.startswith('-') or part.endswith('-'):
                    return False
            
            return True
        except Exception:
            return False
    
    def extract_domain_from_url(self, url: str) -> Optional[str]:
        """
        Extract domain from URL.
        
        Args:
            url (str): URL string
        
        Returns:
            Domain name or None
        """
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except Exception:
            return None
    
    async def check_http_service(self, host: str, port: int = 80, use_https: bool = False) -> Dict[str, Any]:
        """
        Check if HTTP service is running and gather basic information.
        
        Args:
            host (str): Target host
            port (int): Target port
            use_https (bool): Use HTTPS instead of HTTP
        
        Returns:
            Dict with service information
        """
        protocol = 'https' if use_https else 'http'
        url = f"{protocol}://{host}:{port}"
        
        response = await self.make_request(url, method='HEAD')
        
        if response:
            return {
                'service': 'HTTP',
                'protocol': protocol,
                'status': response['status'],
                'headers': response['headers'],
                'server': response['headers'].get('server', 'Unknown'),
                'powered_by': response['headers'].get('x-powered-by', 'Unknown')
            }
        
        return {}
    
    def get_banner(self, host: str, port: int, timeout: float = 5.0) -> Optional[str]:
        """
        Get service banner from a port.
        
        Args:
            host (str): Target host
            port (int): Target port
            timeout (float): Connection timeout
        
        Returns:
            Service banner or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            
            # Try to receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner if banner else None
            
        except Exception:
            return None


class RateLimiter:
    """Rate limiter for API calls and network requests."""
    
    def __init__(self, calls_per_second: float = 1.0):
        """
        Initialize rate limiter.
        
        Args:
            calls_per_second (float): Maximum calls per second
        """
        self.calls_per_second = calls_per_second
        self.last_call = 0.0
    
    async def wait(self):
        """Wait if necessary to respect rate limit."""
        if self.calls_per_second <= 0:
            return
        
        current_time = time.time()
        time_since_last = current_time - self.last_call
        min_interval = 1.0 / self.calls_per_second
        
        if time_since_last < min_interval:
            wait_time = min_interval - time_since_last
            await asyncio.sleep(wait_time)
        
        self.last_call = time.time()


# Utility functions
def is_private_ip(ip: str) -> bool:
    """
    Check if an IP address is private.
    
    Args:
        ip (str): IP address
    
    Returns:
        bool: True if private IP
    """
    try:
        parts = [int(x) for x in ip.split('.')]
        
        # Private IP ranges
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:  # Loopback
            return True
        
        return False
    except (ValueError, IndexError):
        return False


def is_cloud_ip(ip: str) -> bool:
    """
    Check if an IP address belongs to a cloud provider (basic check).
    
    Args:
        ip (str): IP address
    
    Returns:
        bool: True if likely cloud IP
    """
    # This is a basic implementation - in practice, you'd want
    # to use a comprehensive database of cloud IP ranges
    cloud_ranges = [
        ('3.', 'Amazon AWS'),
        ('13.', 'Amazon AWS'),
        ('15.', 'Amazon AWS'),
        ('18.', 'Amazon AWS'),
        ('34.', 'Google Cloud'),
        ('35.', 'Google Cloud'),
        ('104.', 'Microsoft Azure'),
        ('137.', 'Microsoft Azure'),
        ('138.', 'Microsoft Azure'),
        ('139.', 'Microsoft Azure'),
        ('40.', 'Microsoft Azure'),
        ('52.', 'Microsoft Azure'),
    ]
    
    for prefix, provider in cloud_ranges:
        if ip.startswith(prefix):
            return True
    
    return False
