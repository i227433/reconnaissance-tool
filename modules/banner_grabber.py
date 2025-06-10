"""
Banner Grabber Module
Captures service banners from open ports to identify software versions.
"""

import asyncio
import socket
import ssl
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from utils.logger import log_performance
from utils.network import NetworkUtils


class BannerGrabber:
    """Banner grabbing functionality for service identification."""
    
    def __init__(self, config):
        """
        Initialize banner grabber.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.network_utils = NetworkUtils(config)
        
        self.timeout = config.get('banner_grabbing.timeout', 5)
        self.buffer_size = config.get('banner_grabbing.buffer_size', 1024)
        
        # Common banners and their identification patterns
        self.banner_patterns = {
            'ssh': [b'SSH-', b'OpenSSH'],
            'http': [b'Server:', b'HTTP/', b'Content-Type:'],
            'ftp': [b'220', b'FTP', b'vsftpd', b'ProFTPD'],
            'smtp': [b'220', b'SMTP', b'ESMTP', b'Postfix', b'Sendmail'],
            'telnet': [b'login:', b'Telnet', b'Welcome'],
            'pop3': [b'+OK', b'POP3'],
            'imap': [b'* OK', b'IMAP'],
            'mysql': [b'mysql_native_password', b'Got packets out of order'],
            'postgresql': [b'FATAL', b'password authentication failed'],
            'rdp': [b'MSTSHASH='],
            'vnc': [b'RFB ']
        }
    
    @log_performance
    async def grab_banners(self, port_scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Grab banners from open ports discovered in port scanning.
        
        Args:
            port_scan_results (dict): Results from port scanning
        
        Returns:
            Dict containing banner grabbing results
        """
        self.logger.info("Starting banner grabbing for discovered open ports")
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'banners': {},
            'service_versions': {},
            'banner_analysis': {},
            'statistics': {}
        }
        
        try:
            # Extract targets with open ports
            targets_with_ports = []
            
            for host, scan_data in port_scan_results.get('results', {}).items():
                open_ports = scan_data.get('open_ports', [])
                for port_info in open_ports:
                    targets_with_ports.append({
                        'host': host,
                        'port': port_info['port'],
                        'service': port_info.get('service', 'unknown')
                    })
            
            if not targets_with_ports:
                self.logger.warning("No open ports found for banner grabbing")
                return result
            
            # Grab banners for all open ports
            banner_tasks = []
            for target_port in targets_with_ports:
                task = asyncio.create_task(
                    self._grab_single_banner(
                        target_port['host'], 
                        target_port['port'],
                        target_port['service']
                    )
                )
                banner_tasks.append(task)
            
            # Execute banner grabbing tasks
            banner_results = await asyncio.gather(*banner_tasks, return_exceptions=True)
            
            # Process results
            for i, banner_result in enumerate(banner_results):
                if isinstance(banner_result, dict) and not isinstance(banner_result, Exception):
                    host = targets_with_ports[i]['host']
                    port = targets_with_ports[i]['port']
                    
                    # Store banner information
                    if host not in result['banners']:
                        result['banners'][host] = {}
                    
                    result['banners'][host][port] = banner_result
                    
                    # Extract service version information
                    if banner_result.get('banner'):
                        service_info = self._extract_service_info(banner_result)
                        if service_info:
                            if host not in result['service_versions']:
                                result['service_versions'][host] = {}
                            result['service_versions'][host][port] = service_info
            
            # Analyze banners for security insights
            result['banner_analysis'] = self._analyze_banners(result['banners'])
            
            # Generate statistics
            result['statistics'] = self._generate_banner_statistics(result)
            
            self.logger.info(f"Banner grabbing completed for {len(targets_with_ports)} ports")
            
        except Exception as e:
            self.logger.error(f"Banner grabbing failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _grab_single_banner(self, host: str, port: int, service: str = 'unknown') -> Dict[str, Any]:
        """
        Grab banner from a single port.
        
        Args:
            host (str): Target host
            port (int): Target port
            service (str): Expected service type
        
        Returns:
            Banner information
        """
        banner_result = {
            'host': host,
            'port': port,
            'service': service,
            'banner': None,
            'banner_hex': None,
            'connection_successful': False,
            'ssl_enabled': False,
            'response_time': 0,
            'error': None
        }
        
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Try different banner grabbing methods based on service
            if service in ['http', 'https'] or port in [80, 443, 8080, 8443]:
                banner_result.update(await self._grab_http_banner(host, port))
            elif service == 'ssh' or port == 22:
                banner_result.update(await self._grab_ssh_banner(host, port))
            elif service in ['ftp'] or port == 21:
                banner_result.update(await self._grab_ftp_banner(host, port))
            elif service in ['smtp', 'mail'] or port in [25, 587]:
                banner_result.update(await self._grab_smtp_banner(host, port))
            elif service in ['pop3'] or port == 110:
                banner_result.update(await self._grab_pop3_banner(host, port))
            elif service in ['imap'] or port == 143:
                banner_result.update(await self._grab_imap_banner(host, port))
            else:
                # Generic banner grabbing
                banner_result.update(await self._grab_generic_banner(host, port))
            
            banner_result['response_time'] = (asyncio.get_event_loop().time() - start_time) * 1000
            
        except Exception as e:
            banner_result['error'] = str(e)
            self.logger.debug(f"Banner grab failed for {host}:{port} - {e}")
        
        return banner_result
    
    async def _grab_http_banner(self, host: str, port: int) -> Dict[str, Any]:
        """
        Grab HTTP banner and headers.
        
        Args:
            host (str): Target host
            port (int): Target port
        
        Returns:
            HTTP banner information
        """
        result = {'connection_successful': False}
        
        try:
            # Determine if HTTPS should be used
            use_ssl = port in [443, 8443] or port == 443
            
            if use_ssl:
                # Create SSL context
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ssl_context),
                    timeout=self.timeout
                )
                result['ssl_enabled'] = True
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
            
            result['connection_successful'] = True
            
            # Send HTTP HEAD request
            http_request = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (compatible; ReconTool/1.0)\r\nConnection: close\r\n\r\n"
            writer.write(http_request.encode())
            await writer.drain()
            
            # Read response
            response_data = await asyncio.wait_for(
                reader.read(self.buffer_size),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            if response_data:
                banner = response_data.decode('utf-8', errors='ignore')
                result['banner'] = banner
                result['banner_hex'] = response_data.hex()
                
                # Parse HTTP headers
                result['http_headers'] = self._parse_http_headers(banner)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def _grab_ssh_banner(self, host: str, port: int) -> Dict[str, Any]:
        """
        Grab SSH banner.
        
        Args:
            host (str): Target host
            port (int): Target port
        
        Returns:
            SSH banner information
        """
        result = {'connection_successful': False}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            result['connection_successful'] = True
            
            # SSH server sends banner immediately
            banner_data = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            if banner_data:
                banner = banner_data.decode('utf-8', errors='ignore').strip()
                result['banner'] = banner
                result['banner_hex'] = banner_data.hex()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def _grab_ftp_banner(self, host: str, port: int) -> Dict[str, Any]:
        """
        Grab FTP banner.
        
        Args:
            host (str): Target host
            port (int): Target port
        
        Returns:
            FTP banner information
        """
        result = {'connection_successful': False}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            result['connection_successful'] = True
            
            # FTP server sends welcome message immediately
            banner_data = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            if banner_data:
                banner = banner_data.decode('utf-8', errors='ignore').strip()
                result['banner'] = banner
                result['banner_hex'] = banner_data.hex()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def _grab_smtp_banner(self, host: str, port: int) -> Dict[str, Any]:
        """
        Grab SMTP banner.
        
        Args:
            host (str): Target host
            port (int): Target port
        
        Returns:
            SMTP banner information
        """
        result = {'connection_successful': False}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            result['connection_successful'] = True
            
            # SMTP server sends greeting immediately
            banner_data = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            
            # Try to get more info with EHLO command
            writer.write(b"EHLO test\r\n")
            await writer.drain()
            
            ehlo_response = await asyncio.wait_for(
                reader.read(self.buffer_size),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            banner = banner_data.decode('utf-8', errors='ignore').strip()
            result['banner'] = banner
            result['banner_hex'] = banner_data.hex()
            
            if ehlo_response:
                ehlo_text = ehlo_response.decode('utf-8', errors='ignore')
                result['ehlo_response'] = ehlo_text
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def _grab_pop3_banner(self, host: str, port: int) -> Dict[str, Any]:
        """
        Grab POP3 banner.
        
        Args:
            host (str): Target host
            port (int): Target port
        
        Returns:
            POP3 banner information
        """
        result = {'connection_successful': False}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            result['connection_successful'] = True
            
            # POP3 server sends greeting immediately
            banner_data = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            if banner_data:
                banner = banner_data.decode('utf-8', errors='ignore').strip()
                result['banner'] = banner
                result['banner_hex'] = banner_data.hex()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def _grab_imap_banner(self, host: str, port: int) -> Dict[str, Any]:
        """
        Grab IMAP banner.
        
        Args:
            host (str): Target host
            port (int): Target port
        
        Returns:
            IMAP banner information
        """
        result = {'connection_successful': False}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            result['connection_successful'] = True
            
            # IMAP server sends greeting immediately
            banner_data = await asyncio.wait_for(
                reader.readline(),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            if banner_data:
                banner = banner_data.decode('utf-8', errors='ignore').strip()
                result['banner'] = banner
                result['banner_hex'] = banner_data.hex()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    async def _grab_generic_banner(self, host: str, port: int) -> Dict[str, Any]:
        """
        Grab banner using generic method.
        
        Args:
            host (str): Target host
            port (int): Target port
        
        Returns:
            Generic banner information
        """
        result = {'connection_successful': False}
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            
            result['connection_successful'] = True
            
            # Wait for server to send data
            try:
                banner_data = await asyncio.wait_for(
                    reader.read(self.buffer_size),
                    timeout=self.timeout
                )
                
                if banner_data:
                    banner = banner_data.decode('utf-8', errors='ignore').strip()
                    result['banner'] = banner
                    result['banner_hex'] = banner_data.hex()
                else:
                    # Try sending a generic probe
                    writer.write(b"\r\n")
                    await writer.drain()
                    
                    probe_response = await asyncio.wait_for(
                        reader.read(self.buffer_size),
                        timeout=self.timeout
                    )
                    
                    if probe_response:
                        banner = probe_response.decode('utf-8', errors='ignore').strip()
                        result['banner'] = banner
                        result['banner_hex'] = probe_response.hex()
                
            except asyncio.TimeoutError:
                # No immediate response, try sending HTTP request
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
                await writer.drain()
                
                http_response = await asyncio.wait_for(
                    reader.read(self.buffer_size),
                    timeout=self.timeout
                )
                
                if http_response:
                    banner = http_response.decode('utf-8', errors='ignore').strip()
                    result['banner'] = banner
                    result['banner_hex'] = http_response.hex()
            
            writer.close()
            await writer.wait_closed()
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _parse_http_headers(self, http_response: str) -> Dict[str, str]:
        """
        Parse HTTP headers from response.
        
        Args:
            http_response (str): HTTP response
        
        Returns:
            Dictionary of headers
        """
        headers = {}
        
        try:
            lines = http_response.split('\r\n')
            for line in lines[1:]:  # Skip status line
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
        
        except Exception as e:
            self.logger.debug(f"Failed to parse HTTP headers: {e}")
        
        return headers
    
    def _extract_service_info(self, banner_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract service and version information from banner.
        
        Args:
            banner_result (dict): Banner grabbing result
        
        Returns:
            Service information
        """
        service_info = {
            'service_type': 'unknown',
            'version': 'unknown',
            'software': 'unknown',
            'operating_system': 'unknown'
        }
        
        banner = banner_result.get('banner', '').lower()
        
        if not banner:
            return service_info
        
        # SSH identification
        if 'ssh-' in banner:
            service_info['service_type'] = 'ssh'
            if 'openssh' in banner:
                service_info['software'] = 'OpenSSH'
                # Extract version
                import re
                version_match = re.search(r'openssh[_\s]+([0-9.]+)', banner)
                if version_match:
                    service_info['version'] = version_match.group(1)
        
        # HTTP identification
        elif 'http/' in banner or 'server:' in banner:
            service_info['service_type'] = 'http'
            
            # Extract server information
            if 'server:' in banner:
                server_line = [line for line in banner.split('\n') if 'server:' in line]
                if server_line:
                    server_info = server_line[0].split('server:')[1].strip()
                    service_info['software'] = server_info
                    
                    # Common web servers
                    if 'apache' in server_info.lower():
                        service_info['software'] = 'Apache'
                    elif 'nginx' in server_info.lower():
                        service_info['software'] = 'Nginx'
                    elif 'iis' in server_info.lower():
                        service_info['software'] = 'IIS'
        
        # FTP identification
        elif '220' in banner and ('ftp' in banner or 'vsftpd' in banner or 'proftpd' in banner):
            service_info['service_type'] = 'ftp'
            if 'vsftpd' in banner:
                service_info['software'] = 'vsftpd'
            elif 'proftpd' in banner:
                service_info['software'] = 'ProFTPD'
        
        # SMTP identification
        elif '220' in banner and ('smtp' in banner or 'esmtp' in banner):
            service_info['service_type'] = 'smtp'
            if 'postfix' in banner:
                service_info['software'] = 'Postfix'
            elif 'sendmail' in banner:
                service_info['software'] = 'Sendmail'
            elif 'exim' in banner:
                service_info['software'] = 'Exim'
        
        # Operating system detection
        if 'ubuntu' in banner:
            service_info['operating_system'] = 'Ubuntu'
        elif 'debian' in banner:
            service_info['operating_system'] = 'Debian'
        elif 'centos' in banner or 'rhel' in banner:
            service_info['operating_system'] = 'CentOS/RHEL'
        elif 'windows' in banner:
            service_info['operating_system'] = 'Windows'
        
        return service_info
    
    def _analyze_banners(self, banners: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Analyze banners for security insights.
        
        Args:
            banners (dict): Banner results
        
        Returns:
            Security analysis
        """
        analysis = {
            'security_findings': [],
            'version_info': {},
            'service_summary': {},
            'potential_vulnerabilities': []
        }
        
        for host, host_banners in banners.items():
            for port, banner_info in host_banners.items():
                banner = banner_info.get('banner', '').lower()
                
                if not banner:
                    continue
                
                # Check for version disclosure
                if any(keyword in banner for keyword in ['version', 'v.', 'apache/', 'nginx/', 'openssh']):
                    analysis['security_findings'].append(f"{host}:{port} - Version information disclosed")
                
                # Check for default banners
                if any(default in banner for default in ['welcome', 'default', 'test']):
                    analysis['security_findings'].append(f"{host}:{port} - Default banner detected")
                
                # Check for potentially vulnerable services
                if 'telnet' in banner:
                    analysis['potential_vulnerabilities'].append(f"{host}:{port} - Telnet (unencrypted protocol)")
                
                if 'ftp' in banner and 'sftp' not in banner:
                    analysis['potential_vulnerabilities'].append(f"{host}:{port} - FTP (potentially unencrypted)")
                
                # Count services
                service_type = banner_info.get('service', 'unknown')
                if service_type in analysis['service_summary']:
                    analysis['service_summary'][service_type] += 1
                else:
                    analysis['service_summary'][service_type] = 1
        
        return analysis
    
    def _generate_banner_statistics(self, banner_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate statistics for banner grabbing results.
        
        Args:
            banner_results (dict): Banner results
        
        Returns:
            Statistics
        """
        stats = {
            'total_banners_grabbed': 0,
            'successful_grabs': 0,
            'failed_grabs': 0,
            'services_identified': 0,
            'unique_services': set(),
            'hosts_with_banners': len(banner_results.get('banners', {}))
        }
        
        for host, host_banners in banner_results.get('banners', {}).items():
            for port, banner_info in host_banners.items():
                stats['total_banners_grabbed'] += 1
                
                if banner_info.get('banner'):
                    stats['successful_grabs'] += 1
                    
                    service = banner_info.get('service', 'unknown')
                    if service != 'unknown':
                        stats['services_identified'] += 1
                        stats['unique_services'].add(service)
                else:
                    stats['failed_grabs'] += 1
        
        # Convert set to list for JSON serialization
        stats['unique_services'] = list(stats['unique_services'])
        stats['success_rate'] = (stats['successful_grabs'] / stats['total_banners_grabbed'] * 100) if stats['total_banners_grabbed'] > 0 else 0
        
        return stats
    
    async def grab_banner_for_service(self, host: str, port: int, service: str = 'unknown') -> Dict[str, Any]:
        """
        Grab banner for a specific service.
        
        Args:
            host (str): Target host
            port (int): Target port
            service (str): Service type
        
        Returns:
            Banner information
        """
        self.logger.info(f"Grabbing banner for {service} service on {host}:{port}")
        return await self._grab_single_banner(host, port, service)