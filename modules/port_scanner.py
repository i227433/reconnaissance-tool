"""
Port Scanner Module
Performs comprehensive port scanning to identify open services on target systems.
"""

import asyncio
import socket
import subprocess
import logging
import json
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional
import concurrent.futures
from utils.logger import log_performance
from utils.network import NetworkUtils


class PortScanner:
    """Port scanning functionality for active reconnaissance."""
    
    def __init__(self, config):
        """
        Initialize port scanner.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.network_utils = NetworkUtils(config)
        
        # Port scanning configuration
        self.common_ports = config.get('port_scanning.common_ports', [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 
            1723, 3306, 3389, 5432, 5900, 8080
        ])
        self.scan_timeout = config.get('port_scanning.timeout', 3)
        self.max_threads = config.get('port_scanning.threads', 100)
    
    @log_performance
    async def scan(self, targets: List[str], ports: List[int] = None, scan_type: str = None) -> Dict[str, Any]:
        """
        Perform port scanning on target hosts.
        
        Args:
            targets (list): List of target hosts/IPs
            ports (list, optional): Specific ports to scan
            scan_type (str, optional): Type of scan (tcp, udp, syn)
        
        Returns:
            Dict containing scan results
        """
        self.logger.info(f"Starting port scan for {len(targets)} targets")
        
        if ports is None:
            ports = self.common_ports
        
        if scan_type is None:
            scan_type = self.config.get('port_scanning.scan_type', 'tcp')
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'targets': targets,
            'ports_scanned': ports,
            'scan_type': scan_type,
            'results': {},
            'summary': {},
            'scan_method': 'socket'  # Default to socket scanning
        }
        
        try:
            # Check if nmap is available for advanced scanning
            nmap_available = await self._check_nmap_availability()
            
            if nmap_available and len(ports) > 50:
                # Use nmap for large port ranges
                self.logger.info("Using Nmap for comprehensive scanning")
                result['scan_method'] = 'nmap'
                scan_results = await self._nmap_scan(targets, ports, scan_type)
            else:
                # Use socket-based scanning
                self.logger.info("Using socket-based scanning")
                scan_results = await self._socket_scan(targets, ports)
            
            result['results'] = scan_results
            result['summary'] = self._generate_scan_summary(scan_results)
            
            self.logger.info(f"Port scan completed. Found {result['summary']['total_open_ports']} open ports")
            
        except Exception as e:
            self.logger.error(f"Port scanning failed: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _socket_scan(self, targets: List[str], ports: List[int]) -> Dict[str, Any]:
        """
        Perform socket-based port scanning.
        
        Args:
            targets (list): Target hosts
            ports (list): Ports to scan
        
        Returns:
            Scan results
        """
        results = {}
        
        # Create scanning tasks
        tasks = []
        for target in targets:
            for port in ports:
                task = asyncio.create_task(self._scan_port(target, port))
                tasks.append(task)
        
        # Limit concurrent tasks to avoid overwhelming the system
        semaphore = asyncio.Semaphore(self.max_threads)
        
        async def scan_with_semaphore(task):
            async with semaphore:
                return await task
        
        # Execute scans in batches
        batch_size = 100
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            batch_results = await asyncio.gather(
                *[scan_with_semaphore(task) for task in batch],
                return_exceptions=True
            )
            
            # Process batch results
            for result in batch_results:
                if isinstance(result, dict) and not isinstance(result, Exception):
                    target = result['target']
                    if target not in results:
                        results[target] = {
                            'host': target,
                            'open_ports': [],
                            'closed_ports': [],
                            'filtered_ports': [],
                            'host_info': {}
                        }
                    
                    if result['open']:
                        results[target]['open_ports'].append({
                            'port': result['port'],
                            'protocol': 'tcp',
                            'state': 'open',
                            'service': self._identify_service(result['port']),
                            'response_time': result.get('response_time', 0)
                        })
                    else:
                        results[target]['closed_ports'].append(result['port'])
            
            # Small delay between batches to be respectful
            await asyncio.sleep(0.1)
        
        # Resolve hostnames for IP addresses
        for target in results:
            if self.network_utils.is_valid_ip(target):
                try:
                    hostname = socket.gethostbyaddr(target)[0]
                    results[target]['host_info']['hostname'] = hostname
                except:
                    pass
            
            # Get additional host information
            results[target]['host_info'].update(await self._get_host_info(target))
        
        return results
    
    async def _scan_port(self, host: str, port: int) -> Dict[str, Any]:
        """
        Scan a single port on a host.
        
        Args:
            host (str): Target host
            port (int): Port to scan
        
        Returns:
            Scan result for the port
        """
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Attempt connection
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.scan_timeout)
            
            # Connection successful - port is open
            writer.close()
            await writer.wait_closed()
            
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000
            
            return {
                'target': host,
                'port': port,
                'open': True,
                'response_time': response_time
            }
            
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            # Connection failed - port is closed or filtered
            return {
                'target': host,
                'port': port,
                'open': False
            }
    
    async def _nmap_scan(self, targets: List[str], ports: List[int], scan_type: str) -> Dict[str, Any]:
        """
        Perform nmap-based port scanning.
        
        Args:
            targets (list): Target hosts
            ports (list): Ports to scan
            scan_type (str): Type of scan
        
        Returns:
            Nmap scan results
        """
        results = {}
        
        # Prepare nmap command
        targets_str = ' '.join(targets)
        ports_str = ','.join(map(str, ports))
        
        # Build nmap command based on scan type
        if scan_type == 'syn':
            nmap_cmd = f'nmap -sS -p {ports_str} --open -oX - {targets_str}'
        elif scan_type == 'udp':
            nmap_cmd = f'nmap -sU -p {ports_str} --open -oX - {targets_str}'
        else:  # tcp
            nmap_cmd = f'nmap -sT -p {ports_str} --open -oX - {targets_str}'
        
        # Add additional options for better results
        nmap_cmd += ' -Pn -T4 --host-timeout 300s'
        
        try:
            # Execute nmap
            process = await asyncio.create_subprocess_shell(
                nmap_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                # Parse XML output
                results = self._parse_nmap_xml(stdout.decode())
            else:
                self.logger.error(f"Nmap scan failed: {stderr.decode()}")
                # Fallback to socket scanning
                results = await self._socket_scan(targets, ports)
        
        except Exception as e:
            self.logger.error(f"Nmap execution failed: {e}")
            # Fallback to socket scanning
            results = await self._socket_scan(targets, ports)
        
        return results
    
    def _parse_nmap_xml(self, xml_output: str) -> Dict[str, Any]:
        """
        Parse nmap XML output.
        
        Args:
            xml_output (str): XML output from nmap
        
        Returns:
            Parsed results
        """
        results = {}
        
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(xml_output)
            
            for host in root.findall('host'):
                # Get host address
                address_elem = host.find('address')
                if address_elem is not None:
                    host_addr = address_elem.get('addr')
                    
                    results[host_addr] = {
                        'host': host_addr,
                        'open_ports': [],
                        'closed_ports': [],
                        'filtered_ports': [],
                        'host_info': {}
                    }
                    
                    # Get hostname if available
                    hostnames = host.find('hostnames')
                    if hostnames is not None:
                        hostname_elem = hostnames.find('hostname')
                        if hostname_elem is not None:
                            results[host_addr]['host_info']['hostname'] = hostname_elem.get('name')
                    
                    # Get ports
                    ports = host.find('ports')
                    if ports is not None:
                        for port in ports.findall('port'):
                            port_id = int(port.get('portid'))
                            protocol = port.get('protocol')
                            
                            state_elem = port.find('state')
                            if state_elem is not None:
                                state = state_elem.get('state')
                                
                                if state == 'open':
                                    # Get service information
                                    service_elem = port.find('service')
                                    service_name = 'unknown'
                                    service_version = ''
                                    
                                    if service_elem is not None:
                                        service_name = service_elem.get('name', 'unknown')
                                        service_version = service_elem.get('version', '')
                                    
                                    results[host_addr]['open_ports'].append({
                                        'port': port_id,
                                        'protocol': protocol,
                                        'state': state,
                                        'service': service_name,
                                        'version': service_version
                                    })
                                elif state == 'closed':
                                    results[host_addr]['closed_ports'].append(port_id)
                                elif state == 'filtered':
                                    results[host_addr]['filtered_ports'].append(port_id)
        
        except Exception as e:
            self.logger.error(f"Failed to parse nmap XML: {e}")
        
        return results
    
    async def _check_nmap_availability(self) -> bool:
        """
        Check if nmap is available on the system.
        
        Returns:
            bool: True if nmap is available
        """
        try:
            process = await asyncio.create_subprocess_shell(
                'nmap --version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            return process.returncode == 0
        
        except Exception:
            return False
    
    def _identify_service(self, port: int) -> str:
        """
        Identify common services by port number.
        
        Args:
            port (int): Port number
        
        Returns:
            Service name
        """
        common_services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            111: 'rpcbind',
            135: 'msrpc',
            139: 'netbios-ssn',
            143: 'imap',
            443: 'https',
            993: 'imaps',
            995: 'pop3s',
            1723: 'pptp',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            8080: 'http-proxy'
        }
        
        return common_services.get(port, 'unknown')
    
    async def _get_host_info(self, host: str) -> Dict[str, Any]:
        """
        Get additional information about a host.
        
        Args:
            host (str): Target host
        
        Returns:
            Host information
        """
        info = {}
        
        try:
            # Check if host responds to ping
            if await self._ping_host(host):
                info['ping_responsive'] = True
            else:
                info['ping_responsive'] = False
            
            # Get IP addresses if host is a domain
            if not self.network_utils.is_valid_ip(host):
                ips = self.network_utils.resolve_hostname(host)
                if ips:
                    info['ip_addresses'] = ips
        
        except Exception as e:
            self.logger.debug(f"Failed to get host info for {host}: {e}")
        
        return info
    
    async def _ping_host(self, host: str) -> bool:
        """
        Check if host responds to ping.
        
        Args:
            host (str): Target host
        
        Returns:
            bool: True if host responds to ping
        """
        try:
            # Use ping command appropriate for the OS
            import platform
            if platform.system().lower() == 'windows':
                cmd = f'ping -n 1 -w 1000 {host}'
            else:
                cmd = f'ping -c 1 -W 1 {host}'
            
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            await process.communicate()
            return process.returncode == 0
        
        except Exception:
            return False
    
    def _generate_scan_summary(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate summary statistics for scan results.
        
        Args:
            scan_results (dict): Scan results
        
        Returns:
            Summary statistics
        """
        summary = {
            'total_hosts': len(scan_results),
            'hosts_with_open_ports': 0,
            'total_open_ports': 0,
            'total_closed_ports': 0,
            'total_filtered_ports': 0,
            'common_services': {},
            'responsive_hosts': 0
        }
        
        for host, data in scan_results.items():
            open_ports = data.get('open_ports', [])
            closed_ports = data.get('closed_ports', [])
            filtered_ports = data.get('filtered_ports', [])
            
            if open_ports:
                summary['hosts_with_open_ports'] += 1
            
            summary['total_open_ports'] += len(open_ports)
            summary['total_closed_ports'] += len(closed_ports)
            summary['total_filtered_ports'] += len(filtered_ports)
            
            # Count common services
            for port_info in open_ports:
                service = port_info.get('service', 'unknown')
                if service in summary['common_services']:
                    summary['common_services'][service] += 1
                else:
                    summary['common_services'][service] = 1
            
            # Check if host is responsive
            host_info = data.get('host_info', {})
            if host_info.get('ping_responsive', False) or open_ports:
                summary['responsive_hosts'] += 1
        
        # Sort services by frequency
        summary['common_services'] = dict(sorted(
            summary['common_services'].items(),
            key=lambda x: x[1],
            reverse=True
        ))
        
        return summary
    
    async def scan_specific_ports(self, targets: List[str], ports: List[int]) -> Dict[str, Any]:
        """
        Scan specific ports on targets.
        
        Args:
            targets (list): Target hosts
            ports (list): Specific ports to scan
        
        Returns:
            Scan results for specific ports
        """
        self.logger.info(f"Scanning specific ports {ports} on {len(targets)} targets")
        return await self.scan(targets, ports)
    
    async def quick_scan(self, targets: List[str]) -> Dict[str, Any]:
        """
        Perform a quick scan of common ports.
        
        Args:
            targets (list): Target hosts
        
        Returns:
            Quick scan results
        """
        # Use top 20 most common ports for quick scan
        quick_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900, 8080]
        
        self.logger.info(f"Performing quick scan on {len(targets)} targets")
        return await self.scan(targets, quick_ports)
    
    async def comprehensive_scan(self, targets: List[str]) -> Dict[str, Any]:
        """
        Perform comprehensive scan of all ports.
        
        Args:
            targets (list): Target hosts
        
        Returns:
            Comprehensive scan results
        """
        # Scan all ports (this can take a very long time)
        all_ports = list(range(1, 65536))
        
        self.logger.warning(f"Starting comprehensive scan - this may take several hours")
        return await self.scan(targets, all_ports)