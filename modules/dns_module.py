"""
DNS Enumeration Module
Performs comprehensive DNS queries to map target DNS infrastructure.
"""

import dns.resolver
import dns.reversename
import dns.exception
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from utils.logger import log_performance
from utils.network import NetworkUtils


class DNSModule:
    """DNS enumeration functionality for reconnaissance."""
    
    def __init__(self, config):
        """
        Initialize DNS module.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.network_utils = NetworkUtils(config)
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        nameservers = config.get('dns.nameservers', ['8.8.8.8', '8.8.4.4', '1.1.1.1'])
        self.resolver.nameservers = nameservers
        self.resolver.timeout = config.get('dns.timeout', 5)
        self.resolver.lifetime = config.get('dns.timeout', 5)
    
    @log_performance
    async def enumerate(self, domain: str) -> Dict[str, Any]:
        """
        Perform comprehensive DNS enumeration for a domain.
        
        Args:
            domain (str): Domain name to enumerate
        
        Returns:
            Dict containing DNS information
        """
        self.logger.info(f"Starting DNS enumeration for {domain}")
        
        result = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'records': {},
            'nameservers': [],
            'mail_servers': [],
            'ip_addresses': [],
            'reverse_dns': {},
            'zone_transfer': None,
            'dns_security': {}
        }
        
        try:
            # Get record types to query
            record_types = self.config.get('dns.record_types', ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'])
            
            # Query each record type
            for record_type in record_types:
                records = await self._query_record_type(domain, record_type)
                if records:
                    result['records'][record_type] = records
            
            # Extract specific information
            result['nameservers'] = self._extract_nameservers(result['records'])
            result['mail_servers'] = self._extract_mail_servers(result['records'])
            result['ip_addresses'] = self._extract_ip_addresses(result['records'])
            
            # Perform reverse DNS lookups
            if result['ip_addresses']:
                result['reverse_dns'] = await self._reverse_dns_lookup(result['ip_addresses'])
            
            # Check for zone transfer vulnerability
            if result['nameservers']:
                result['zone_transfer'] = await self._check_zone_transfer(domain, result['nameservers'])
            
            # Check DNS security features
            result['dns_security'] = await self._check_dns_security(domain)
            
            self.logger.info(f"DNS enumeration completed for {domain}")
            
        except Exception as e:
            self.logger.error(f"DNS enumeration failed for {domain}: {e}")
            result['error'] = str(e)
        
        return result
    
    async def _query_record_type(self, domain: str, record_type: str) -> List[Dict[str, Any]]:
        """
        Query specific DNS record type.
        
        Args:
            domain (str): Domain name
            record_type (str): DNS record type
        
        Returns:
            List of records
        """
        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, 
                self._sync_query_record_type, 
                domain, 
                record_type
            )
            return response
        except Exception as e:
            self.logger.debug(f"Failed to query {record_type} for {domain}: {e}")
            return []
    
    def _sync_query_record_type(self, domain: str, record_type: str) -> List[Dict[str, Any]]:
        """
        Synchronous DNS query for a specific record type.
        
        Args:
            domain (str): Domain name
            record_type (str): DNS record type
        
        Returns:
            List of records
        """
        records = []
        
        try:
            answers = self.resolver.resolve(domain, record_type)
            
            for rdata in answers:
                record_data = {
                    'type': record_type,
                    'ttl': answers.ttl,
                    'value': str(rdata).rstrip('.')
                }
                
                # Add type-specific information
                if record_type == 'MX':
                    record_data['priority'] = rdata.preference
                    record_data['exchange'] = str(rdata.exchange).rstrip('.')
                elif record_type == 'SOA':
                    record_data['mname'] = str(rdata.mname).rstrip('.')
                    record_data['rname'] = str(rdata.rname).rstrip('.')
                    record_data['serial'] = rdata.serial
                    record_data['refresh'] = rdata.refresh
                    record_data['retry'] = rdata.retry
                    record_data['expire'] = rdata.expire
                    record_data['minimum'] = rdata.minimum
                elif record_type == 'TXT':
                    record_data['text'] = ' '.join([part.decode() if isinstance(part, bytes) else str(part) for part in rdata.strings])
                
                records.append(record_data)
                
        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"Domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No {record_type} records found for {domain}")
        except dns.exception.Timeout:
            self.logger.warning(f"DNS query timeout for {record_type} {domain}")
        except Exception as e:
            self.logger.debug(f"DNS query error for {record_type} {domain}: {e}")
        
        return records
    
    def _extract_nameservers(self, records: Dict) -> List[str]:
        """Extract nameservers from DNS records."""
        nameservers = []
        if 'NS' in records:
            for record in records['NS']:
                ns = record['value']
                if ns not in nameservers:
                    nameservers.append(ns)
        return nameservers
    
    def _extract_mail_servers(self, records: Dict) -> List[Dict[str, Any]]:
        """Extract mail servers from DNS records."""
        mail_servers = []
        if 'MX' in records:
            for record in records['MX']:
                mail_servers.append({
                    'hostname': record['exchange'],
                    'priority': record['priority'],
                    'ttl': record['ttl']
                })
            # Sort by priority
            mail_servers.sort(key=lambda x: x['priority'])
        return mail_servers
    
    def _extract_ip_addresses(self, records: Dict) -> List[str]:
        """Extract IP addresses from DNS records."""
        ips = []
        for record_type in ['A', 'AAAA']:
            if record_type in records:
                for record in records[record_type]:
                    ip = record['value']
                    if ip not in ips:
                        ips.append(ip)
        return ips
    
    async def _reverse_dns_lookup(self, ip_addresses: List[str]) -> Dict[str, Any]:
        """
        Perform reverse DNS lookups for IP addresses.
        
        Args:
            ip_addresses (list): List of IP addresses
        
        Returns:
            Dict mapping IPs to hostnames
        """
        reverse_results = {}
        
        for ip in ip_addresses:
            try:
                loop = asyncio.get_event_loop()
                hostname = await loop.run_in_executor(None, self._sync_reverse_lookup, ip)
                reverse_results[ip] = hostname
            except Exception as e:
                self.logger.debug(f"Reverse DNS lookup failed for {ip}: {e}")
                reverse_results[ip] = None
        
        return reverse_results
    
    def _sync_reverse_lookup(self, ip: str) -> Optional[str]:
        """
        Synchronous reverse DNS lookup.
        
        Args:
            ip (str): IP address
        
        Returns:
            Hostname or None
        """
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = self.resolver.resolve(reverse_name, 'PTR')
            return str(answers[0]).rstrip('.')
        except Exception:
            return None
    
    async def _check_zone_transfer(self, domain: str, nameservers: List[str]) -> Dict[str, Any]:
        """
        Check for zone transfer vulnerability.
        
        Args:
            domain (str): Domain name
            nameservers (list): List of nameservers
        
        Returns:
            Zone transfer results
        """
        zone_transfer_results = {
            'vulnerable': False,
            'nameservers_tested': [],
            'successful_transfers': [],
            'errors': []
        }
        
        for ns in nameservers:
            try:
                loop = asyncio.get_event_loop()
                result = await loop.run_in_executor(None, self._sync_zone_transfer, domain, ns)
                
                zone_transfer_results['nameservers_tested'].append(ns)
                
                if result['success']:
                    zone_transfer_results['vulnerable'] = True
                    zone_transfer_results['successful_transfers'].append({
                        'nameserver': ns,
                        'records_count': len(result['records']),
                        'records': result['records'][:10]  # Limit for security
                    })
                
            except Exception as e:
                zone_transfer_results['errors'].append(f"{ns}: {str(e)}")
        
        return zone_transfer_results
    
    def _sync_zone_transfer(self, domain: str, nameserver: str) -> Dict[str, Any]:
        """
        Attempt zone transfer from a nameserver.
        
        Args:
            domain (str): Domain name
            nameserver (str): Nameserver to try
        
        Returns:
            Zone transfer result
        """
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=10))
            records = []
            
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append({
                            'name': str(name),
                            'type': dns.rdatatype.to_text(rdataset.rdtype),
                            'value': str(rdata).rstrip('.')
                        })
            
            return {'success': True, 'records': records}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _check_dns_security(self, domain: str) -> Dict[str, Any]:
        """
        Check DNS security features like DNSSEC.
        
        Args:
            domain (str): Domain name
        
        Returns:
            DNS security information
        """
        security_info = {
            'dnssec_enabled': False,
            'dnskey_records': [],
            'ds_records': [],
            'nsec_records': [],
            'caa_records': []
        }
        
        try:
            # Check for DNSSEC records
            for record_type in ['DNSKEY', 'DS', 'NSEC', 'NSEC3']:
                records = await self._query_record_type(domain, record_type)
                if records:
                    security_info['dnssec_enabled'] = True
                    if record_type == 'DNSKEY':
                        security_info['dnskey_records'] = records
                    elif record_type == 'DS':
                        security_info['ds_records'] = records
                    elif record_type in ['NSEC', 'NSEC3']:
                        security_info['nsec_records'] = records
            
            # Check for CAA records
            caa_records = await self._query_record_type(domain, 'CAA')
            if caa_records:
                security_info['caa_records'] = caa_records
            
        except Exception as e:
            self.logger.debug(f"DNS security check failed for {domain}: {e}")
        
        return security_info
    
    async def check_subdomain_dns(self, subdomain: str) -> Dict[str, Any]:
        """
        Check DNS records for a specific subdomain.
        
        Args:
            subdomain (str): Subdomain to check
        
        Returns:
            DNS information for subdomain
        """
        result = {
            'subdomain': subdomain,
            'exists': False,
            'ip_addresses': [],
            'cname': None
        }
        
        try:
            # Check A records
            a_records = await self._query_record_type(subdomain, 'A')
            if a_records:
                result['exists'] = True
                result['ip_addresses'] = [r['value'] for r in a_records]
            
            # Check CNAME records
            cname_records = await self._query_record_type(subdomain, 'CNAME')
            if cname_records:
                result['exists'] = True
                result['cname'] = cname_records[0]['value']
            
        except Exception as e:
            self.logger.debug(f"DNS check failed for subdomain {subdomain}: {e}")
        
        return result
    
    def analyze_dns_structure(self, dns_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze DNS structure and identify interesting findings.
        
        Args:
            dns_result (dict): DNS enumeration result
        
        Returns:
            Analysis summary
        """
        analysis = {
            'total_records': 0,
            'unique_ips': [],
            'mail_infrastructure': {},
            'dns_providers': [],
            'security_findings': [],
            'interesting_records': []
        }
        
        # Count total records
        for record_type, records in dns_result.get('records', {}).items():
            analysis['total_records'] += len(records)
        
        # Analyze IP addresses
        analysis['unique_ips'] = dns_result.get('ip_addresses', [])
        
        # Analyze mail infrastructure
        mail_servers = dns_result.get('mail_servers', [])
        if mail_servers:
            analysis['mail_infrastructure'] = {
                'primary_mx': mail_servers[0]['hostname'] if mail_servers else None,
                'mx_count': len(mail_servers),
                'providers': self._identify_mail_providers(mail_servers)
            }
        
        # Identify DNS providers
        nameservers = dns_result.get('nameservers', [])
        analysis['dns_providers'] = self._identify_dns_providers(nameservers)
        
        # Security findings
        if dns_result.get('zone_transfer', {}).get('vulnerable'):
            analysis['security_findings'].append('Zone transfer vulnerability detected')
        
        if dns_result.get('dns_security', {}).get('dnssec_enabled'):
            analysis['security_findings'].append('DNSSEC enabled')
        else:
            analysis['security_findings'].append('DNSSEC not enabled')
        
        # Look for interesting TXT records
        txt_records = dns_result.get('records', {}).get('TXT', [])
        for record in txt_records:
            text = record.get('text', '').lower()
            if any(keyword in text for keyword in ['spf', 'dmarc', 'dkim', 'verification', 'google-site']):
                analysis['interesting_records'].append(record)
        
        return analysis
    
    def _identify_mail_providers(self, mail_servers: List[Dict]) -> List[str]:
        """Identify mail service providers from MX records."""
        providers = []
        provider_patterns = {
            'Google': ['google.com', 'googlemail.com'],
            'Microsoft': ['outlook.com', 'hotmail.com', 'live.com'],
            'Proofpoint': ['pphosted.com'],
            'Mimecast': ['mimecast.com'],
            'Amazon SES': ['amazonses.com'],
            'Mailgun': ['mailgun.org']
        }
        
        for mx in mail_servers:
            hostname = mx['hostname'].lower()
            for provider, patterns in provider_patterns.items():
                if any(pattern in hostname for pattern in patterns):
                    if provider not in providers:
                        providers.append(provider)
                    break
        
        return providers
    
    def _identify_dns_providers(self, nameservers: List[str]) -> List[str]:
        """Identify DNS service providers from nameservers."""
        providers = []
        provider_patterns = {
            'Cloudflare': ['cloudflare.com'],
            'Amazon Route 53': ['awsdns'],
            'Google Cloud DNS': ['googledomains.com'],
            'Azure DNS': ['azure-dns'],
            'GoDaddy': ['domaincontrol.com'],
            'Namecheap': ['registrar-servers.com']
        }
        
        for ns in nameservers:
            ns_lower = ns.lower()
            for provider, patterns in provider_patterns.items():
                if any(pattern in ns_lower for pattern in patterns):
                    if provider not in providers:
                        providers.append(provider)
                    break
        
        return providers
